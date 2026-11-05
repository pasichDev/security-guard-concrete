<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Waf;

use Concrete\Core\Application\Application;
use Concrete\Core\Database\Connection\Connection;
use PasichDev\SecurityGuard\Ip\IpRange;
use PasichDev\SecurityGuard\Logs\CrawlerRanges;
use PasichDev\SecurityGuard\Logs\IpMatcher;
use PasichDev\SecurityGuard\Rules\RuleSet;
use PasichDev\SecurityGuard\State\CounterStore;
use PasichDev\SecurityGuard\State\StateDir;
use Throwable;

/**
 * Перевірка пошукових ботів.
 *
 * На запиті відвідувача — ЖОДНОГО DNS: кеш у лічильниках → результат
 * попередньої перевірки в SecurityGuardBotCache (один запит до бази на IP
 * на годину, лише для UA пошуковика) → опубліковані діапазони IP
 * (CrawlerRanges::PUBLISHED або оновлені з SecurityGuardBotRanges). Невідома
 * IP — «не перевірено» (звичайні перевірки, ніколи не «фейк») і стає в чергу.
 * Черга обробляється з cron (Maintenance) під неблокуючим замком і з лімітом
 * часу: rDNS → суфікс домену → прямий DNS → SecurityGuardBotCache.
 */
final class BotVerifier
{
    public const NONE = 'none';
    public const VERIFIED = 'verified';
    public const FAKE = 'fake';
    public const UNVERIFIED = 'unverified';

    private const TTL = 86400;
    private const TTL_UNVERIFIED = 3600;
    private const QUEUE_MAX_BYTES = 262144;

    /** @var Application|null */
    private $app;

    /** @var CounterStore */
    private $counters;

    /** @var callable|null fn(string $ip): string|false */
    private $reverse;

    /** @var callable|null fn(string $host, bool $v6): string[] */
    private $forward;

    /** @var string|null тека черги (null — тека стану) */
    private $queueDir;

    /** @var array<string, string[]> бот => CIDR із SecurityGuardBotRanges */
    private $storedRanges;

    /** @var array<string, IpMatcher> */
    private static $matchers = [];

    public function __construct(?Application $app, CounterStore $counters, ?callable $reverse = null, ?callable $forward = null, ?string $queueDir = null, array $storedRanges = [])
    {
        $this->app = $app;
        $this->counters = $counters;
        $this->reverse = $reverse;
        $this->forward = $forward;
        $this->queueDir = $queueDir;
        $this->storedRanges = $storedRanges;
    }

    /** Назва бота за UA або null. */
    public static function detect(string $userAgent): ?string
    {
        if ($userAgent === '') {
            return null;
        }
        foreach (RuleSet::searchBots() as $name => [$regex]) {
            if (preg_match($regex, $userAgent)) {
                return $name;
            }
        }

        return null;
    }

    /**
     * Рішення для запиту відвідувача, без мережевих запитів.
     *
     * @return array{status: string, name: ?string, host: string}
     */
    public function verify(string $ip, string $userAgent): array
    {
        $name = self::detect($userAgent);
        if ($name === null) {
            return ['status' => self::NONE, 'name' => null, 'host' => ''];
        }
        $key = 'bot:' . $ip;
        $cached = $this->counters->get($key);
        if (is_array($cached) && ($cached['name'] ?? null) === $name && isset($cached['status'])) {
            return ['status' => (string) $cached['status'], 'name' => $name, 'host' => (string) ($cached['host'] ?? '')];
        }
        $result = null;
        if ($this->inPublishedRanges($ip, $name)) {
            $result = ['status' => self::VERIFIED, 'name' => $name, 'host' => ''];
        } elseif (($row = $this->readDb($ip, $name)) !== null) {
            $result = $row + ['name' => $name];
        }
        if ($result !== null) {
            $this->counters->set($key, $result, self::TTL);

            return $result;
        }
        $result = ['status' => self::UNVERIFIED, 'name' => $name, 'host' => ''];
        // Негативний кеш на годину: не питаємо базу на кожному запиті цієї IP.
        $this->counters->set($key, $result, self::TTL_UNVERIFIED);
        $this->enqueue($ip, $name);

        return $result;
    }

    /** IP у списку, який пошуковик публікує сам (без евристичних мереж). */
    public function inPublishedRanges(string $ip, string $name): bool
    {
        $list = $this->storedRanges[$name] ?? (CrawlerRanges::PUBLISHED[$name] ?? []);
        if (!is_array($list) || $list === []) {
            return false;
        }
        $key = $name . ':' . count($list) . ':' . md5(implode(',', array_slice($list, 0, 5)));
        if (!isset(self::$matchers[$key])) {
            self::$matchers[$key] = new IpMatcher(array_values(array_map('strval', $list)));
        }

        return self::$matchers[$key]->matches(IpRange::normalize($ip));
    }

    /**
     * Обробка черги rDNS з cron. Один процес за раз (неблокуючий flock), не
     * довше $budget секунд і не більше $max IP. Повертає кількість перевірених.
     */
    public function processQueue(float $budget = 10.0, int $max = 200): int
    {
        $dir = $this->queueDir();
        $lock = @fopen($dir . '/botqueue.lock', 'c');
        if ($lock === false) {
            return 0;
        }
        $done = 0;
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                return 0; // інша обробка вже йде — ту саму IP двічі не перевіряємо
            }
            $file = $dir . '/botqueue.txt';
            $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
            @unlink($file);
            $deadline = microtime(true) + max(0.1, $budget);
            $seen = [];
            $rest = [];
            foreach ($lines as $line) {
                [$ip, $name] = array_pad(explode('|', (string) $line, 2), 2, '');
                $ip = IpRange::normalize($ip);
                if ($ip === '' || !isset(RuleSet::searchBots()[$name]) || isset($seen[$ip])) {
                    continue;
                }
                $seen[$ip] = true;
                if ($done >= $max || microtime(true) > $deadline) {
                    $rest[] = $ip . '|' . $name;
                    continue;
                }
                $this->checkNow($ip, $name);
                $done++;
            }
            if ($rest !== []) {
                @file_put_contents($file, implode("\n", $rest) . "\n", FILE_APPEND | LOCK_EX);
            }
            flock($lock, LOCK_UN);
        } finally {
            fclose($lock);
        }

        return $done;
    }

    /** Повна перевірка через DNS (лише з cron/CLI). */
    public function checkNow(string $ip, string $name): string
    {
        $suffixes = RuleSet::searchBots()[$name][1] ?? [];
        $host = $this->reverseLookup($ip);
        $forwardIps = ($host !== '' && self::hostMatches($host, $suffixes)) ? $this->forwardLookup($host, strpos($ip, ':') !== false) : [];
        $status = self::evaluate($ip, $suffixes, $host, $forwardIps);
        $result = ['status' => $status, 'name' => $name, 'host' => $host];
        $this->counters->set('bot:' . $ip, $result, $status === self::UNVERIFIED ? self::TTL_UNVERIFIED : self::TTL);
        if ($status !== self::UNVERIFIED) {
            $this->writeDb($ip, $host, $status === self::VERIFIED, $name);
        }

        return $status;
    }

    /**
     * Чисте рішення: $host '' — rDNS не відповів (не перевірено).
     * Хост не з доменів пошуковика або прямий DNS не повертає цю IP — фейк.
     *
     * @param string[] $forwardIps
     */
    public static function evaluate(string $ip, array $suffixes, string $host, array $forwardIps): string
    {
        if ($host === '') {
            return self::UNVERIFIED;
        }
        if (!self::hostMatches($host, $suffixes)) {
            return self::FAKE;
        }
        if ($forwardIps === []) {
            // Хост правильний, але прямий DNS мовчить — це може бути збій DNS.
            return self::UNVERIFIED;
        }
        $ip = IpRange::normalize($ip);
        foreach ($forwardIps as $candidate) {
            if (IpRange::normalize((string) $candidate) === $ip) {
                return self::VERIFIED;
            }
        }

        return self::FAKE;
    }

    public static function hostMatches(string $host, array $suffixes): bool
    {
        $host = rtrim(strtolower($host), '.');
        foreach ($suffixes as $suffix) {
            $suffix = strtolower($suffix);
            if ($host !== '' && substr($host, -strlen($suffix)) === $suffix) {
                return true;
            }
        }

        return false;
    }

    /** Ставить IP у чергу перевірки, не частіше разу на годину для однієї IP. */
    private function enqueue(string $ip, string $name): void
    {
        if (!$this->counters->add('botq:' . $ip, 1, self::TTL_UNVERIFIED)) {
            return;
        }
        $file = $this->queueDir() . '/botqueue.txt';
        $size = @filesize($file);
        if ($size !== false && $size > self::QUEUE_MAX_BYTES) {
            return; // черга переповнена (cron не працює) — не ростемо
        }
        // Дописування одного короткого рядка в режимі append — без довгих блокувань.
        @file_put_contents($file, IpRange::normalize($ip) . '|' . $name . "\n", FILE_APPEND);
    }

    private function queueDir(): string
    {
        return $this->queueDir ?? StateDir::path();
    }

    private function reverseLookup(string $ip): string
    {
        try {
            $host = $this->reverse ? ($this->reverse)($ip) : @gethostbyaddr($ip);
        } catch (Throwable $e) {
            return '';
        }
        if (!is_string($host) || $host === '' || IpRange::normalize($host) !== '') {
            return ''; // повернув саму IP — запису PTR немає
        }

        return rtrim(strtolower($host), '.');
    }

    /** @return string[] */
    private function forwardLookup(string $host, bool $v6): array
    {
        try {
            if ($this->forward) {
                return (array) ($this->forward)($host, $v6);
            }
            if (!$v6) {
                $ips = @gethostbynamel($host);

                return is_array($ips) ? $ips : [];
            }
            $records = @dns_get_record($host, DNS_AAAA);
            $out = [];
            foreach (is_array($records) ? $records : [] as $r) {
                if (!empty($r['ipv6'])) {
                    $out[] = (string) $r['ipv6'];
                }
            }

            return $out;
        } catch (Throwable $e) {
            return [];
        }
    }

    private function readDb(string $ip, string $name): ?array
    {
        if ($this->app === null) {
            return null;
        }
        try {
            $row = $this->app->make(Connection::class)->fetchAssociative(
                'SELECT hostname, isBot, botName FROM SecurityGuardBotCache WHERE ip = ? AND verifiedAt > ?',
                [$ip, time() - self::TTL]
            );
        } catch (Throwable $e) {
            return null;
        }
        if (!$row || (string) $row['botName'] !== $name) {
            return null;
        }

        return ['status' => (int) $row['isBot'] ? self::VERIFIED : self::FAKE, 'host' => (string) $row['hostname']];
    }

    private function writeDb(string $ip, string $host, bool $isBot, string $name): void
    {
        if ($this->app === null) {
            return;
        }
        try {
            $db = $this->app->make(Connection::class);
            $data = ['hostname' => Text::cut($host, 255), 'isBot' => $isBot ? 1 : 0, 'botName' => $name, 'verifiedAt' => time()];
            if ($db->fetchOne('SELECT 1 FROM SecurityGuardBotCache WHERE ip = ?', [$ip])) {
                $db->update('SecurityGuardBotCache', $data, ['ip' => $ip]);
            } else {
                $db->insert('SecurityGuardBotCache', $data + ['ip' => $ip]);
            }
        } catch (Throwable $e) {
            // Кеш у базі — лише оптимізація.
        }
    }
}
