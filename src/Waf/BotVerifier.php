<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Waf;

use Concrete\Core\Application\Application;
use Concrete\Core\Database\Connection\Connection;
use PasichDev\SecurityGuard\Ip\IpRange;
use PasichDev\SecurityGuard\Rules\RuleSet;
use PasichDev\SecurityGuard\State\CounterStore;
use Throwable;

/**
 * Перевірка пошукових ботів: rDNS (gethostbyaddr) → суфікс домену пошуковика
 * → прямий DNS має повернути ту саму IP. Результат кешується в лічильниках
 * (APCu/файл) і в SecurityGuardBotCache на 24 год, тож DNS-запит — один раз
 * на IP на добу. Збій DNS ніколи не дає «фейк» — лише «не перевірено».
 */
final class BotVerifier
{
    public const NONE = 'none';
    public const VERIFIED = 'verified';
    public const FAKE = 'fake';
    public const UNVERIFIED = 'unverified';

    private const TTL = 86400;
    private const TTL_UNVERIFIED = 3600;

    /** @var Application|null */
    private $app;

    /** @var CounterStore */
    private $counters;

    /** @var callable|null fn(string $ip): string|false */
    private $reverse;

    /** @var callable|null fn(string $host, bool $v6): string[] */
    private $forward;

    public function __construct(?Application $app, CounterStore $counters, ?callable $reverse = null, ?callable $forward = null)
    {
        $this->app = $app;
        $this->counters = $counters;
        $this->reverse = $reverse;
        $this->forward = $forward;
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

    /** @return array{status: string, name: ?string, host: string} */
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
        $fromDb = $this->readDb($ip, $name);
        if ($fromDb !== null) {
            $this->counters->set($key, $fromDb + ['name' => $name], self::TTL);

            return $fromDb + ['name' => $name];
        }

        $suffixes = RuleSet::searchBots()[$name][1];
        $host = $this->reverseLookup($ip);
        $forwardIps = ($host !== '' && self::hostMatches($host, $suffixes)) ? $this->forwardLookup($host, strpos($ip, ':') !== false) : [];
        $status = self::evaluate($ip, $suffixes, $host, $forwardIps);

        $result = ['status' => $status, 'name' => $name, 'host' => $host];
        $this->counters->set($key, $result, $status === self::UNVERIFIED ? self::TTL_UNVERIFIED : self::TTL);
        if ($status !== self::UNVERIFIED) {
            $this->writeDb($ip, $host, $status === self::VERIFIED, $name);
        }

        return $result;
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
