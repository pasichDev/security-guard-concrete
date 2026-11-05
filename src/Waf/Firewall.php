<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Waf;

use PasichDev\SecurityGuard\Block\BlockService;
use PasichDev\SecurityGuard\Config\Settings;
use PasichDev\SecurityGuard\Contract\AlertServiceInterface;
use PasichDev\SecurityGuard\Contract\BlockServiceInterface;
use PasichDev\SecurityGuard\Contract\EventLogInterface;
use PasichDev\SecurityGuard\Contract\HoneypotRepositoryInterface;
use PasichDev\SecurityGuard\Contract\ScoreServiceInterface;
use PasichDev\SecurityGuard\Geo\CountryGuesser;
use PasichDev\SecurityGuard\Rules\ConcreteRoutes;
use PasichDev\SecurityGuard\Rules\HoneypotList;
use PasichDev\SecurityGuard\Rules\Paths;
use PasichDev\SecurityGuard\Rules\RuleSet;
use PasichDev\SecurityGuard\Rules\Signatures;
use PasichDev\SecurityGuard\State\CounterStore;
use Throwable;

/**
 * Рішення WAF для одного запиту. Працює лише зі знімком стану (state.php) і
 * лічильниками; у базу звертається тільки при події (атака, бан, honeypot,
 * невдалий вхід) через сервіси-контракти. Не залежить від HTTP-об'єктів
 * Concrete — їх розбирає GuardMiddleware.
 *
 * Режим monitor: банів не ставимо, події пишемо з action=logged, запит
 * пропускаємо. Режим enforce: бан + відмова.
 */
final class Firewall
{
    /** Ботів/соцмереж не скоримо навіть неперевірених: краще пропустити краулера, ніж забанити. */
    private const CRAWLER_UA = '/googlebot|bingbot|yandex|duckduckbot|applebot|baiduspider|mojeekbot|msnbot|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|discordbot|viber|skypeuripreview|slackbot/i';

    /** @var array */
    private $state;
    /** @var array */
    private $settings;
    /** @var CounterStore */
    private $counters;
    /** @var callable fn(string $id): object */
    private $services;
    /** @var callable|null fn(string $message): void */
    private $logger;
    /** @var RuleSet|null */
    private $rules;
    /** @var bool Запит від довіреного джерела (білий список, адміністратор, sg_pass). */
    private $trusted = false;

    /**
     * @param callable $services fn(string $id) для 'block', 'events', 'honeypot', 'scores', 'alerts', 'bots'
     */
    public function __construct(array $state, CounterStore $counters, callable $services, ?callable $logger = null)
    {
        $this->state = $state;
        $this->settings = (array) ($state['settings'] ?? []) + Settings::DEFAULTS;
        $this->counters = $counters;
        $this->services = $services;
        $this->logger = $logger;
    }

    public function isEnabled(): bool
    {
        return !empty($this->settings['enabled']);
    }

    public function isEnforcing(): bool
    {
        return $this->isEnabled() && $this->settings['mode'] === Settings::MODE_ENFORCE;
    }

    public function isTrusted(): bool
    {
        return $this->trusted;
    }

    public function settings(): array
    {
        return $this->settings;
    }

    /**
     * Перевірка до диспетчеризації. null — пропустити запит.
     *
     * @param callable $isTrustedUser fn(): bool — увійшов користувач із доступом до дашборду (викликається ліниво)
     * @param callable|null $isRegisteredUser fn(): bool — увійшов будь-який користувач (редактор без дашборду)
     */
    public function inspect(RequestInfo $r, callable $isTrustedUser, ?callable $isRegisteredUser = null): ?Decision
    {
        if (!$this->isEnabled()) {
            return null;
        }
        $s = $this->settings;
        $now = $r->now ?: time();
        $this->trusted = false;

        if (!empty($s['ddos_enabled'])) {
            $this->countTraffic($now);
        }

        // 1. Аварійний обхід.
        $tokenHash = (string) ($s['bypass_token_hash'] ?? '');
        if ($tokenHash === '' && (string) $s['bypass_token'] !== '') {
            $tokenHash = hash('sha256', (string) $s['bypass_token']);
        }
        if ($tokenHash !== '' && $r->bypass !== null && $r->bypass !== '' && hash_equals($tokenHash, hash('sha256', $r->bypass))) {
            $this->emergencyUnblock($r);
            $this->trusted = true;

            return null;
        }

        // 2. Білий список і адміністратори.
        if (Whitelist::isTrusted($r->ip, $this->state, $now)) {
            $this->trusted = true;

            return null;
        }
        if ($isTrustedUser()) {
            $this->trusted = true;

            return null;
        }

        // 3. Активний бан.
        $ban = $this->state['blocks'][$r->ip] ?? null;
        if (is_array($ban) && ((int) $ban['until'] === 0 || (int) $ban['until'] > $now)) {
            return $this->denyBanned($r, $ban, $now);
        }

        // Дашборд, /ccm/, вхід — без евристик вмісту лише для того, хто увійшов
        // (редактори постять HTML з <script>, ../ тощо). Анонім проходить усі перевірки.
        $servicePath = Paths::isTrusted($r->pathInfo) || Paths::isTrusted(Paths::normalize($r->path()));
        $registered = $isRegisteredUser !== null && $servicePath ? (bool) $isRegisteredUser() : false;
        if ($registered) {
            return null;
        }

        // 4. Пошукові боти.
        if (!empty($s['verify_search_bots']) && BotVerifier::detect($r->userAgent) !== null) {
            $bot = $this->safe(function () use ($r) {
                return $this->service('bots')->verify($r->ip, $r->userAgent);
            });
            $status = is_array($bot) ? $bot['status'] : BotVerifier::UNVERIFIED;
            if ($status === BotVerifier::VERIFIED) {
                return null;
            }
            if ($status === BotVerifier::FAKE && !empty($s['block_fake_bots'])) {
                return $this->violation($r, 'FAKE_BOT', 'fake_bot');
            }
        }

        $rules = $this->rules();

        // 5. Honeypot.
        if (!empty($s['honeypot_enabled'])
            && $rules->isHoneypot($r->path(), HoneypotList::parseCustom((string) $s['honeypot_custom_urls']))) {
            if ($this->counters->add('hp:' . $r->ip . ':' . md5($r->path()), 1, 300)) {
                $this->safe(function () use ($r): void {
                    $this->service('honeypot')->record($r->ip, $r->uri, $r->userAgent);
                });
            }

            return $this->violation($r, 'HONEYPOT', 'honeypot');
        }

        // 6. User-Agent.
        if (($hit = $rules->classifyUserAgent($r->userAgent)) !== null) {
            return $this->violation($r, $hit['rule'], $hit['category']);
        }

        // 6a. Службові маршрути Concrete, потрібні лише тому, хто увійшов.
        if ($this->on('rules_concrete')) {
            $hit = ConcreteRoutes::classifyAnonymous($r->path()) ?? ConcreteRoutes::classifyAnonymous($r->pathInfo);
            if ($hit !== null) {
                return $this->backendProbe($r, $hit);
            }
        }

        // 6b. Cookie: серіалізовані об'єкти, XXE, SSRF.
        if ($r->cookies !== '' && !empty($s['rules_code_exec']) && ($hit = Signatures::classifyCookies($r->cookies)) !== null) {
            return $this->violation($r, $hit['rule'], $hit['category']);
        }

        // 7. Гео-блок.
        $countries = CountryGuesser::parseCountries((string) $s['geo_block_countries']);
        if ($countries !== []) {
            $cc = CountryGuesser::guess($r->ip);
            if ($cc !== '' && in_array($cc, $countries, true)) {
                return $this->violation($r, 'GEO_BLOCK_' . $cc, 'geo');
            }
        }

        // 8. Сплеск PHP-проб — рахуємо ДО сигнатур, щоб відомі шелли теж ішли в лічильник.
        $phpBurst = false;
        if (!empty($s['php_probe_enabled']) && self::isPhpProbe($r->path())) {
            $n = $this->counters->increment('pp:' . $r->ip, 1, max(1, (int) $s['php_probe_window']));
            $phpBurst = $n >= max(1, (int) $s['php_probe_threshold']);
        }

        // 9. Сигнатури атак.
        if (($hit = $rules->classifyRequest($r->method, $r->uri, '', $r->body)) !== null) {
            return $this->violation($r, $hit['rule'], $hit['category']);
        }
        if ($phpBurst) {
            return $this->violation($r, 'PHP_PROBE_BURST', 'php_probe');
        }

        $isStatic = RuleSet::isStaticPath($r->path());

        // 10. Ліміт частоти.
        if (!$isStatic && !empty($s['rate_limit_enabled'])) {
            $n = $this->counters->increment('rl:' . $r->ip, 1, max(1, (int) $s['rate_limit_window']));
            if ($n > max(1, (int) $s['rate_limit_requests'])) {
                return $this->violation($r, 'RATE_LIMIT', 'ratelimit');
            }
        }

        // DDoS: під час активного сплеску банимо найактивніші IP (якщо ввімкнено).
        if (!empty($s['ddos_enabled']) && !empty($s['ddos_auto_block']) && $this->counters->get('ddos:active')) {
            $minute = intdiv($now, 60);
            $n = $this->counters->increment('di:' . $r->ip . ':' . $minute, 1, 120);
            if ($n >= max(30, intdiv((int) $s['ddos_min_requests'], 5))) {
                return $this->violation($r, 'DDOS_TOP_IP', 'ddos');
            }
        }

        // 11. Поведінковий скоринг.
        if (!$isStatic && !empty($s['behavior_scoring'])) {
            return $this->score($r);
        }

        return null;
    }

    /**
     * Після відповіді на POST форми входу. $failed — Concrete знову показав
     * форму (успіх — завжди redirect на /login/login_complete).
     */
    public function afterLogin(RequestInfo $r, bool $failed): ?Decision
    {
        if (!$failed || !$r->isLoginAttempt || $this->trusted || !$this->isEnabled() || empty($this->settings['bruteforce_enabled'])) {
            return null;
        }
        $s = $this->settings;
        $n = $this->counters->increment('bf:' . $r->ip, 1, max(60, (int) $s['bruteforce_window']));
        $this->logEvent($r, 'LOGIN_FAILED', 'bruteforce', 'logged');
        if ($n < max(1, (int) $s['bruteforce_threshold'])) {
            return null;
        }
        $this->counters->delete('bf:' . $r->ip);
        $enforce = $this->isEnforcing();
        $message = $enforce
            ? t('IP %s was blocked after %d failed sign-in attempts.', $r->ip, $n)
            : t('IP %s made %d failed sign-in attempts (monitor mode, not blocked).', $r->ip, $n);
        $this->safe(function () use ($r, $message, $n): void {
            $this->service('alerts')->raise('bruteforce', 'warning', $message, ['ip' => $r->ip, 'url' => $r->uri, 'value' => $n]);
        });

        return $this->violation($r, 'BRUTEFORCE', 'bruteforce');
    }

    /**
     * Анонім на службовому маршруті. Застарілі вкладки редактора після
     * завершення сесії теж можуть сюди стукати, тому перші два звернення за
     * 10 хв лише відхиляємо (403 без бану), а бан — з третього.
     */
    private function backendProbe(RequestInfo $r, array $hit): ?Decision
    {
        if ($hit['rule'] === 'CONCRETE_BACKEND_ANON') {
            $n = $this->counters->increment('cb:' . $r->ip, 1, 600);
            if ($n < 3) {
                if (!$this->isEnforcing()) {
                    $this->logEvent($r, $hit['rule'], $hit['category'], 'logged');

                    return null;
                }
                $this->logEvent($r, $hit['rule'], $hit['category'], 'blocked');

                return new Decision($this->statusFor($hit['category']), $hit['rule'], $hit['category']);
            }
            $this->counters->delete('cb:' . $r->ip);
        }

        return $this->violation($r, $hit['rule'], $hit['category']);
    }

    private function on(string $toggle): bool
    {
        if (!array_key_exists($toggle, $this->settings)) {
            return $toggle === 'rules_concrete';
        }

        return !empty($this->settings[$toggle]);
    }

    /** Чи пора виконати періодичне очищення (не частіше разу на годину). */
    public function maintenanceDue(): bool
    {
        return $this->counters->add('maint', 1, 3600);
    }

    public static function isPhpProbe(string $path): bool
    {
        $path = Paths::normalize($path);
        if (!preg_match('/\.(?:php[0-9]?|phtml|phar|pht)$/', $path)) {
            return false;
        }

        // index.php у будь-якій теці — легітимна точка входу (і старі адреси Joomla).
        return !preg_match('#(?:^|/)index\.php$#', $path);
    }

    /**
     * Бали поведінки. Ознаки клієнта (порожній/короткий UA, нема Accept,
     * Accept-Language) — один раз на IP за TTL, бо це властивість клієнта, а
     * не запиту: інакше фідрідер без Accept-Language банився б за 5 запитів.
     * Ознаки запиту накопичуються.
     */
    private function score(RequestInfo $r): ?Decision
    {
        $s = $this->settings;
        if ($r->userAgent !== '' && preg_match(self::CRAWLER_UA, $r->userAgent)) {
            return null;
        }
        $ttl = max(60, (int) $s['behavior_ttl']);
        $signals = [];
        $traits = [];
        if ($r->userAgent === '') {
            $traits['EMPTY_UA'] = 5;
        } elseif (strlen($r->userAgent) < 20) {
            $traits['SHORT_UA'] = 3;
        }
        if (!$r->hasAcceptLanguage) {
            $traits['NO_ACCEPT_LANG'] = 3;
        }
        if (!$r->hasAccept) {
            $traits['NO_ACCEPT'] = 2;
        }
        foreach ($traits as $name => $points) {
            if ($this->counters->add('bt:' . $r->ip . ':' . $name, 1, $ttl)) {
                $signals[$name] = $points;
            }
        }
        if ($r->method === 'POST' && $r->referer === '') {
            $signals['POST_NO_REFERER'] = 5;
        }
        if (preg_match('/(?:^|&)[^=&]*=[^&]{200,}/', $r->query())) {
            $signals['LONG_QUERY'] = 5;
        }
        if ($r->referer === '' && $r->query() !== '' && preg_match('/\.(?:php|asp|aspx|cgi|jsp)$/i', $r->path())
            && self::isPhpProbe($r->path())) {
            $signals['PHP_NO_REFERER'] = 3;
        }
        if (preg_match('#(?:^|/)(?:wp-admin|wp-login|wp-includes|wp-content|phpmyadmin|myadmin|adminer|setup\.php|install\.php|\.env|\.git)(?:/|$|\?|\.)#i', $r->path())) {
            $signals['PROBE_PATH'] = 2;
        }
        $points = array_sum($signals);
        if ($points <= 0) {
            return null;
        }
        $threshold = max(1, (int) $s['behavior_threshold']);
        $total = $this->counters->increment('sc:' . $r->ip, $points, $ttl);
        $pending = $this->counters->increment('sp:' . $r->ip, $points, $ttl);
        $events = (array) ($this->counters->get('se:' . $r->ip) ?? []);
        $events = array_slice(array_merge($events, array_keys($signals)), -20);
        $this->counters->set('se:' . $r->ip, $events, $ttl);

        // У базу (для панелі) — лише помітні бали і не частіше разу на хвилину.
        if ($total >= $threshold || ($total * 2 >= $threshold && $this->counters->add('sw:' . $r->ip, 1, 60))) {
            $this->safe(function () use ($r, $pending, $events): void {
                $this->service('scores')->add($r->ip, $pending, $events);
            });
            $this->counters->delete('sp:' . $r->ip);
            $this->counters->delete('se:' . $r->ip);
        }
        if ($total >= $threshold) {
            $this->counters->delete('sc:' . $r->ip);

            return $this->violation($r, 'BEHAVIOR_SCORE', 'behavior');
        }

        return null;
    }

    /**
     * Порушення: у enforce — бан (з ескалацією) і відмова; у monitor — лише запис.
     * Якщо запис бану в базу не вдався, поточний запит усе одно відхиляємо
     * (виявлення відбулося), але сайт від цього не падає.
     */
    private function violation(RequestInfo $r, string $rule, string $category, ?int $duration = null): ?Decision
    {
        if (!$this->isEnforcing()) {
            $this->logEvent($r, $rule, $category, 'logged');

            return null;
        }
        $until = 0;
        $row = $this->safe(function () use ($r, $rule, $category, $duration) {
            return $this->service('block')->block($r->ip, $rule, $category, $duration, false, $r->context());
        });
        if (is_array($row)) {
            $until = !empty($row['permanent']) ? 0 : (int) ($row['blockedUntil'] ?? 0);
            $this->state['blocks'][$r->ip] = ['until' => $until, 'reason' => $rule, 'category' => $category];
        }
        $this->logEvent($r, $rule, $category, 'banned');
        $now = $r->now ?: time();

        return new Decision($this->statusFor($category), $rule, $category, $until > $now ? $until - $now : 0);
    }

    private function denyBanned(RequestInfo $r, array $ban, int $now): ?Decision
    {
        $category = (string) ($ban['category'] ?? '');
        $reason = (string) ($ban['reason'] ?? 'BLOCKED');
        // Ручний бан з панелі — свідоме рішення адміністратора: діє і в режимі monitor.
        if (!$this->isEnforcing() && empty($ban['manual'])) {
            $this->logEvent($r, $reason, 'blocked_ip', 'logged');

            return null;
        }
        $this->logEvent($r, $reason, 'blocked_ip', 'denied');
        // Спроби забаненої IP: копимо в лічильнику, у базу — раз на хвилину.
        $this->counters->increment('ba:' . $r->ip, 1, 3600);
        if ($this->counters->add('baw:' . $r->ip, 1, 60)) {
            $pending = (int) ($this->counters->get('ba:' . $r->ip) ?? 0);
            $this->counters->delete('ba:' . $r->ip);
            $this->safe(function () use ($r, $pending): void {
                $block = $this->service('block');
                if ($block instanceof BlockService || method_exists($block, 'recordAttempts')) {
                    $block->recordAttempts($r->ip, $pending);
                }
            });
        }
        $until = (int) $ban['until'];

        return new Decision($this->statusFor($category), $reason, $category, $until > $now ? $until - $now : 0);
    }

    private function emergencyUnblock(RequestInfo $r): void
    {
        $this->safe(function () use ($r): void {
            $this->service('block')->unblock($r->ip);
        });
        $this->safe(function () use ($r): void {
            $this->service('scores')->reset($r->ip);
        });
        foreach (['sc:', 'sp:', 'se:', 'bf:', 'rl:', 'pp:'] as $prefix) {
            $this->counters->delete($prefix . $r->ip);
        }
        unset($this->state['blocks'][$r->ip]);
        $this->logEvent($r, 'EMERGENCY_BYPASS', 'blocked_ip', 'logged');
    }

    /**
     * Хвилинні кошики загального трафіку. Базова лінія — середнє попередніх
     * 30 хвилин (рахується раз на хвилину і лише коли трафік уже вище мінімуму).
     */
    private function countTraffic(int $now): void
    {
        $s = $this->settings;
        $minute = intdiv($now, 60);
        $count = $this->counters->increment('dd:' . $minute, 1, 7200);
        $min = max(1, (int) $s['ddos_min_requests']);
        if ($count < $min) {
            return;
        }
        $baseline = $this->counters->get('dB:' . $minute);
        if ($baseline === null) {
            $samples = [];
            for ($m = $minute - 30; $m < $minute; $m++) {
                $v = $this->counters->get('dd:' . $m);
                if ($v !== null) {
                    $samples[] = (int) $v;
                }
            }
            $baseline = count($samples) >= 10 ? array_sum($samples) / count($samples) : -1.0;
            $this->counters->set('dB:' . $minute, $baseline, 120);
        }
        $baseline = (float) $baseline;
        $multiplier = max(1.0, (float) $s['ddos_multiplier']);
        $spike = $baseline >= 0 ? $count > $baseline * $multiplier : $count >= $min * $multiplier;
        if (!$spike) {
            return;
        }
        $this->counters->set('ddos:active', 1, 300);
        if ($this->counters->add('ddos:alerted', 1, 900)) {
            $message = $baseline >= 0
                ? t('Traffic spike: %d requests in the last minute against a baseline of %d per minute.', $count, (int) round($baseline))
                : t('Traffic spike: %d requests in the last minute.', $count);
            $this->safe(function () use ($message, $count, $baseline): void {
                $this->service('alerts')->raise('ddos', 'critical', $message, ['value' => $count, 'baseline' => max(0, $baseline)]);
            });
        }
    }

    private function statusFor(string $category): int
    {
        if ($category === 'bruteforce') {
            return 429;
        }
        $code = (int) $this->settings['response_code'];

        return in_array($code, [403, 404, 410, 429], true) ? $code : 403;
    }

    private function logEvent(RequestInfo $r, string $rule, string $category, string $action): void
    {
        $this->safe(function () use ($r, $rule, $category, $action): void {
            /** @var EventLogInterface $events */
            $events = $this->service('events');
            $events->log($r->ip, $rule, $category, $action, $r->context());
        });
    }

    private function rules(): RuleSet
    {
        return $this->rules ?? ($this->rules = new RuleSet($this->settings));
    }

    /** @return BlockServiceInterface|EventLogInterface|HoneypotRepositoryInterface|ScoreServiceInterface|AlertServiceInterface|BotVerifier */
    private function service(string $id)
    {
        return ($this->services)($id);
    }

    /** Fail-open для окремої дії: помилка пишеться в лог, робота триває. */
    private function safe(callable $fn)
    {
        try {
            return $fn();
        } catch (Throwable $e) {
            if ($this->logger) {
                try {
                    ($this->logger)('Security Guard: ' . get_class($e) . ': ' . $e->getMessage());
                } catch (Throwable $ignored) {
                }
            }

            return null;
        }
    }
}
