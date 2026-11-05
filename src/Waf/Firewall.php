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
use PasichDev\SecurityGuard\Ip\IpRange;
use PasichDev\SecurityGuard\Login\AdminIps;
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
 * пропускаємо. Режим enforce: відмова, а бан — за правилами нижче.
 *
 * Захист від «чужих банів» (будь-хто може змусити браузер відвідувача
 * відкрити /.env через <img> або посилання):
 *  - запит, який ініціював інший сайт (Sec-Fetch-Site: cross-site/same-site
 *    або Sec-Fetch-Dest: image/script/…) — лише відмова, ніколи не бан;
 *  - «пасивні» правила (усе, що спрацьовує на простий GET: honeypot,
 *    чутливі файли, сигнатури в адресі) — бан лише з 3-го РІЗНОГО влучання
 *    за 10 хв, до того — відмова;
 *  - однозначні експлойти (серіалізовані об'єкти, log4shell, XXE, виклик
 *    коду, PHP-CGI, Joomla RCE, сигнатури в тілі POST), сканер за UA,
 *    ліміти, підбір пароля — бан одразу.
 * Ключ IP — IpRange::subject(): IPv4 як є, IPv6 — /64.
 */
final class Firewall
{
    /** Скільки різних «пасивних» влучань за вікно дають бан. */
    public const PASSIVE_HITS = 3;
    public const PASSIVE_WINDOW = 600;

    /** Бали поведінки за слабку ознаку атаки (без відмови). */
    public const WEAK_POINTS = 8;

    /** Правила, за якими бан одразу (однозначні експлойти). */
    private const IMMEDIATE_RULES = [
        'PHP_OBJECT_INJECTION' => true, 'LOG4SHELL' => true, 'XXE' => true, 'CODE_EXEC' => true,
        'PHP_INI_INJECTION' => true, 'PHP_WRAPPER' => true, 'CMD_INJECTION' => true, 'PHPUNIT_RCE' => true,
        'SQL_SLEEP' => true, 'SQL_SCHEMA' => true,
    ];

    /** Joomla-правила за шляхом — проби, не експлойти. */
    private const JOOMLA_PASSIVE = ['JOOMLA_ADMIN_PROBE' => true, 'JOOMLA_FINGERPRINT' => true, 'JOOMLA_DIRECT_PHP' => true, 'JOOMLA_API_LEAK' => true];

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
    /** Рівень довіри запиту: null, 'manual', 'session', 'auto', 'bypass'. @var string|null */
    private $trust;
    /** 1 із K запитів рахується в загальний трафік (×K) — без APCu не серіалізуємо воркери на одному файлі. @var int */
    private $trafficSample;

    /**
     * @param callable $services fn(string $id) для 'block', 'events', 'honeypot', 'scores', 'alerts', 'bots'
     */
    public function __construct(array $state, CounterStore $counters, callable $services, ?callable $logger = null, ?int $trafficSample = null)
    {
        $this->state = $state;
        $this->settings = (array) ($state['settings'] ?? []) + Settings::DEFAULTS;
        $this->counters = $counters;
        $this->services = $services;
        $this->logger = $logger;
        $this->trafficSample = $trafficSample ?? ($counters->name() === 'apcu' ? 1 : 10);
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
        return $this->trust !== null;
    }

    public function trustLevel(): ?string
    {
        return $this->trust;
    }

    public function settings(): array
    {
        return $this->settings;
    }

    /**
     * Перевірка до диспетчеризації. null — пропустити запит.
     *
     * @param callable $isTrustedUser fn(): bool — увійшов користувач із доступом до дашборду (викликається ліниво)
     * @param callable|null $isRegisteredUser fn(): bool — увійшов редактор, якому довіряємо на службових шляхах
     * @param callable|null $isSignedIn fn(): bool — увійшов будь-хто (і учасник з публічною реєстрацією):
     *                       правило «анонім на службовому маршруті» до нього не застосовується
     */
    public function inspect(RequestInfo $r, callable $isTrustedUser, ?callable $isRegisteredUser = null, ?callable $isSignedIn = null): ?Decision
    {
        if (!$this->isEnabled()) {
            return null;
        }
        $s = $this->settings;
        $now = $r->now ?: time();
        $this->trust = null;
        $subject = self::subjectOf($r);

        if (!empty($s['ddos_enabled'])) {
            $this->countTraffic($now);
        }

        // 1. Аварійний обхід: знімає бан і одразу перенаправляє на ту саму адресу без токена
        //    (токен не лишається в історії браузера, Referer і журналах сайту).
        $tokenHash = (string) ($s['bypass_token_hash'] ?? '');
        if ($tokenHash === '' && (string) $s['bypass_token'] !== '') {
            $tokenHash = hash('sha256', (string) $s['bypass_token']);
        }
        if ($r->bypass !== null) {
            if ($tokenHash !== '' && $r->bypass !== '' && hash_equals($tokenHash, hash('sha256', $r->bypass))) {
                $this->emergencyUnblock($r);
                $this->trust = 'bypass';

                return new Decision(302, 'EMERGENCY_BYPASS', 'blocked_ip', 0, false, self::safeLocation($r->uri));
            }
        }

        // 2. Білий список (ручний) і адміністратори з сесією — повний обхід.
        $level = Whitelist::trustLevel($r->ip, $this->state, $now);
        if ($level === 'manual') {
            $this->trust = 'manual';

            return null;
        }
        if ($isTrustedUser()) {
            $this->trust = 'session';

            return null;
        }

        // 3. Активний бан (діє і для автодовіреної IP: автодовіра не знімає чужих банів).
        $ban = $this->activeBan($subject, $r->ip, $now);
        if ($ban !== null) {
            return $this->denyBanned($r, $ban, $now);
        }

        // Автодовіра після входу адміністратора: без евристик (підрахунок підбору чужих логінів — після відповіді).
        if ($level === 'auto') {
            $this->trust = 'auto';

            return null;
        }

        // Дашборд, /ccm/, вхід — без евристик вмісту лише для того, хто увійшов.
        $servicePath = Paths::isTrusted($r->pathInfo) || Paths::isTrusted(Paths::normalize($r->path()));
        if ($servicePath && $isRegisteredUser !== null && $isRegisteredUser()) {
            return null;
        }

        // 4. Пошукові боти (без DNS на запиті).
        if (!empty($s['verify_search_bots']) && BotVerifier::detect($r->userAgent) !== null) {
            $bot = $this->safe(function () use ($r) {
                return $this->service('bots')->verify($r->ip, $r->userAgent);
            });
            $status = is_array($bot) ? $bot['status'] : BotVerifier::UNVERIFIED;
            if ($status === BotVerifier::VERIFIED) {
                return null;
            }
            if ($status === BotVerifier::FAKE && !empty($s['block_fake_bots'])) {
                return $this->violation($r, 'FAKE_BOT', 'fake_bot', false);
            }
        }

        $rules = $this->rules();

        // 5. Honeypot.
        if (!empty($s['honeypot_enabled'])
            && $rules->isHoneypot($r->path(), HoneypotList::parseCustom((string) $s['honeypot_custom_urls']))) {
            if ($this->counters->add('hp:' . $subject, 1, 300)) {
                $this->safe(function () use ($r): void {
                    $this->service('honeypot')->record($r->ip, Text::cleanUrl($r->uri), $r->userAgent);
                });
            }

            return $this->violation($r, 'HONEYPOT', 'honeypot', true);
        }

        // 6. User-Agent (чужий сайт UA не підмінить — бан одразу).
        if (($hit = $rules->classifyUserAgent($r->userAgent)) !== null) {
            return $this->violation($r, $hit['rule'], $hit['category'], false);
        }

        // 6a. Службові маршрути Concrete, потрібні лише тому, хто увійшов.
        if ($this->on('rules_concrete')) {
            $hit = ConcreteRoutes::classifyAnonymous($r->path()) ?? ConcreteRoutes::classifyAnonymous($r->pathInfo);
            if ($hit !== null && !($isSignedIn !== null && $isSignedIn())) {
                return $this->violation($r, $hit['rule'], $hit['category'], true);
            }
        }

        // 6b. Cookie: серіалізовані об'єкти, XXE, SSRF.
        if ($r->cookies !== '' && !empty($s['rules_code_exec']) && ($hit = Signatures::classifyCookies($r->cookies)) !== null) {
            return $this->violation($r, $hit['rule'], $hit['category'], $hit['rule'] === 'SSRF_TARGET');
        }

        // 7. Гео-блок.
        $countries = CountryGuesser::parseCountries((string) $s['geo_block_countries']);
        if ($countries !== []) {
            $cc = CountryGuesser::guess($r->ip);
            if ($cc !== '' && in_array($cc, $countries, true)) {
                return $this->violation($r, 'GEO_BLOCK_' . $cc, 'geo', false);
            }
        }

        // 8. Сплеск PHP-проб — рахуємо ДО сигнатур, щоб відомі шелли теж ішли в лічильник.
        $phpBurst = false;
        if (!empty($s['php_probe_enabled']) && self::isPhpProbe($r->path())) {
            $n = $this->counters->increment('pp:' . $subject, 1, max(1, (int) $s['php_probe_window']));
            $phpBurst = $n >= max(1, (int) $s['php_probe_threshold']);
        }

        // 9. Сигнатури атак.
        $weakHit = null;
        if (($hit = $rules->classifyRequest($r->method, $r->uri, '', $r->body)) !== null) {
            if (($hit['strength'] ?? 'strong') === 'strong') {
                return $this->violation($r, $hit['rule'], $hit['category'], $this->isPassive($r, $hit));
            }
            // Слабка ознака (схоже на атаку, але буває і в тексті): журнал + бали, без відмови.
            $weakHit = $hit;
            $this->logEvent($r, $hit['rule'], $hit['category'], 'logged');
        }
        if ($phpBurst) {
            return $this->violation($r, 'PHP_PROBE_BURST', 'php_probe', true);
        }

        $isStatic = RuleSet::isStaticPath($r->path());

        // 10. Ліміт частоти.
        if (!$isStatic && !empty($s['rate_limit_enabled'])) {
            $n = $this->counters->increment('rl:' . $subject, 1, max(1, (int) $s['rate_limit_window']));
            if ($n > max(1, (int) $s['rate_limit_requests'])) {
                return $this->violation($r, 'RATE_LIMIT', 'ratelimit', false);
            }
        }

        // DDoS: під час активного сплеску банимо найактивніші IP (якщо ввімкнено).
        if (!empty($s['ddos_enabled']) && !empty($s['ddos_auto_block']) && $this->counters->get('ddos:active')) {
            $minute = intdiv($now, 60);
            $n = $this->counters->increment('di:' . $subject . ':' . $minute, 1, 120);
            if ($n >= max(30, intdiv((int) $s['ddos_min_requests'], 5))) {
                return $this->violation($r, 'DDOS_TOP_IP', 'ddos', false);
            }
        }

        // 11. Поведінковий скоринг.
        if (!empty($s['behavior_scoring']) && (!$isStatic || $weakHit !== null)) {
            return $this->score($r, $weakHit);
        }

        return null;
    }

    /**
     * Після відповіді на POST форми входу (або OAuth2 password grant).
     * $failed — Concrete знову показав форму / повернув invalid_grant.
     * Ручний білий список і сесія адміністратора — не рахуються; автодовірена
     * IP — рахується, якщо логін не належить адміністратору, що входив з неї.
     */
    public function afterLogin(RequestInfo $r, bool $failed): ?Decision
    {
        if (!$failed || !$r->isLoginAttempt || !$this->isEnabled() || empty($this->settings['bruteforce_enabled'])) {
            return null;
        }
        if (in_array($this->trust, ['manual', 'session', 'bypass'], true)) {
            return null;
        }
        if ($this->trust === 'auto' && $r->loginUser !== '' && in_array(strtolower($r->loginUser), AdminIps::usersFor($r->ip), true)) {
            return null;
        }
        $s = $this->settings;
        $subject = self::subjectOf($r);
        $n = $this->counters->increment('bf:' . $subject, 1, max(60, (int) $s['bruteforce_window']));
        $this->logEvent($r, 'LOGIN_FAILED', 'bruteforce', 'logged');
        if ($n < max(1, (int) $s['bruteforce_threshold'])) {
            return null;
        }
        $this->counters->delete('bf:' . $subject);
        $enforce = $this->isEnforcing();
        $message = $enforce
            ? t('IP %s was blocked after %d failed sign-in attempts.', $subject, $n)
            : t('IP %s made %d failed sign-in attempts (monitor mode, not blocked).', $subject, $n);
        $this->safe(function () use ($r, $message, $n): void {
            $this->service('alerts')->raise('bruteforce', 'warning', $message, ['ip' => $r->ip, 'url' => Text::cleanUrl($r->uri), 'value' => $n]);
        });
        // Підбір пароля не можна запустити з чужого сайту без пароля, тож бан одразу.
        $this->trust = null;

        return $this->violation($r, 'BRUTEFORCE', 'bruteforce', false, true);
    }

    /**
     * Запасне очищення з веба — лише якщо cron не запускав його понад добу,
     * зрідка (1 з 200 запитів) і не частіше разу на годину.
     */
    public function maintenanceFallbackDue(?bool $stale = null): bool
    {
        if (!($stale ?? Maintenance::isStale())) {
            return false;
        }

        return mt_rand(1, 200) === 1 && $this->counters->add('maint', 1, 3600);
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

    /** Ключ IP для лічильників і банів: IPv4 — адреса, IPv6 — /64. */
    public static function subjectOf(RequestInfo $r): string
    {
        $subject = IpRange::subject($r->ip);

        return $subject === '' ? $r->ip : $subject;
    }

    /** Відносна адреса без sg_pass і без можливості перенаправити на інший хост. */
    public static function safeLocation(string $uri): string
    {
        $clean = Text::cleanUrl($uri);
        $clean = '/' . ltrim(str_replace(["\r", "\n", '\\'], ['', '', '/'], $clean), '/');

        return $clean;
    }

    private function isPassive(RequestInfo $r, array $hit): bool
    {
        $rule = (string) $hit['rule'];
        if (isset(self::IMMEDIATE_RULES[$rule])) {
            return false;
        }
        if ($hit['category'] === 'joomla' && !isset(self::JOOMLA_PASSIVE[$rule])) {
            return false; // експлойт Joomla за параметрами (task=…upload, plugin.rpc)
        }
        // Сильна сигнатура в тілі POST/PUT — не «пасивна»: чужий <img> тіла не надішле.
        if ($r->body !== '' && !in_array($r->method, ['GET', 'HEAD'], true)
            && $this->rules()->classifyRequest($r->method, '/', '', $r->body) !== null) {
            return false;
        }

        return true;
    }

    private function on(string $toggle): bool
    {
        if (!array_key_exists($toggle, $this->settings)) {
            return $toggle === 'rules_concrete';
        }

        return !empty($this->settings[$toggle]);
    }

    /** Активний бан: свіжий з лічильника (до перебудови стану) або зі знімка. */
    private function activeBan(string $subject, string $ip, int $now): ?array
    {
        $recent = $this->counters->get('ban:' . $subject);
        // Лічильник — лише міст до перебудови стану: якщо знімок новіший за бан і
        // бану в ньому немає (його зняли, напр. з CLI, де APCu інший) — ігноруємо.
        $stale = is_array($recent) && (int) ($this->state['builtAt'] ?? 0) > (int) ($recent['at'] ?? 0)
            && !isset($this->state['blocks'][$subject]);
        if (is_array($recent) && !$stale && ((int) ($recent['until'] ?? -1) === 0 || (int) ($recent['until'] ?? 0) > $now)) {
            return ['until' => (int) $recent['until'], 'reason' => (string) ($recent['reason'] ?? 'BLOCKED'), 'category' => (string) ($recent['category'] ?? ''), 'manual' => !empty($recent['manual'])];
        }
        foreach (array_unique([$subject, $ip]) as $key) {
            $ban = $this->state['blocks'][$key] ?? null;
            if (is_array($ban) && ((int) $ban['until'] === 0 || (int) $ban['until'] > $now)) {
                return $ban;
            }
        }

        return null;
    }

    /**
     * Бали поведінки. Ознаки клієнта (порожній/короткий UA, нема Accept,
     * Accept-Language) — один раз на IP за TTL, бо це властивість клієнта.
     * Ознаки запиту й слабкі сигнатури накопичуються. Пропускаються лише
     * ПЕРЕВІРЕНІ боти (вони повертаються раніше).
     */
    private function score(RequestInfo $r, ?array $weakHit = null): ?Decision
    {
        $s = $this->settings;
        $subject = self::subjectOf($r);
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
            if ($this->counters->add('bt:' . $subject . ':' . $name, 1, $ttl)) {
                $signals[$name] = $points;
            }
        }
        if ($r->method === 'POST' && $r->referer === '') {
            $signals['POST_NO_REFERER'] = 5;
        }
        if (preg_match('/(?:^|&)[^=&]{0,100}=[^&]{200,}/', $r->query())) {
            $signals['LONG_QUERY'] = 5;
        }
        if ($r->referer === '' && $r->query() !== '' && preg_match('/\.(?:php|asp|aspx|cgi|jsp)$/i', $r->path())
            && self::isPhpProbe($r->path())) {
            $signals['PHP_NO_REFERER'] = 3;
        }
        if (preg_match('#(?:^|/)(?:wp-admin|wp-login|wp-includes|wp-content|phpmyadmin|myadmin|adminer|setup\.php|install\.php|\.env|\.git)(?:/|$|\?|\.)#i', $r->path())) {
            $signals['PROBE_PATH'] = 2;
        }
        if ($weakHit !== null) {
            $signals['WEAK_' . $weakHit['rule']] = self::WEAK_POINTS;
        }
        $points = array_sum($signals);
        if ($points <= 0) {
            return null;
        }
        $threshold = max(1, (int) $s['behavior_threshold']);
        $total = $this->counters->increment('sc:' . $subject, $points, $ttl);
        $pending = $this->counters->increment('sp:' . $subject, $points, $ttl);
        $events = (array) ($this->counters->get('se:' . $subject) ?? []);
        $events = array_slice(array_merge($events, array_keys($signals)), -20);
        $this->counters->set('se:' . $subject, $events, $ttl);

        // У базу (для панелі) — лише помітні бали і не частіше разу на хвилину.
        if ($total >= $threshold || ($total * 2 >= $threshold && $this->counters->add('sw:' . $subject, 1, 60))) {
            $this->safe(function () use ($subject, $pending, $events): void {
                $this->service('scores')->add($subject, $pending, $events);
            });
            $this->counters->delete('sp:' . $subject);
            $this->counters->delete('se:' . $subject);
        }
        if ($total >= $threshold) {
            $this->counters->delete('sc:' . $subject);

            return $this->violation($r, 'BEHAVIOR_SCORE', 'behavior', false);
        }

        return null;
    }

    /**
     * Порушення. monitor — лише запис. enforce — відмова; бан, якщо запит не
     * з чужого сайту і (для пасивних правил) це вже 3-тє різне влучання.
     * Якщо запис бану в базу не вдався, поточний запит усе одно відхиляємо.
     */
    private function violation(RequestInfo $r, string $rule, string $category, bool $passive, bool $force = false): ?Decision
    {
        if (!$this->isEnforcing()) {
            $this->logEvent($r, $rule, $category, 'logged');

            return null;
        }
        $subject = self::subjectOf($r);
        $denyOnly = !$force && $r->isCrossSiteTriggered();
        if (!$denyOnly && $passive) {
            $hits = (array) ($this->counters->get('pv:' . $subject) ?? []);
            $key = substr(md5($rule . '|' . Paths::normalize($r->path())), 0, 12);
            if (!in_array($key, $hits, true)) {
                $hits[] = $key;
                $this->counters->set('pv:' . $subject, array_slice($hits, -10), self::PASSIVE_WINDOW);
            }
            $denyOnly = count($hits) < self::PASSIVE_HITS;
            if (!$denyOnly) {
                $this->counters->delete('pv:' . $subject);
            }
        }
        if ($denyOnly) {
            $this->logEvent($r, $rule, $category, 'blocked');

            return new Decision($this->statusFor($category), $rule, $category);
        }
        $until = 0;
        $row = $this->safe(function () use ($r, $subject, $rule, $category) {
            return $this->service('block')->block($subject, $rule, $category, null, false, $r->context());
        });
        if (is_array($row)) {
            $until = !empty($row['permanent']) ? 0 : (int) ($row['blockedUntil'] ?? 0);
            $this->state['blocks'][$subject] = ['until' => $until, 'reason' => $rule, 'category' => $category];
        }
        $this->logEvent($r, $rule, $category, 'banned');
        $now = $r->now ?: time();

        return new Decision($this->statusFor($category), $rule, $category, $until > $now ? $until - $now : 0, true);
    }

    private function denyBanned(RequestInfo $r, array $ban, int $now): ?Decision
    {
        $category = (string) ($ban['category'] ?? '');
        $reason = (string) ($ban['reason'] ?? 'BLOCKED');
        $subject = self::subjectOf($r);
        // Ручний бан з панелі — свідоме рішення адміністратора: діє і в режимі monitor.
        if (!$this->isEnforcing() && empty($ban['manual'])) {
            $this->logEvent($r, $reason, 'blocked_ip', 'logged');

            return null;
        }
        $this->logEvent($r, $reason, 'blocked_ip', 'denied');
        // Спроби забаненої IP: копимо в лічильнику, у базу — раз на хвилину.
        $this->counters->increment('ba:' . $subject, 1, 3600);
        if ($this->counters->add('baw:' . $subject, 1, 60)) {
            $pending = (int) ($this->counters->get('ba:' . $subject) ?? 0);
            $this->counters->delete('ba:' . $subject);
            $this->safe(function () use ($subject, $pending): void {
                $block = $this->service('block');
                if ($block instanceof BlockService || method_exists($block, 'recordAttempts')) {
                    $block->recordAttempts($subject, $pending);
                }
            });
        }
        $until = (int) $ban['until'];

        return new Decision($this->statusFor($category), $reason, $category, $until > $now ? $until - $now : 0, true);
    }

    private function emergencyUnblock(RequestInfo $r): void
    {
        $subject = self::subjectOf($r);
        $this->safe(function () use ($r): void {
            $this->service('block')->unblock($r->ip);
        });
        $this->safe(function () use ($subject): void {
            $this->service('scores')->reset($subject);
        });
        foreach (['sc:', 'sp:', 'se:', 'bf:', 'rl:', 'pp:', 'pv:', 'ban:'] as $prefix) {
            $this->counters->delete($prefix . $subject);
        }
        unset($this->state['blocks'][$subject], $this->state['blocks'][$r->ip]);
        // У журнал — без адреси: у ній був токен (контекст і так його вирізає).
        $this->logEvent($r, 'EMERGENCY_BYPASS', 'blocked_ip', 'logged');
    }

    /**
     * Хвилинні кошики загального трафіку (вибірка 1 з K, ×K). Базова лінія —
     * середнє попередніх 30 хвилин (рахується раз на хвилину і лише коли
     * трафік уже вище мінімуму).
     */
    private function countTraffic(int $now): void
    {
        $k = max(1, $this->trafficSample);
        if ($k > 1 && mt_rand(1, $k) !== 1) {
            return;
        }
        $s = $this->settings;
        $minute = intdiv($now, 60);
        $count = $this->counters->increment('dd:' . $minute, $k, 7200);
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
