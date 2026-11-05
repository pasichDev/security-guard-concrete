<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use PasichDev\SecurityGuard\Config\Settings;
use PasichDev\SecurityGuard\Contract\AlertServiceInterface;
use PasichDev\SecurityGuard\Contract\BlockServiceInterface;
use PasichDev\SecurityGuard\Contract\EventLogInterface;
use PasichDev\SecurityGuard\Contract\HoneypotRepositoryInterface;
use PasichDev\SecurityGuard\Contract\ScoreServiceInterface;
use PasichDev\SecurityGuard\State\FileCounterStore;
use PasichDev\SecurityGuard\Waf\BotVerifier;
use PasichDev\SecurityGuard\Waf\Firewall;
use PasichDev\SecurityGuard\Waf\RequestInfo;

// --- Підробки сервісів у пам'яті ---
final class FakeBlocks implements BlockServiceInterface
{
    public $rows = [];
    public $calls = [];
    public $attempts = 0;
    public function block(string $ip, string $reason, string $category, ?int $duration = null, bool $manual = false, array $context = []): array
    {
        $this->calls[] = [$ip, $reason, $category];
        return $this->rows[$ip] = ['ip' => $ip, 'reason' => $reason, 'category' => $category, 'blockedUntil' => time() + 3600, 'permanent' => false];
    }
    public function unblock(string $ip): void { unset($this->rows[$ip]); $this->calls[] = [$ip, 'UNBLOCK', '']; }
    public function find(string $ip): ?array { return $this->rows[$ip] ?? null; }
    public function listActive(int $limit = 50, int $offset = 0, string $search = ''): array { return ['rows' => array_values($this->rows), 'total' => count($this->rows)]; }
    public function listHistory(int $limit = 50, int $offset = 0, string $search = ''): array { return ['rows' => [], 'total' => 0]; }
    public function countActive(): int { return count($this->rows); }
    public function purgeExpired(int $olderThanDays = 30): int { return 0; }
    public function recordAttempts(string $ip, int $count): void { $this->attempts += $count; }
}
final class FakeEvents implements EventLogInterface
{
    public $rows = [];
    public function log(string $ip, string $rule, string $category, string $action, array $request = []): void { $this->rows[] = [$ip, $rule, $category, $action]; }
    public function query(array $filters = [], int $limit = 50, int $offset = 0): array { return ['rows' => [], 'total' => 0]; }
    public function summary(int $from, int $to): array { return []; }
    public function purgeOlderThan(int $days): int { return 0; }
    public function last(): ?array { return $this->rows ? $this->rows[count($this->rows) - 1] : null; }
}
final class FakeHoneypot implements HoneypotRepositoryInterface
{
    public $hits = [];
    public function record(string $ip, string $url, string $userAgent): void { $this->hits[] = [$ip, $url]; }
    public function list(int $limit = 50, int $offset = 0): array { return ['rows' => [], 'total' => 0]; }
    public function trapUrls(): array { return []; }
}
final class FakeScores implements ScoreServiceInterface
{
    public $adds = [];
    public function add(string $ip, int $points, array $events): int { $this->adds[] = [$ip, $points, $events]; return $points; }
    public function reset(string $ip): void {}
    public function purgeExpired(): int { return 0; }
    public function list(int $limit = 50, int $offset = 0): array { return ['rows' => [], 'total' => 0]; }
}
final class FakeAlerts implements AlertServiceInterface
{
    public $raised = [];
    public function raise(string $type, string $severity, string $message, array $context = []): void { $this->raised[] = [$type, $severity, $message, $context]; }
    public function recent(int $limit = 20, bool $unreadOnly = false): array { return ['rows' => [], 'total' => 0]; }
    public function markAllRead(): void {}
}

final class World
{
    public $blocks;
    public $events;
    public $honeypot;
    public $scores;
    public $alerts;
    public $counters;
    public $bots;
    public $dns = [];

    public function __construct()
    {
        $this->blocks = new FakeBlocks();
        $this->events = new FakeEvents();
        $this->honeypot = new FakeHoneypot();
        $this->scores = new FakeScores();
        $this->alerts = new FakeAlerts();
        $this->counters = new FileCounterStore(sg_temp_dir('fw') . '/c', str_repeat('c', 64));
        $dns = &$this->dns;
        $this->bots = new BotVerifier(null, $this->counters, static function (string $ip) use (&$dns) {
            return $dns['ptr'][$ip] ?? $ip;
        }, static function (string $host, bool $v6) use (&$dns) {
            return $dns['a'][$host] ?? [];
        });
    }

    public function firewall(array $settings = [], array $blocks = [], array $whitelist = []): Firewall
    {
        $state = ['settings' => $settings + Settings::DEFAULTS, 'blocks' => $blocks, 'whitelist' => $whitelist, 'builtAt' => 1];
        $map = ['block' => $this->blocks, 'events' => $this->events, 'honeypot' => $this->honeypot, 'scores' => $this->scores, 'alerts' => $this->alerts, 'bots' => $this->bots];

        return new Firewall($state, $this->counters, static function (string $id) use ($map) {
            return $map[$id];
        });
    }
}

function req(string $uri, array $o = []): RequestInfo
{
    $r = new RequestInfo();
    $r->ip = $o['ip'] ?? '203.0.113.50';
    $r->method = $o['method'] ?? 'GET';
    $r->uri = $uri;
    $r->pathInfo = $o['pathInfo'] ?? (explode('?', $uri)[0]);
    $r->userAgent = $o['ua'] ?? 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
    $r->referer = $o['referer'] ?? 'https://example.org/';
    $r->hasAccept = $o['accept'] ?? true;
    $r->hasAcceptLanguage = $o['acceptLanguage'] ?? true;
    $r->bypass = $o['bypass'] ?? null;
    $r->body = $o['body'] ?? '';
    $r->isLoginAttempt = $o['login'] ?? false;
    $r->now = $o['now'] ?? time();

    return $r;
}
$no = static function (): bool { return false; };
$yes = static function (): bool { return true; };
$enforce = ['mode' => Settings::MODE_ENFORCE];

// 1. Monitor (за замовчуванням): атака лише журналюється.
$w = new World();
$fw = $w->firewall();
T::eq(null, $fw->inspect(req('/wp-login.php'), $no), 'monitor: атака пропускається');
T::eq([], $w->blocks->calls, 'monitor: бан не ставиться');
T::eq(['203.0.113.50', 'HONEYPOT', 'honeypot', 'logged'], $w->events->last(), 'monitor: подія logged');

// 2. Enforce: honeypot → бан + відмова з налаштованим кодом.
$w = new World();
$fw = $w->firewall($enforce);
$d = $fw->inspect(req('/wp-login.php'), $no);
T::eq(403, $d->status ?? null, 'enforce: honeypot → 403');
T::eq([['203.0.113.50', 'HONEYPOT', 'honeypot']], $w->blocks->calls, 'enforce: бан поставлено');
T::eq('banned', $w->events->last()[3], 'enforce: подія banned');
T::eq(1, count($w->honeypot->hits), 'honeypot записано');
$d = $w->firewall($enforce + ['response_code' => 404])->inspect(req('/.env', ['ip' => '198.51.100.7']), $no);
T::eq(404, $d->status ?? null, 'response_code 404');

// 3. Легасі-редиректи й звичайні сторінки не чіпаються навіть у enforce.
$w = new World();
$fw = $w->firewall($enforce);
foreach (['/', '/novyny/some-news', '/index.php?option=com_content&view=article&id=12', '/application/files/1234/5678/document.pdf', '/novyny/вступ-2026'] as $uri) {
    T::eq(null, $fw->inspect(req($uri), $no), 'enforce: легітимний ' . $uri);
}
T::eq([], $w->blocks->calls, 'легітимні запити без банів');

// 4. Joomla-експлойт → бан.
$w = new World();
$d = $w->firewall($enforce)->inspect(req('/index.php?option=com_jce&task=plugin.rpc'), $no);
T::eq('joomla', $d->category ?? null, 'Joomla JCE → бан');

// 5. Адміністратор і білий список обходять усе, навіть активний бан.
$w = new World();
$banned = ['203.0.113.50' => ['until' => 0, 'reason' => 'HONEYPOT', 'category' => 'honeypot']];
$fw = $w->firewall($enforce, $banned);
T::eq(null, $fw->inspect(req('/wp-login.php'), $yes), 'адмін із доступом до дашборду не блокується');
T::ok($fw->isTrusted(), 'адмін позначений довіреним');
$fw = $w->firewall($enforce + ['whitelist_ranges' => '203.0.113.0/24'], $banned);
T::eq(null, $fw->inspect(req('/wp-login.php'), $no), 'білий список (налаштування) обходить бан');
$fw = $w->firewall($enforce, $banned, [['range' => '203.0.113.50', 'expires' => time() + 60]]);
T::eq(null, $fw->inspect(req('/wp-login.php'), $no), 'автодовіра обходить бан');
$fw = $w->firewall($enforce, $banned, [['range' => '203.0.113.50', 'expires' => time() - 60]]);
T::ok($fw->inspect(req('/'), $no) !== null, 'прострочена автодовіра не діє');
T::eq(null, $w->firewall($enforce)->inspect(req('/wp-login.php', ['ip' => '127.0.0.1']), $no), 'loopback довірений');
// Перевірку користувача не викликаємо, якщо IP уже в білому списку.
$called = false;
$w->firewall($enforce + ['whitelist_ranges' => '203.0.113.'])->inspect(req('/'), static function () use (&$called): bool { $called = true; return false; });
T::ok(!$called, 'білий список перевіряється раніше за сесію');

// 6. Активний бан: відмова, лічильник спроб, 429 для підбору пароля.
$w = new World();
$fw = $w->firewall($enforce, $banned);
$d = $fw->inspect(req('/'), $no);
T::eq(403, $d->status ?? null, 'забанена IP → 403 на будь-якій сторінці');
T::eq(['203.0.113.50', 'HONEYPOT', 'blocked_ip', 'denied'], $w->events->last(), 'подія denied');
T::eq(1, $w->blocks->attempts, 'спроба забаненої IP дописана');
$fw->inspect(req('/a'), $no);
T::eq(1, $w->blocks->attempts, 'спроби в базу — не частіше разу на хвилину');
$bf = ['203.0.113.50' => ['until' => time() + 900, 'reason' => 'BRUTEFORCE', 'category' => 'bruteforce']];
$d = $w->firewall($enforce, $bf)->inspect(req('/login'), $no);
T::eq(429, $d->status ?? null, 'бан за підбір пароля → 429');
T::ok(($d->retryAfter ?? 0) > 800, 'Retry-After');
$expired = ['203.0.113.50' => ['until' => time() - 1, 'reason' => 'X', 'category' => 'scanner']];
T::eq(null, $w->firewall($enforce, $expired)->inspect(req('/'), $no), 'прострочений бан не діє');
T::eq(null, (new World())->firewall([], $banned)->inspect(req('/'), $no), 'monitor: забанена IP проходить');

// 7. Аварійний обхід.
$w = new World();
$fw = $w->firewall($enforce + ['bypass_token' => 'S3cr3t-Token-123'], $banned);
T::ok($fw->inspect(req('/', ['bypass' => 'wrong']), $no) !== null, 'неправильний sg_pass не допомагає');
T::eq(null, $fw->inspect(req('/', ['bypass' => 'S3cr3t-Token-123']), $no), 'правильний sg_pass пропускає');
T::ok(in_array(['203.0.113.50', 'UNBLOCK', ''], $w->blocks->calls, true), 'sg_pass знімає бан');
$fw = $w->firewall($enforce, $banned);
T::ok($fw->inspect(req('/', ['bypass' => '']), $no) !== null, 'порожній bypass_token вимикає обхід');

// 8. Службові шляхи: пропуск евристик лише для того, хто увійшов.
$w = new World();
$fw = $w->firewall($enforce);
$html = 'content=' . rawurlencode('<script>x</script> union select ../../');
$editorReq = req('/index.php/ccm/system/block/edit', ['method' => 'POST', 'body' => $html, 'referer' => '']);
T::eq(null, $fw->inspect($editorReq, $no, $yes), 'редактор (увійшов, без дашборду): /ccm POST з HTML пропускається');
T::eq(null, $fw->inspect(req('/dashboard/pages', ['ua' => '', 'accept' => false, 'acceptLanguage' => false]), $no, $yes), 'редактор: /dashboard без скорингу');
T::eq(null, $fw->inspect($editorReq, $yes), 'адмін із дашбордом: /ccm POST з HTML пропускається');
$w = new World();
$fw = $w->firewall($enforce);
T::ok($fw->inspect($editorReq, $no, $no) !== null, 'анонім: /ccm POST з HTML блокується');
T::ok($fw->inspect(req('/kontakty', ['method' => 'POST', 'body' => $html, 'ip' => '198.51.100.9']), $no) !== null, 'та сама форма на фронтенді блокується');
$w = new World();
$fw = $w->firewall($enforce);
T::eq(null, $fw->inspect(req('/login'), $no, $no), 'анонім: сторінка входу');
T::eq(null, $fw->inspect(req('/dashboard'), $no, $no), 'анонім: /dashboard (ядро покаже вхід)');
T::eq(null, $fw->inspect(req('/ccm/assets/localization/core/js'), $no, $no), 'анонім: локалізація JS');
T::eq(null, $fw->inspect(req('/index.php/ccm/system/heartbeat'), $no, $no), 'анонім: heartbeat');
T::eq([], $w->blocks->calls, 'без банів для легітимних анонімних службових запитів');

// 8a. Анонім на службовому маршруті: два відхилення без бану, бан з третього.
$w = new World();
$fw = $w->firewall($enforce);
$d1 = $fw->inspect(req('/ccm/system/file/usage/1'), $no, $no);
$d2 = $fw->inspect(req('/ccm/system/summary_template/render/page/1/1'), $no, $no);
T::ok(($d1->status ?? 0) === 403 && ($d2->status ?? 0) === 403, 'анонімний backend → 403');
T::eq([], $w->blocks->calls, 'перші два — без бану');
T::eq('blocked', $w->events->last()[3] ?? null, 'подія blocked');
$d3 = $fw->inspect(req('/ccm/system/dialogs/page/attributes'), $no, $no);
T::eq('CONCRETE_BACKEND_ANON', $w->blocks->calls[0][1] ?? null, 'третій — бан');
T::eq(null, $fw->inspect(req('/ccm/system/dialogs/page/attributes', ['ip' => '198.51.100.20']), $no, $yes), 'редактор, що увійшов, не зачіпається');
$w = new World();
T::eq('CONCRETE_UPGRADE_ANON', $w->firewall($enforce)->inspect(req('/index.php/ccm/system/upgrade'), $no, $no)->rule ?? null, 'анонімний upgrade — одразу бан');
$w = new World();
T::eq(null, $w->firewall()->inspect(req('/ccm/system/file/usage/1'), $no, $no), 'monitor: службовий маршрут лише журналюється');
T::eq('logged', $w->events->last()[3] ?? null, 'monitor: logged');

// 8b. Cookie.
$w = new World();
$r = req('/');
$r->cookies = 'prefs=' . rawurlencode('O:8:"stdClass":0:{}') . "\n";
T::eq('PHP_OBJECT_INJECTION', $w->firewall($enforce)->inspect($r, $no, $no)->rule ?? null, 'серіалізований об\'єкт у cookie → бан');
$r = req('/', ['ip' => '198.51.100.30']);
$r->cookies = "_ga=GA1.1.1.2\nlang=uk\n";
T::eq(null, $w->firewall($enforce)->inspect($r, $no, $no), 'звичайні cookie');

// 9. Підбір пароля.
$w = new World();
$fw = $w->firewall($enforce + ['bruteforce_threshold' => 3]);
$login = req('/login/authenticate/concrete', ['method' => 'POST', 'login' => true]);
T::eq(null, $fw->inspect($login, $no), 'POST входу пропускається до ядра');
T::eq(null, $fw->afterLogin($login, true), 'невдача 1');
T::eq(null, $fw->afterLogin($login, true), 'невдача 2');
$d = $fw->afterLogin($login, true);
T::eq(429, $d->status ?? null, 'невдача 3 → 429');
T::eq('BRUTEFORCE', $w->blocks->calls[0][1] ?? null, 'бан BRUTEFORCE');
T::eq('bruteforce', $w->alerts->raised[0][0] ?? null, 'сповіщення про підбір');
$w = new World();
$fw = $w->firewall($enforce + ['bruteforce_threshold' => 2]);
$fw->inspect($login, $no);
for ($i = 0; $i < 5; $i++) {
    $fw->afterLogin($login, false);
}
T::eq([], $w->blocks->calls, 'успішні входи не рахуються');
$fw = $w->firewall($enforce + ['bruteforce_threshold' => 1, 'whitelist_ranges' => '203.0.113.50']);
$fw->inspect($login, $no);
T::eq(null, $fw->afterLogin($login, true), 'IP з білого списку не рахується');
$w = new World();
$fw = $w->firewall(['bruteforce_threshold' => 1]);
$fw->inspect($login, $no);
T::eq(null, $fw->afterLogin($login, true), 'monitor: підбір лише журналюється');
T::eq([], $w->blocks->calls, 'monitor: без бану за підбір');
T::ok(strpos($w->alerts->raised[0][2] ?? '', 'monitor') !== false, 'monitor: сповіщення з позначкою режиму');

// 10. Ліміт частоти (статика не рахується).
$w = new World();
$fw = $w->firewall($enforce + ['rate_limit_requests' => 5, 'behavior_scoring' => false]);
for ($i = 0; $i < 20; $i++) {
    $fw->inspect(req('/application/themes/mytheme/css/theme.css'), $no);
}
T::eq([], $w->blocks->calls, 'статика не рахується в ліміт');
$d = null;
for ($i = 1; $i <= 6 && $d === null; $i++) {
    $d = $fw->inspect(req('/novyny/' . $i), $no);
}
T::eq(6, $i - 1, 'ліміт спрацьовує на 6-му запиті з 5');
T::eq('ratelimit', $d->category ?? null, 'категорія ratelimit');

// 11. Сплеск PHP-проб.
$w = new World();
$fw = $w->firewall($enforce + ['php_probe_threshold' => 3, 'rate_limit_enabled' => false, 'behavior_scoring' => false]);
$d1 = $fw->inspect(req('/random1.php'), $no);
$d2 = $fw->inspect(req('/random2.php'), $no);
$d3 = $fw->inspect(req('/random3.php'), $no);
T::ok($d1 === null && $d2 === null, 'перші невідомі .php пропускаються');
T::eq('PHP_PROBE_BURST', $d3->rule ?? null, 'третій .php за вікно → бан');
$w = new World();
$fw = $w->firewall($enforce + ['php_probe_threshold' => 2, 'rate_limit_enabled' => false]);
T::eq(null, $fw->inspect(req('/index.php?cID=1'), $no), 'index.php не PHP-проба');
T::eq(null, $fw->inspect(req('/index.php/novyny'), $no), '/index.php/... не PHP-проба');

// 12. Поведінковий скоринг.
$w = new World();
$fw = $w->firewall($enforce + ['rate_limit_enabled' => false]);
for ($i = 0; $i < 50; $i++) {
    $d = $fw->inspect(req('/novyny/' . $i, ['ua' => 'FeedReader/1.0', 'accept' => false, 'acceptLanguage' => false]), $no);
}
T::eq(null, $d, 'клієнт без Accept/Accept-Language не банується за ознаки клієнта');
$w = new World();
$fw = $w->firewall($enforce + ['rate_limit_enabled' => false]);
$d = null;
for ($i = 0; $i < 10 && $d === null; $i++) {
    $d = $fw->inspect(req('/kontakty', ['method' => 'POST', 'referer' => '', 'ua' => '', 'acceptLanguage' => false]), $no);
}
T::eq('BEHAVIOR_SCORE', $d->rule ?? null, 'POST без Referer + порожній UA → бан за скорингом');
T::ok(count($w->scores->adds) >= 1, 'бал записано в базу для панелі');
T::eq(null, (new World())->firewall($enforce)->inspect(req('/', ['ua' => 'Mozilla/5.0 (compatible; bingbot/2.0)', 'accept' => false, 'acceptLanguage' => false]), $no), 'краулер не скориться');

// 13. Перевірка пошукових ботів.
$w = new World();
$gb = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
$w->dns = ['ptr' => ['66.249.66.1' => 'crawl-66-249-66-1.googlebot.com.', '6.6.6.6' => 'evil.example.net', '7.7.7.7' => 'fake.googlebot.com'],
    'a' => ['crawl-66-249-66-1.googlebot.com' => ['66.249.66.1'], 'fake.googlebot.com' => ['1.1.1.1']]];
$fw = $w->firewall($enforce + ['rate_limit_requests' => 1]);
T::eq(null, $fw->inspect(req('/', ['ip' => '66.249.66.1', 'ua' => $gb]), $no), 'справжній Googlebot');
T::eq(null, $fw->inspect(req('/a', ['ip' => '66.249.66.1', 'ua' => $gb]), $no), 'справжній Googlebot не впирається в ліміт');
T::eq('FAKE_BOT', $fw->inspect(req('/', ['ip' => '6.6.6.6', 'ua' => $gb]), $no)->rule ?? null, 'rDNS не Google → фейк');
T::eq('FAKE_BOT', $fw->inspect(req('/', ['ip' => '7.7.7.7', 'ua' => $gb]), $no)->rule ?? null, 'прямий DNS не збігся → фейк');
T::eq(null, $fw->inspect(req('/', ['ip' => '8.8.4.4', 'ua' => $gb]), $no), 'нема PTR → не перевірено, але не бан');
T::eq(BotVerifier::VERIFIED, BotVerifier::evaluate('2001:4860:4801:10::1', ['.googlebot.com'], 'crawl.googlebot.com', ['2001:4860:4801:0010:0000:0000:0000:0001']), 'IPv6 Googlebot');
T::eq(BotVerifier::UNVERIFIED, BotVerifier::evaluate('1.2.3.4', ['.googlebot.com'], 'x.googlebot.com', []), 'прямий DNS мовчить → не перевірено');
T::ok(!BotVerifier::hostMatches('googlebot.com.evil.net', ['.googlebot.com']), 'суфікс, а не підрядок');
T::ok(BotVerifier::hostMatches('CRAWL.GOOGLEBOT.COM.', ['.googlebot.com']), 'регістр і крапка в кінці');

// 14. DDoS-сплеск: сповіщення.
$w = new World();
$fw = $w->firewall(['ddos_min_requests' => 20, 'ddos_multiplier' => 2]);
$base = intdiv(time(), 60) * 60 - 1800;
for ($m = 0; $m < 30; $m++) {
    for ($i = 0; $i < 5; $i++) {
        $fw->inspect(req('/', ['now' => $base + $m * 60]), $no);
    }
}
for ($i = 0; $i < 25; $i++) {
    $fw->inspect(req('/', ['now' => $base + 1800]), $no);
}
T::eq('ddos', $w->alerts->raised[0][0] ?? null, 'сплеск понад базову лінію × множник → сповіщення');
T::eq(1, count($w->alerts->raised), 'сповіщення про сплеск — один раз');

// 15. Вимкнений пакет — нічого не робить.
$w = new World();
T::eq(null, $w->firewall($enforce + ['enabled' => false])->inspect(req('/wp-login.php'), $no), 'enabled=false');
T::eq([], $w->events->rows, 'enabled=false — без подій');

// 16. Збій сервісу бану — запит усе одно відхилено, винятку немає.
$w = new World();
$state = ['settings' => $enforce + Settings::DEFAULTS, 'blocks' => [], 'whitelist' => []];
$logged = [];
$fw = new Firewall($state, $w->counters, static function (string $id) use ($w) {
    if ($id === 'block') {
        throw new RuntimeException('DB down');
    }
    return $w->events;
}, static function (string $m) use (&$logged): void { $logged[] = $m; });
T::eq(403, $fw->inspect(req('/.git/config'), $no)->status ?? null, 'збій бази при бані: відмова, без винятку');
T::ok(count(array_filter($logged, static function (string $m): bool { return strpos($m, 'DB down') !== false; })) === 1, 'збій записано в лог');

T::done('firewall_test');
