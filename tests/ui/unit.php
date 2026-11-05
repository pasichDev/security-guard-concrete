<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

/*
 * Перевірки допоміжних класів інтерфейсу і перевірки безпеки без Concrete:
 *   php tests/ui/unit.php
 */

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\IpRange;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Period;

$pass = 0;
$fail = 0;
function check(string $name, bool $ok): void
{
    global $pass, $fail;
    if ($ok) {
        ++$pass;
    } else {
        ++$fail;
        fwrite(STDERR, "FAIL: {$name}\n");
    }
}

// --- IpRange
foreach (['203.0.113.7', '2001:db8::1', '203.0.113.', '10.', '10.0.0.0/8', '203.0.113.0/24', '2001:db8::/32', '::1'] as $ok) {
    check("valid {$ok}", IpRange::validate($ok) === null);
}
foreach (['', 'abc', '0.0.0.0/0', '1.0.0.0/7', '::/0', '2001:db8::/15', '256.1.1.1', '1.2.3.4/33', '01.2.3.', '1.2.3.4.5', '<script>', str_repeat('1', 70), '1.2.3.4 5.6.7.8'] as $bad) {
    check("invalid {$bad}", IpRange::validate($bad) !== null);
}
$list = IpRange::parseList("198.51.100.23 # office\n10.0.0.0/8, 192.168.1.\n\n# comment\nbad-entry\n10.0.0.0/8");
check('parseList valid', $list['valid'] === ['198.51.100.23', '10.0.0.0/8', '192.168.1.']);
check('parseList errors', count($list['errors']) === 1);

// --- Period (часовий пояс сайту)
$now = (new DateTimeImmutable('2026-11-05 01:30:00', new DateTimeZone('Europe/Kyiv')))->getTimestamp();
$p = Period::fromInput('7', '', '', $now);
check('7d from', $p->fromDay === '2026-10-30');
check('7d to', $p->toDay === '2026-11-05');
check('7d count', $p->dayCount() === 7);
check('7d fromTs is local midnight', $p->fromTs === (new DateTimeImmutable('2026-10-30 00:00:00', new DateTimeZone('Europe/Kyiv')))->getTimestamp());
check('7d toTs exclusive', $p->toTs === (new DateTimeImmutable('2026-11-06 00:00:00', new DateTimeZone('Europe/Kyiv')))->getTimestamp());
$p = Period::fromInput('custom', '2026-10-25', '2026-10-01', $now);
check('custom swapped', $p->fromDay === '2026-10-01' && $p->toDay === '2026-10-25' && $p->key === 'custom');
$p = Period::fromInput('custom', '2020-01-01', '2026-12-31', $now);
check('custom clamps future and length', $p->toDay === '2026-11-05' && $p->dayCount() === Period::MAX_DAYS);
$p = Period::fromInput('custom', '2026-02-30', '2026-03-01', $now);
check('invalid date falls back to 30', $p->key === '30' && $p->dayCount() === 30);
$p = Period::fromInput('evil', '', '', $now);
check('unknown preset falls back', $p->key === '30');
// Перехід на зимовий час (25.10.2026 у Києві): день має 25 годин, але це один день.
$p = Period::fromInput('custom', '2026-10-24', '2026-10-26', $now);
check('DST days', $p->days() === ['2026-10-24', '2026-10-25', '2026-10-26']);
$p = Period::lastDays(1, $now);
check('lastDays(1)', $p->fromDay === '2026-11-05' && $p->toDay === '2026-11-05');

// --- Період повністю в майбутньому
$p = Period::fromInput('custom', '2027-01-01', '2027-02-01', $now);
check('future period clamped to today', $p->fromDay === '2026-11-05' && $p->toDay === '2026-11-05' && $p->notice !== '');

// --- LogPaths: межі акаунта, символьні посилання, шаблони лише в імені файлу
require_once SG_PKG . '/controllers/single_page/dashboard/security_guard/support/log_paths.php';
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\LogPaths;
$home = sys_get_temp_dir() . '/sg-home-' . getmypid();
@mkdir($home . '/access-logs', 0755, true);
@mkdir($home . '/logs', 0755, true);
file_put_contents($home . '/access-logs/example.com-ssl_log', 'x');
@symlink('/etc', $home . '/escape');
$root = realpath($home);
check('logpaths root ok', LogPaths::validateRoot($root, $root) === null);
check('logpaths root ~', LogPaths::validateRoot('~/logs', $root) === null);
check('logpaths root outside', LogPaths::validateRoot('/etc', $root) !== null);
check('logpaths root symlink escape', LogPaths::validateRoot($root . '/escape', $root) !== null);
check('logpaths root dotdot', LogPaths::validateRoot($root . '/../', $root) !== null);
check('logpaths source glob in name', LogPaths::validateSource('~/access-logs/*-ssl_log', $root) === null);
check('logpaths source glob in dir', LogPaths::validateSource('~/*/x.log', $root) !== null);
check('logpaths source outside', LogPaths::validateSource('/var/log/*.log', $root) !== null);
check('logpaths source via symlink', LogPaths::validateSource($root . '/escape/passwd', $root) !== null);
check('logpaths no root', LogPaths::validateSource('/x', null) !== null && LogPaths::validateRoot('', null) === null);
$f = LogPaths::filter([$root . '/access-logs/example.com-ssl_log' => 1, '/etc/passwd' => 2, $root . '/escape/passwd' => 3], $root);
check('logpaths filter keeps only inside', array_keys($f) === [$root . '/access-logs/example.com-ssl_log']);
@unlink($home . '/escape');
@unlink($home . '/access-logs/example.com-ssl_log');
@rmdir($home . '/access-logs');
@rmdir($home . '/logs');
@rmdir($home);

// --- Format
check('flag UA', Format::flag('ua') === "\u{1F1FA}\u{1F1E6}");
check('flag bad', Format::flag('<x>') === '' && Format::flag('') === '' && Format::flag('XX') === '');
check('truncate', Format::truncate(str_repeat('а', 100), 10) === str_repeat('а', 9) . '…');
check('truncate control chars', Format::truncate("a\x00b\nc", 10) === 'a b c');
check('bytes', Format::bytes(1536) === "1,5\u{00A0}KB" && Format::bytes(10) === "10\u{00A0}B");
check('day', Format::day('2026-11-05') === '05.11.2026');
check('duration', Format::duration(0) === 'Permanent' && Format::duration(86400 * 7) === '7 d');
$pairs = Format::pairs(['a' => 1, 'b' => 5]);
check('pairs map', $pairs[0][0] === 'b' && $pairs[0][1] === 5);
$pairs = Format::pairs([['ip' => '1.1.1.1', 'count' => 3, 'attacks' => 1], ['url' => '/x', 'count' => 9]]);
check('pairs objects', $pairs[0][0] === '/x' && $pairs[1][0] === '1.1.1.1');
$pairs = Format::pairs([['/a', 2], ['/b', 7]]);
check('pairs tuples', $pairs[0] === ['/b', 7, []]);
check('pairs garbage', Format::pairs('x') === [] && Format::pairs([null, 'q']) === []);

// --- CSV-клітинки (та сама логіка, що в Events::csvCell — приватна, тому перевірка через Reflection)
if (!class_exists('Concrete\Core\Page\Controller\DashboardPageController')) {
    eval('namespace Concrete\Core\Page\Controller; abstract class DashboardPageController { }');
}
require_once SG_PKG . '/controllers/single_page/dashboard/security_guard/support/base_controller.php';
require_once SG_PKG . '/controllers/single_page/dashboard/security_guard/events.php';
$m = new ReflectionMethod('Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Events', 'csvCell');
$m->setAccessible(true);
check('csv =', $m->invoke(null, '=HYPERLINK("x")') === "'=HYPERLINK(\"x\")");
check('csv +', $m->invoke(null, '+1') === "'+1");
check('csv -', $m->invoke(null, '-1') === "'-1");
check('csv @', $m->invoke(null, '@SUM(A1)') === "'@SUM(A1)");
check('csv tab', $m->invoke(null, "\tx") === "'\tx");
check('csv newline flattened', $m->invoke(null, "a\nb") === 'a b');
check('csv plain', $m->invoke(null, '/index.php?a=1') === '/index.php?a=1');

// --- Checklist: сканування і пункти без мережі
eval('namespace Concrete\Core\Package; class PackageService { public $cfg; public function getClass($h) { return $this; } public function getConfig() { return $this->cfg; } }');
require_once SG_PKG . '/src/Config/Settings.php';
// Підпис самоперевірки залежить від каталогу стану Concrete — тут заглушка.
eval('namespace PasichDev\\SecurityGuard\\Http; final class SelfProbe { public const HEADER = "X-Security-Guard-Probe"; public static function headerValue(): string { return "1:test"; } public static function headerFor(string $m, string $u): string { return "1:test"; } }');
require_once SG_PKG . '/src/Audit/Checklist.php';

final class SgCfg
{
    public $data = [];

    public function get($k)
    {
        return $this->data[$k] ?? null;
    }

    public function save($k, $v)
    {
        $this->data[$k] = $v;
    }
}
final class SgSettingsStub
{
    public $v = ['enabled' => true, 'mode' => 'monitor'];

    public function get($k)
    {
        return $this->v[$k];
    }
}
final class SgCategory
{
    public function isEnabled()
    {
        return true;
    }

    public function getTimeWindow()
    {
        return 300;
    }

    public function getBanDuration()
    {
        return null;
    }

    public function getMaxEvents()
    {
        return 5;
    }
}

$root = sys_get_temp_dir() . '/sg-audit-' . getmypid();
@mkdir($root . '/application/config', 0750, true);
@mkdir($root . '/application/files/cache', 0777, true);
@mkdir($root . '/application/files/security_guard', 0777, true);
@mkdir($root . '/application/files/a/b', 0777, true);
file_put_contents($root . '/application/config/database.php', '<?php return [];');
chmod($root . '/application/config/database.php', 0644);
chmod($root . '/application/config', 0750);
file_put_contents($root . '/application/files/a/b/shell.php', '<?php');
file_put_contents($root . '/application/files/a/photo.php.jpg', 'x');
file_put_contents($root . '/application/files/a/ok.jpg', 'x');
file_put_contents($root . '/application/files/cache/c.php', '<?php');
file_put_contents($root . '/application/files/security_guard/state.php', '<?php');
file_put_contents($root . '/index.php', '<?php');
chmod($root . '/index.php', 0666);
chmod($root . '/application/files/a', 0755);
chmod($root . '/application/files/a/b', 0755);

$app = new \Concrete\Core\Application\Application();
$pkgService = new \Concrete\Core\Package\PackageService();
$pkgService->cfg = new SgCfg();
$siteCfg = new SgCfg();
$siteCfg->data = ['concrete.version' => '9.5.2', 'concrete.version_installed' => '9.5.2', 'concrete.error.display.guests' => 'message', 'concrete.cache.pages' => false];
$app->bindings['Concrete\Core\Package\PackageService'] = $pkgService;
$app->bindings['PasichDev\SecurityGuard\Config\Settings'] = new SgSettingsStub();
$app->bindings['config'] = $siteCfg;
$app->bindings['failed_login'] = new class () {
    public function getCategory()
    {
        return new SgCategory();
    }
};
$app->bindings['http/client'] = new class () {
    public function request($m, $url, $opt)
    {
        throw new RuntimeException('no network in tests');
    }
};

$audit = new \PasichDev\SecurityGuard\Audit\Checklist($app, 'https://example.com', $root, $root . '/application');
$result = $audit->run();
$by = [];
foreach ($result['items'] as $it) {
    $by[$it['id']] = $it;
}
check('audit config perms warn (0644 world-readable)', ($by['config_perms']['status'] ?? '') === 'warn');
check('audit php in uploads fail', ($by['php_uploads']['status'] ?? '') === 'fail');
check('audit php in uploads finds 2 (not cache/state)', count($by['php_uploads']['details'] ?? []) === 2);
check('audit world writable warn', ($by['world_writable']['status'] ?? '') === 'warn');
$wwList = implode(' ', $by['world_writable']['details'] ?? []);
check('audit world writable lists index.php, skips cache', strpos($wwList, 'index.php') !== false && strpos($wwList, 'files/cache') === false);
check('audit http probe unknown without network', ($by['http_probe']['status'] ?? '') === 'unknown');
check('audit headers unknown without network', ($by['headers']['status'] ?? '') === 'unknown');
check('audit https ok', ($by['https']['status'] ?? '') === 'ok');
check('audit mode monitor warn', ($by['mode']['status'] ?? '') === 'warn');
check('audit debug message warn', ($by['debug']['status'] ?? '') === 'warn');
check('audit page cache warn', ($by['page_cache']['status'] ?? '') === 'warn');
check('audit failed login ok', ($by['failed_login']['status'] ?? '') === 'ok');
check('audit php version present', isset($by['php_version']));
check('audit counts sum', array_sum($result['counts']) === count($result['items']));
$audit->save($result);
$last = \PasichDev\SecurityGuard\Audit\Checklist::lastResult($app);
check('audit saved and reloaded', is_array($last) && count($last['items']) === count($result['items']));

// HTTP-проби: відповіді-заглушки.
$app->bindings['http/client'] = new class () {
    public $calls = [];

    public function request($m, $url, $opt)
    {
        $this->calls[] = $url;
        $path = parse_url($url, PHP_URL_PATH);
        $map = ['/.env' => [200, 'DB_PASSWORD=x'], '/.git/config' => [404, ''], '/composer.json' => [403, ''], '/application/config/database.php' => [200, ''], '/' => [200, '<html>']];
        [$code, $body] = $map[$path] ?? [404, ''];

        return new class ($code, $body, $opt) {
            private $code;
            private $body;

            public function __construct($code, $body, $opt)
            {
                $this->code = $code;
                $this->body = $body;
                if (($opt['allow_redirects'] ?? true) !== false || empty($opt['timeout'])) {
                    throw new RuntimeException('unsafe client options');
                }
            }

            public function getStatusCode()
            {
                return $this->code;
            }

            public function getHeaders()
            {
                return $this->code === 200 ? ['X-Content-Type-Options' => ['nosniff'], 'Strict-Transport-Security' => ['max-age=1']] : [];
            }

            public function getBody()
            {
                $b = $this->body;

                return new class ($b) {
                    private $b;

                    public function __construct($b)
                    {
                        $this->b = $b;
                    }

                    public function read($n)
                    {
                        return substr($this->b, 0, $n);
                    }
                };
            }
        };
    }
};
$result = (new \PasichDev\SecurityGuard\Audit\Checklist($app, 'https://example.com', $root, $root . '/application'))->run();
$by = [];
foreach ($result['items'] as $it) {
    $by[$it['id']] = $it;
}
check('probe finds exposed .env', ($by['http_probe']['status'] ?? '') === 'fail' && strpos($by['http_probe']['finding'], '/.env') !== false);
check('probe empty database.php is not a leak', strpos($by['http_probe']['finding'], 'database.php') === false);
check('headers warn: X-Frame-Options missing', ($by['headers']['status'] ?? '') === 'warn' && strpos($by['headers']['finding'], 'X-Frame-Options') !== false);
foreach ($app->bindings['http/client']->calls as $u) {
    check("probe same host {$u}", parse_url($u, PHP_URL_HOST) === 'example.com');
}

// прибирання
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
foreach ($it as $f) {
    $f->isDir() ? rmdir((string) $f) : unlink((string) $f);
}
rmdir($root);

echo "{$pass} passed, {$fail} failed\n";
exit($fail ? 1 : 0);
