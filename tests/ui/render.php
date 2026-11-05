<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

/*
 * Рендер усіх шаблонів дашборду з вигаданими даними.
 *   php tests/ui/render.php <вихідний каталог> [css-url-дашборду]
 * Падає на будь-якому notice/warning. Перевіряє, що атакуючі значення
 * (URL/UA з <script>) у вихідному HTML екрановані.
 */

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$outDir = $argv[1] ?? sys_get_temp_dir() . '/sg-ui';
$dashboardCss = $argv[2] ?? '';
if (!is_dir($outDir)) {
    mkdir($outDir, 0777, true);
}

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Period;
use PasichDev\SecurityGuard\Config\Settings;

// Settings.php залежить лише від PackageService у конструкторі — DEFAULTS/GROUPS читаються статично.
if (!class_exists('Concrete\Core\Package\PackageService')) {
    eval('namespace Concrete\Core\Package; class PackageService {}');
}
require_once SG_PKG . '/src/Config/Settings.php';

$now = time();
$evil = '/index.php?q=<script>alert(1)</script>&x="\'><img src=x onerror=alert(2)>';
$evilUa = 'Mozilla/5.0 <script>steal()</script> "quoted" \'single\'';

$period = Period::fromInput('30');
$series = static function (int $seed, int $scale) use ($period) {
    $out = [];
    foreach ($period->days() as $i => $d) {
        $v = (int) (abs(sin($i * 0.7 + $seed)) * $scale + ($i % 7 === 3 ? $scale : 0));
        $out[] = ['label' => substr($d, 8, 2) . '.' . substr($d, 5, 2), 'title' => $d, 'value' => $v];
    }

    return $out;
};
$events = [];
foreach (['wordpress', 'secrets', 'joomla', 'shells', 'injection', 'honeypot', 'bruteforce'] as $i => $cat) {
    $events[] = [
        'id' => $i + 1, 'ip' => '203.0.113.' . (10 + $i), 'rule' => strtoupper($cat) . '_RULE', 'category' => $cat,
        'action' => ['logged', 'blocked', 'banned', 'denied'][$i % 4], 'method' => 'GET',
        'url' => $evil . str_repeat('/very-long-path-segment', $i), 'userAgent' => $evilUa, 'referrer' => '',
        'country' => ['CN', 'US', 'RU', 'NL', 'DE', 'UA', ''][$i], 'createdAt' => $now - $i * 3600,
    ];
}
$settings = Settings::DEFAULTS;
$settings['bypass_token'] = 'Abc_def-1234567890xyz';
$settings['whitelist_ranges'] = "198.51.100.23\n10.0.0.0/8";

$common = [
    'token' => new SgFakeToken(),
    'sgServiceErrors' => ['Hosting log statistics is unavailable: Table SecurityGuardDailyStats does not exist'],
    'sgMode' => 'monitor',
];
$clientIps = ['resolved' => '198.51.100.20', 'remote' => '10.1.2.3', 'all' => ['198.51.100.20', '10.1.2.3']];
$pagination = ['total' => 1234, 'perPage' => 50, 'page' => 3, 'pages' => 25, 'query' => ['ip' => '1.2.3.4', 'category' => '']];

$modulesFn = static function (array $s) {
    return [
        ['label' => t('Firewall enabled'), 'on' => true, 'weight' => 3],
        ['label' => t('Enforce mode (attacks are blocked)'), 'on' => false, 'weight' => 3],
        ['label' => t('Attack signatures (%s of %s groups)', 9, 9), 'on' => true, 'weight' => 2],
        ['label' => t('E-mail alerts'), 'on' => false, 'weight' => 1],
    ];
};
$audit = [
    'ranAt' => $now - 600, 'duration' => 12.3,
    'counts' => ['ok' => 5, 'warn' => 3, 'fail' => 1, 'unknown' => 1],
    'items' => [
        ['id' => 'php_uploads', 'title' => t('PHP files in application/files'), 'status' => 'fail', 'finding' => 'Found 2 <b>files</b>', 'advice' => 'Delete them', 'details' => ['application/files/x/<script>.php', 'application/files/y.php.jpg']],
        ['id' => 'headers', 'title' => t('Security headers on the home page'), 'status' => 'warn', 'finding' => 'Missing: Content-Security-Policy', 'advice' => 'Add headers', 'details' => []],
        ['id' => 'mode', 'title' => t('Firewall mode'), 'status' => 'ok', 'finding' => 'Enforce', 'advice' => '', 'details' => []],
        ['id' => 'http_probe', 'title' => t('Sensitive files reachable from the internet'), 'status' => 'unknown', 'finding' => 'No response', 'advice' => '', 'details' => ['/.env — no response']],
    ],
];

$pages = [
    'overview' => [
        'period' => $period,
        'settings' => $settings,
        'modules' => $modulesFn($settings),
        'tiles' => ['today' => 37, 'd7' => 1450, 'd30' => 19387, 'ips30' => 728, 'activeBans' => 12, 'loginFailed' => 62, 'bruteforce' => 3, 'overload' => 47],
        'summary' => ['byCategory' => ['wordpress' => 15967, 'secrets' => 3301, 'joomla' => 2858, 'shells' => 1030, 'injection' => 28, 'ddos' => 2]],
        'statSum' => [],
        'series' => ['waf' => $series(1, 900), 'logAttacks' => $series(2, 1200), 'total' => $series(3, 8000), 'overload' => $series(4, 0)],
        'hasStats' => true,
        'topIps' => [
            ['ip' => '203.0.113.5', 'waf' => 2854, 'logs' => 3000, 'country' => 'CN', 'banned' => true],
            ['ip' => '198.51.100.20', 'waf' => 120, 'logs' => 0, 'country' => 'UA', 'banned' => false],
            ['ip' => '2001:db8::1', 'waf' => 0, 'logs' => 99, 'country' => '', 'banned' => false],
            ['ip' => '66.249.70.37', 'waf' => 0, 'logs' => 2839, 'country' => 'US', 'banned' => false, 'bot' => 'Googlebot<script>'],
        ],
        'categorySources' => ['waf' => [], 'logs' => ['wordpress' => 15967, 'secrets' => 3301, '<b>x</b>' => 3]],
        'countrySources' => ['waf' => ['CN' => 5000, 'US' => 2400, '<x>' => 1], 'logs' => ['NL' => 800]],
        'recentEvents' => $events,
        'alerts' => ['rows' => [['id' => 1, 'type' => 'ddos', 'severity' => 'critical', 'message' => 'Spike <b>5x</b> ' . $evil, 'ip' => '203.0.113.5', 'isRead' => 0, 'createdAt' => $now - 60]], 'total' => 1],
        'audit' => $audit,
        'clientIps' => $clientIps,
        'quickDurations' => ['escalation', '3600', '0'],
        'lastIngestAt' => $now - 7200,
    ],
    'events' => [
        'rows' => $events, 'total' => 1234,
        'filters' => ['category' => 'secrets', 'outcome' => '', 'ip' => '', 'from' => '2026-10-01', 'to' => '', 'search' => '"><script>'],
        'categories' => \Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format::categoryLabels(),
        'actions' => \Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format::actionLabels(),
        'pagination' => $pagination, 'exportUrl' => '/index.php/dashboard/security_guard/events/export?ccm_token=1:x',
    ],
    'blocks' => [
        'tab' => 'active', 'search' => '', 'activeCount' => 2, 'clientIps' => $clientIps,
        'myBans' => ['10.1.2.3' => ['ip' => '10.1.2.3']], 'prefillIp' => '66.249.70.37', 'prefillBot' => 'Googlebot',
        'durations' => ['escalation' => 'By escalation rules', '3600' => '1 hour', '0' => 'Permanent'],
        'rows' => [
            ['ip' => '203.0.113.5', 'reason' => 'SQL_UNION', 'category' => 'injection', 'blockedUntil' => $now + 3600, 'permanent' => 0, 'escalationLevel' => 1, 'attempts' => 17, 'manual' => 0, 'lastUrl' => $evil, 'lastUserAgent' => $evilUa, 'country' => 'CN', 'createdAt' => $now - 100],
            ['ip' => '198.51.100.99', 'reason' => 'MANUAL', 'category' => 'manual', 'blockedUntil' => 0, 'permanent' => 1, 'escalationLevel' => 0, 'attempts' => 0, 'manual' => 1, 'lastUrl' => null, 'lastUserAgent' => null, 'country' => null, 'createdAt' => $now - 100],
        ],
        'pagination' => ['total' => 2, 'perPage' => 50, 'page' => 1, 'pages' => 1, 'query' => []],
    ],
    'whitelist' => [
        'manual' => [['id' => 1, 'ipRange' => '198.51.100.23', 'description' => 'Office <script>', 'auto' => false, 'expiresAt' => 0, 'createdAt' => $now - 86400]],
        'auto' => [['id' => 2, 'ipRange' => '198.51.100.20', 'description' => 'admin', 'auto' => true, 'expiresAt' => $now + 5 * 86400, 'createdAt' => $now - 86400], ['id' => 3, 'ipRange' => '198.51.100.21', 'description' => null, 'auto' => true, 'expiresAt' => $now - 5, 'createdAt' => $now - 86400]],
        'fromSettings' => ['10.0.0.0/8'], 'clientIps' => $clientIps, 'trustAdmin' => true, 'trustDays' => 7,
        'expiries' => ['0' => 'Never expires', '86400' => '24 hours'],
    ],
    'honeypot' => [
        'traps' => ['/wp-login.php', '/administrator/index.php.bak', '/my-trap'], 'customTraps' => ['/my-trap'], 'enabled' => true,
        'rows' => [['id' => 1, 'ip' => '203.0.113.9', 'url' => $evil, 'userAgent' => $evilUa, 'createdAt' => $now - 50]],
        'pagination' => ['total' => 1, 'perPage' => 50, 'page' => 1, 'pages' => 1, 'query' => []],
    ],
    'scores' => [
        'rows' => [
            ['ip' => '203.0.113.7', 'score' => 30, 'events' => ['empty_ua' => 2, 'no_accept_language' => 1], 'banned' => true, 'updatedAt' => $now - 30],
            ['ip' => '203.0.113.8', 'score' => 10, 'events' => [['type' => 'post_no_referer<script>']], 'banned' => false, 'updatedAt' => $now - 300],
        ],
        'threshold' => 25, 'ttl' => 3600, 'scoringOn' => true, 'clientIps' => $clientIps,
        'pagination' => ['total' => 2, 'perPage' => 50, 'page' => 1, 'pages' => 1, 'query' => []],
    ],
    'traffic' => [
        'period' => $period, 'hasData' => true,
        'sum' => ['totalRequests' => 193333, 'uniqueIps' => 4000, 'attackRequests' => 19387, 'attackIps' => 728, 'blocked403' => 5000, 'loginFailed' => 44, 'errors404' => 3000, 'errors5xx' => 12, 'overload508' => 273, 'botRequests' => 50000, 'bytes' => 9876543210],
        'series' => [
            'totalRequests' => $series(1, 8000), 'attackRequests' => $series(2, 1000), 'uniqueIps' => $series(3, 60), 'errors404' => $series(4, 300),
            'errors5xx' => $series(5, 0), 'overload508' => $series(6, 40), 'botRequests' => $series(7, 2000), 'bytes' => $series(8, 300000000),
        ],
        'hours' => array_map(static function ($h) {
            return ['label' => sprintf('%02d', $h), 'title' => $h . ':00', 'value' => 100 + $h * 10];
        }, range(0, 23)),
        'breakdown' => [
            'statuses' => ['200' => 150000, '404' => 3000, '403' => 5000, '508' => 273, '301' => 9000],
            'categories' => ['wordpress' => 15000, 'secrets' => 3000],
            'topUrls' => [['url' => '/', 'count' => 5000], ['url' => $evil, 'count' => 3]],
            'top404' => [[$evil, 7]],
            'topIps' => [['ip' => '203.0.113.5', 'count' => 1500, 'bot' => null], ['ip' => '66.249.70.37', 'count' => 900, 'bot' => 'Googlebot'], ['ip' => '1.1.1.1', 'count' => 5]],
            'countries' => ['US' => 100],
        ],
        'lastIngestAt' => $now - 3600,
        'sources' => ['/home/u/access-logs/example.com-ssl_log' => 123456, '/home/u/logs/<x>.gz' => 5],
        'excludedIps' => "198.51.100.23\n10.0.0.1",
    ],
    'checklist' => ['audit' => $audit, 'enforcing' => true, 'baseUrl' => 'https://example.com'],
    'settings' => [
        'values' => $settings, 'groups' => Settings::GROUPS, 'clientIps' => $clientIps, 'siteUrl' => 'https://example.com',
        'sources' => ['/home/u/access-logs/example.com-ssl_log' => 1],
    ],
];

// Поля налаштувань будуються в контролері; тут — спрощена копія з типами.
$fields = [];
foreach (Settings::DEFAULTS as $k => $d) {
    $type = is_bool($d) ? 'bool' : (is_int($d) ? 'int' : (is_array($d) ? 'escalation' : 'string'));
    $type = ['mode' => 'mode', 'response_code' => 'response_code', 'bypass_token' => 'token', 'whitelist_ranges' => 'ranges', 'log_exclude_ips' => 'ranges', 'honeypot_custom_urls' => 'paths', 'log_sources' => 'sources'][$k] ?? $type;
    $fields[$k] = ['label' => 'Label ' . $k, 'help' => 'Help text for ' . $k, 'type' => $type, 'min' => 1, 'max' => 100];
}
$pages['settings']['fields'] = $fields;

$failures = 0;
$index = [];
foreach ($pages as $name => $vars) {
    $vars += $common;
    $vars['view'] = new SgFakeView('/dashboard/security_guard/' . $name);
    $vars['sgPagePath'] = '/dashboard/security_guard/' . $name;
    $vars['sgPageUrl'] = '/index.php/dashboard/security_guard/' . $name;
    ob_start();
    try {
        (static function () use ($vars, $name) {
            extract($vars);
            include SG_PKG . '/single_pages/dashboard/security_guard/' . $name . '.php';
        })();
        $html = ob_get_clean();
    } catch (\Throwable $e) {
        ob_end_clean();
        fwrite(STDERR, "FAIL {$name}: " . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine() . "\n");
        ++$failures;
        continue;
    }
    // Сирий <script> з даних атакувальника не має з'явитися у виводі.
    if (preg_match('/<script>alert|<script>steal|onerror=alert\(2\)>|<img src=x/i', $html)) {
        fwrite(STDERR, "FAIL {$name}: unescaped attacker data in output\n");
        ++$failures;
    }
    $doc = '<!DOCTYPE html><html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' . h($name) . '</title>'
        . ($dashboardCss !== '' ? '<link rel="stylesheet" href="' . h($dashboardCss) . '">' : '')
        . '<link rel="stylesheet" href="security-guard.css"></head><body class="p-4" style="background:#fff;max-width:1280px;margin:0 auto">'
        . '<h1 class="h3 mb-3">' . h($name) . '</h1>' . $html
        . '<script src="security-guard.js"></script></body></html>';
    file_put_contents($outDir . '/' . $name . '.html', $doc);
    $index[] = '<li><a href="' . h($name) . '.html">' . h($name) . '</a></li>';
    echo "ok {$name} (" . strlen($html) . " bytes)\n";
}

// Картка дашборду — з заглушками сервісів.
copy(SG_PKG . '/css/security-guard.css', $outDir . '/security-guard.css');
copy(SG_PKG . '/js/security-guard.js', $outDir . '/security-guard.js');
file_put_contents($outDir . '/index.html', '<!DOCTYPE html><meta charset="utf-8"><ul>' . implode('', $index) . '</ul>');

if (getenv('SG_DUMP_STRINGS')) {
    file_put_contents(getenv('SG_DUMP_STRINGS'), implode("\n", array_keys($GLOBALS['sg_used_strings'])));
}

exit($failures ? 1 : 0);
