<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

/*
 * Заміри часу й пам'яті імпорту на копії реальних логів (каталог з access-logs/ і logs/):
 *   docker run --rm -v "$PWD":/s -v /шлях/до/логів:/logs:ro -w /s php:8.2-cli \
 *     php tests/logs/bench-ingest.php /logs example.org
 * Логи копіюються в тимчасовий каталог; сценарії: повна перебудова, ротація cPanel
 * (живий лог дописано в місячний .gz і обрізано), щогодинний запуск після ротації.
 */

declare(strict_types=1);

use PasichDev\SecurityGuard\Logs\IngestEngine;
use PasichDev\SecurityGuard\Logs\IpMatcher;
use PasichDev\SecurityGuard\Logs\LogParser;
use PasichDev\SecurityGuard\Logs\RuleSetClassifier;
use PasichDev\SecurityGuard\Logs\SourceLocator;
use PasichDev\SecurityGuard\Rules\RuleSet;
use PasichDev\SecurityGuard\Tests\Logs\MemoryCursors;
use PasichDev\SecurityGuard\Tests\Logs\MemoryDays;
use PasichDev\SecurityGuard\Tests\Logs\MemoryPending;

require __DIR__ . '/bootstrap.php';

$root = $argv[1] ?? '';
$domain = $argv[2] ?? '';
if ($root === '' || !is_dir($root) || $domain === '') {
    echo "usage: bench-ingest.php <log-root> <domain>\n";
    exit(0);
}
$work = sys_get_temp_dir() . '/sg-bench-' . getmypid();
foreach (['access-logs', 'logs'] as $d) {
    @mkdir("$work/$d", 0777, true);
    foreach (glob("$root/$d/*") ?: [] as $f) {
        copy($f, "$work/$d/" . basename($f));
    }
}
$tz = new DateTimeZone(date_default_timezone_get() === 'UTC' ? 'Europe/Kyiv' : date_default_timezone_get());
$state = ['c' => new MemoryCursors(), 'p' => new MemoryPending(), 'd' => new MemoryDays()];
$extra = [];
if (class_exists(\PasichDev\SecurityGuard\Tests\Logs\MemoryIndex::class)) {
    $extra[] = new \PasichDev\SecurityGuard\Tests\Logs\MemoryIndex();
}
$engine = new IngestEngine($tz, static function () {
    return new RuleSetClassifier(new RuleSet());
}, new IpMatcher(''), $state['c'], $state['p'], $state['d'], null, null, ...$extra);
$sources = static function () use ($work, $domain): array {
    clearstatcache();

    return (new SourceLocator($work, $domain))->discover();
};
$measure = static function (string $label, callable $fn): void {
    gc_collect_cycles();
    if (function_exists('memory_reset_peak_usage')) {
        memory_reset_peak_usage();
    }
    $t = microtime(true);
    $r = $fn();
    printf("%-34s %6.2f s  peak %5.1f MB  lines=%d days=%d dedup=%d\n", $label, microtime(true) - $t,
        memory_get_peak_usage() / 1048576, $r['lines'], count($r['days']), $r['deduplicated']);
};

$measure('full rebuild', static function () use ($engine, $sources) {
    return $engine->run($sources(), ['rebuild' => true]);
});

// Ротація: рядки живого ssl-логу дописуються в останній місячний ssl-архів, живий лог обрізається.
$live = "$work/access-logs/$domain-ssl_log";
$archives = glob("$work/logs/$domain-ssl_log-*_NGINX.gz") ?: [];
usort($archives, static function ($a, $b) {
    return filemtime($a) <=> filemtime($b);
});
$gz = end($archives);
$lines = file($live, FILE_IGNORE_NEW_LINES) ?: [];
file_put_contents($gz, gzencode(implode("\n", $lines) . "\n"), FILE_APPEND);
$last = $lines ? $lines[count($lines) - 1] : '';
file_put_contents($live, '');
$measure('after rotation', static function () use ($engine, $sources) {
    return $engine->run($sources());
});

// Щогодинний запуск: у живий лог дописано 300 рядків того самого дня.
$ts = LogParser::timestamp($last) ?? time();
$add = [];
for ($i = 1; $i <= 300; ++$i) {
    $add[] = preg_replace('/\[[^\]]+\]/', '[' . date('d/M/Y:H:i:s O', $ts + $i) . ']', $last, 1);
}
file_put_contents($live, implode("\n", $add) . "\n", FILE_APPEND);
$measure('hourly run after rotation', static function () use ($engine, $sources) {
    return $engine->run($sources());
});
file_put_contents($live, implode("\n", $add) . "\n", FILE_APPEND);
$measure('next hourly run', static function () use ($engine, $sources) {
    return $engine->run($sources());
});
$measure('no new lines', static function () use ($engine, $sources) {
    return $engine->run($sources());
});

array_map('unlink', array_merge(glob("$work/*/*") ?: []));
@rmdir("$work/access-logs");
@rmdir("$work/logs");
@rmdir($work);
