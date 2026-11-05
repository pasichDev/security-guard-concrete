<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use PasichDev\SecurityGuard\Block\Escalation;
use PasichDev\SecurityGuard\Config\Settings;
use PasichDev\SecurityGuard\State\FileCounterStore;
use PasichDev\SecurityGuard\State\FileStateCache;
use PasichDev\SecurityGuard\State\StateDir;

// --- Ескалація ---
$steps = Escalation::steps(Settings::DEFAULTS['escalation'], Settings::DEFAULTS['block_duration']);
T::eq([3600, 86400, 604800, 2592000], $steps, 'кроки за замовчуванням');
T::eq([600, 86400, 604800, 2592000], Escalation::steps([3600, 86400, 604800, 2592000], 600), 'block_duration замінює перший крок');
T::eq([3600], Escalation::steps([], 0), 'порожні кроки → 1 год');
$now = 1_800_000_000;
T::eq(['level' => 0, 'duration' => 3600], Escalation::next($steps, null, $now), 'перший бан — 1 год');
$prev = ['escalationLevel' => 0, 'blockedUntil' => $now - 100, 'permanent' => 0];
T::eq(['level' => 1, 'duration' => 86400], Escalation::next($steps, $prev, $now), 'повтор після недавнього бану — 24 год');
$prev = ['escalationLevel' => 1, 'blockedUntil' => $now - 86400, 'permanent' => 0];
T::eq(['level' => 2, 'duration' => 604800], Escalation::next($steps, $prev, $now), 'третій — 7 днів');
$prev = ['escalationLevel' => 2, 'blockedUntil' => $now - 10, 'permanent' => 0];
T::eq(['level' => 3, 'duration' => 2592000], Escalation::next($steps, $prev, $now), 'четвертий — 30 днів');
$prev = ['escalationLevel' => 3, 'blockedUntil' => $now - 10, 'permanent' => 0];
T::eq(['level' => 3, 'duration' => 2592000], Escalation::next($steps, $prev, $now), 'далі — не вище останнього кроку');
$prev = ['escalationLevel' => 3, 'blockedUntil' => $now - Escalation::DECAY - 1, 'permanent' => 0];
T::eq(['level' => 0, 'duration' => 3600], Escalation::next($steps, $prev, $now), 'давній бан (> 30 днів) — знову з 1 год');
$prev = ['escalationLevel' => 0, 'blockedUntil' => $now + 500, 'permanent' => 0];
T::eq(['level' => 1, 'duration' => 86400], Escalation::next($steps, $prev, $now), 'порушення під час чинного бану — ескалація');
T::eq([$now + 3600, false], Escalation::until(3600, null, $now), 'until без попереднього');
T::eq([$now + 864000, false], Escalation::until(3600, ['blockedUntil' => $now + 864000, 'permanent' => 0], $now), 'не скорочуємо довший чинний бан');
T::eq([0, true], Escalation::until(0, null, $now), '0 — назавжди');
T::eq([0, true], Escalation::until(3600, ['blockedUntil' => 0, 'permanent' => 1], $now), 'назавжди лишається назавжди');

// --- Файлові лічильники ---
$dir = sg_temp_dir('counters');
$clock = $now;
$store = new FileCounterStore($dir . '/counters', str_repeat('a', 64), static function () use (&$clock): int {
    return $clock;
});
T::eq(1, $store->increment('rl:1.2.3.4', 1, 60), 'перший increment');
T::eq(2, $store->increment('rl:1.2.3.4', 1, 60), 'другий increment');
T::eq(7, $store->increment('rl:1.2.3.4', 5, 60), 'increment на 5');
T::eq(1, $store->increment('rl:5.6.7.8', 1, 60), 'інший ключ — окремо');
T::eq(7, $store->get('rl:1.2.3.4'), 'get');
$clock += 59;
T::eq(8, $store->increment('rl:1.2.3.4', 1, 60), 'вікно фіксоване: TTL не продовжується');
$clock += 1;
T::eq(null, $store->get('rl:1.2.3.4'), 'прострочено');
T::eq(1, $store->increment('rl:1.2.3.4', 1, 60), 'після вікна — з нуля');
T::ok($store->add('ev:x', 1, 30), 'add уперше');
T::ok(!$store->add('ev:x', 1, 30), 'add удруге в межах TTL — ні');
$clock += 31;
T::ok($store->add('ev:x', 1, 30), 'add після TTL — так');
$store->set('se:ip', ['A', 'B'], 100);
T::eq(['A', 'B'], $store->get('se:ip'), 'масив значень');
$store->delete('se:ip');
T::eq(null, $store->get('se:ip'), 'delete');
$files = glob($dir . '/counters/*.cnt');
T::ok(count($files) >= 3, 'файли створено');
$joined = implode('', array_map('basename', $files));
T::ok(strpos($joined, '1.2.3.4') === false && strpos($joined, 'rl') === false, 'імена файлів не розкривають ключ');
foreach ($files as $f) {
    T::ok(strpos((string) file_get_contents($f), '1.2.3.4') === false, 'вміст файла не містить IP');
}
// Прибирання за mtime.
$clock += 1000;
$removed = $store->purgeExpired();
T::ok($removed >= 3, 'purgeExpired видаляє прострочені (' . $removed . ')');
T::eq([], glob($dir . '/counters/*.cnt'), 'після прибирання порожньо');
// Конкурентні increment у кількох процесах (flock).
if (function_exists('pcntl_fork')) {
    $real = new FileCounterStore($dir . '/race', str_repeat('b', 64));
    $pids = [];
    for ($p = 0; $p < 4; $p++) {
        $pid = pcntl_fork();
        if ($pid === 0) {
            for ($i = 0; $i < 100; $i++) {
                $real->increment('race', 1, 600);
            }
            exit(0);
        }
        $pids[] = $pid;
    }
    foreach ($pids as $pid) {
        pcntl_waitpid($pid, $status);
    }
    T::eq(400, $real->get('race'), '4 процеси × 100 increment = 400 (flock)');
} else {
    echo "  (pcntl недоступний — тест гонки пропущено)\n";
}

// --- Файл стану ---
$sdir = sg_temp_dir('state') . '/security_guard';
$cache = new FileStateCache(null, $sdir);
T::eq(Settings::MODE_MONITOR, $cache->load()['settings']['mode'], 'немає файла й нема застосунку → за замовчуванням monitor');
$cache->write([
    'settings' => ['mode' => Settings::MODE_ENFORCE] + Settings::DEFAULTS,
    'blocks' => ['1.2.3.4' => ['until' => 0, 'reason' => "QUOTE'\"\\", 'category' => 'honeypot']],
    'whitelist' => [['range' => '10.0.0.0/8', 'expires' => 0]],
]);
$fresh = new FileStateCache(null, $sdir);
$loaded = $fresh->load();
T::eq(Settings::MODE_ENFORCE, $loaded['settings']['mode'], 'стан перечитано');
T::eq("QUOTE'\"\\", $loaded['blocks']['1.2.3.4']['reason'], 'var_export екранує лапки');
T::ok($loaded['builtAt'] > 0, 'builtAt');
$php = (string) file_get_contents($sdir . '/state.php');
T::ok(strpos($php, "defined('C5_EXECUTE') or die") !== false, 'state.php має захист C5_EXECUTE');
T::ok(is_file($sdir . '/.htaccess') && is_file($sdir . '/index.html'), '.htaccess та index.html створено');
T::eq([], glob($sdir . '/*.tmp'), 'тимчасових файлів не лишилось');
// Пошкоджений файл → за замовчуванням, без винятку.
file_put_contents($sdir . '/state.php', "<?php return 'broken';");
T::eq(Settings::MODE_MONITOR, (new FileStateCache(null, $sdir))->load()['settings']['mode'], 'пошкоджений стан → monitor');
// Сіль.
$salt1 = StateDir::salt($sdir);
$salt2 = StateDir::salt($sdir);
T::ok(strlen($salt1) === 64 && $salt1 === $salt2, 'сіль стабільна');
$cache->clear();
T::ok(!is_dir($sdir), 'clear() прибирає теку');

T::done('state_test');
