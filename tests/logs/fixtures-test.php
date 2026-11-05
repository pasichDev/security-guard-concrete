<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

/*
 * Тести розбору логів на синтетичних даних (без Concrete):
 *   docker run --rm -v "$PWD":/s -w /s php:8.2-cli php tests/logs/fixtures-test.php
 */

declare(strict_types=1);

use PasichDev\SecurityGuard\Logs\CrawlerVerifier;
use PasichDev\SecurityGuard\Logs\DayAggregator;
use PasichDev\SecurityGuard\Logs\IngestEngine;
use PasichDev\SecurityGuard\Logs\IpMatcher;
use PasichDev\SecurityGuard\Logs\LogParser;
use PasichDev\SecurityGuard\Logs\SourceLocator;
use PasichDev\SecurityGuard\Logs\CardinalitySketch;
use PasichDev\SecurityGuard\Logs\ReportClassifier;
use PasichDev\SecurityGuard\Stats\RangeSummarizer;
use PasichDev\SecurityGuard\Tests\Logs\FakeClassifier;
use PasichDev\SecurityGuard\Tests\Logs\MemoryCursors;
use PasichDev\SecurityGuard\Tests\Logs\MemoryDays;
use PasichDev\SecurityGuard\Tests\Logs\MemoryPending;
use PasichDev\SecurityGuard\Tests\Logs\T;

require __DIR__ . '/bootstrap.php';

// ---------- Парсер
$p = LogParser::parse('1.2.3.4 - - [31/Oct/2026:22:18:03 +0200] "GET /a/b?q=1 HTTP/1.1" 200 1234 "http://r/" "UA \"quoted\""');
T::eq('1.2.3.4', $p['ip'], 'parse ip');
T::eq(gmmktime(20, 18, 3, 10, 31, 2026), $p['ts'], 'parse ts with offset');
T::eq('GET', $p['method'], 'parse method');
T::eq('/a/b?q=1', $p['uri'], 'parse uri');
T::eq('/a/b', $p['path'], 'parse path');
T::eq(200, $p['status'], 'parse status');
T::eq(1234, $p['bytes'], 'parse bytes');
T::eq('UA "quoted"', $p['ua'], 'parse escaped UA');
$p = LogParser::parse('35.205.215.15 - - [02/Nov/2026:11:26:05 +0200] "-" 400 150 "-" "-"');
T::ok($p !== null && $p['status'] === 400 && $p['uri'] === '' && $p['method'] === '', 'empty request still a request');
$p = LogParser::parse('146.70.40.68 - - [01/Nov/2026:10:29:17 +0200] "" 400 0 "-" "-"');
T::ok($p !== null && $p['status'] === 400, 'empty quoted request');
$p = LogParser::parse('1.1.1.1 - - [04/Nov/2026:22:38:01 +0200] "GET http://example.org/x/y.jpg?z HTTP/1.1" 301 306 "-" "-"');
T::eq('/x/y.jpg', $p['path'], 'absolute URI path');
T::eq(null, LogParser::parse('garbage'), 'garbage rejected');
T::eq(null, LogParser::parse('1.2.3.4 - - [99/Foo/2026:10:00:00 +0300] "GET / HTTP/1.1" 200 1'), 'bad date rejected');
T::eq(gmmktime(5, 0, 0, 1, 1, 2026), LogParser::timestamp('9.9.9.9 - - [31/Dec/2025:23:30:00 -0530] "GET / HTTP/1.1" 200 1 "-" "-"'), 'negative half-hour offset');
T::eq('2026-10-31', LogParser::literalDay('1.2.3.4 - - [31/Oct/2026:22:18:03 +0200] "GET / HTTP/1.1" 200 1'), 'literal day');
$p = LogParser::parse('1.2.3.4 - - [31/Oct/2026:22:18:03 +0200] "GET / HTTP/1.1" 200 -');
T::ok($p !== null && $p['bytes'] === 0 && !$p['partial'], 'common log format, bytes "-"');

// ---------- Класифікатор звіту
$rc = new ReportClassifier();
T::ok($rc->classify('GET', '/wp-login.php', '') !== null, 'report: wp-');
T::ok($rc->classify('GET', '/x/UP.php', '') !== null, 'report: /up.php case-insensitive');
T::ok($rc->classify('GET', '/index.php?option=com_content&view=article', '') !== null, 'report: option=com_ (as in audit)');
T::eq(null, $rc->classify('GET', '/upload.php', ''), 'report: /upload.php is not /up.php');
T::ok(ReportClassifier::isLoginFailure('POST', '/index.php?option=com_gridbox&task=account.socialLogin', 200), 'report login: socialLogin 200');
T::ok(!ReportClassifier::isLoginFailure('POST', '/login/authenticate/concrete', 302), 'report login: 302 is success');

// ---------- IpMatcher
$m = new IpMatcher("198.51.100.23, 10.9.9.0/24\n203.0.113.\n2001:db8::/32");
T::ok($m->matches('198.51.100.23'), 'ip exact');
T::ok($m->matches('10.9.9.9') && !$m->matches('10.9.10.1'), 'ip cidr v4');
T::ok($m->matches('203.0.113.77') && !$m->matches('203.0.11.1'), 'ip prefix');
T::ok($m->matches('2001:db8::66') && !$m->matches('2001:db9::1'), 'ip cidr v6');

// ---------- Sketch
$s = new CardinalitySketch();
for ($i = 0; $i < 5000; ++$i) {
    $s->add('10.0.' . intdiv($i, 256) . '.' . ($i % 256));
}
$est = (new CardinalitySketch($s->serialize()))->count();
T::ok(abs($est - 5000) < 300, "HLL estimate within 6% ($est)");

// ---------- Потоки
T::eq('example.org-ssl_log', SourceLocator::streamOf('/h/logs/example.org-ssl_log-Oct-2026_NGINX.gz'), 'stream of nginx archive');
T::eq('example.org-ssl_log', SourceLocator::streamOf('/h/access-logs/example.org-ssl_log'), 'stream of live ssl');
T::eq('example.org', SourceLocator::streamOf('/h/logs/example.org-Oct-2026.gz'), 'stream of http archive');
T::eq('example.org', SourceLocator::normalizeDomain('https://www.Example.org/'), 'normalize domain');
$tmpHome = sys_get_temp_dir() . '/sg-home-' . getmypid();
@mkdir($tmpHome . '/public_html', 0777, true);
@mkdir($tmpHome . '/access-logs');
@mkdir($tmpHome . '/public_html/logs'); // стара тека logs/ у корені сайту (лишилась від Joomla)
T::eq($tmpHome, SourceLocator::detectHome($tmpHome . '/public_html'), 'home from site root (access-logs wins over docroot logs/)');
$tmpHome2 = sys_get_temp_dir() . '/sg-home2-' . getmypid();
@mkdir($tmpHome2 . '/public_html/logs', 0777, true);
@mkdir($tmpHome2 . '/logs');
touch($tmpHome2 . '/logs/example.org-Oct-2026.gz');
T::eq($tmpHome2, SourceLocator::detectHome($tmpHome2 . '/public_html', 'example.org'), 'home with only logs/ archives, empty docroot logs/ ignored');

// ---------- Пошукові краулери: UA + опублікований діапазон IP
$cv = new CrawlerVerifier(['203.0.113.250' => 'YandexBot']);
$gua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
T::eq('Googlebot', $cv->verify('66.249.66.1', $gua), 'Googlebot from published range verified');
T::eq(null, $cv->verify('198.51.100.77', $gua), 'Googlebot UA from cloud IP is fake');
T::eq(null, $cv->verify('66.249.66.1', 'curl/8'), 'Google IP without bot UA is not a crawler');
T::eq('YandexBot', $cv->verify('203.0.113.250', 'Mozilla/5.0 (compatible; YandexBot/3.0)'), 'rDNS-cache verified IP');
T::eq('Baiduspider', $cv->verify('220.181.108.10', 'Mozilla/5.0 (compatible; Baiduspider/2.0)'), 'Baidu heuristic range');
T::eq('Bingbot', $cv->verify('157.55.39.1', 'Mozilla/5.0 (compatible; bingbot/2.0)'), 'Bingbot range');
$agg = new DayAggregator(new DateTimeZone('UTC'), new FakeClassifier(), null, null, $cv);
foreach (['66.249.66.1', '66.249.66.1', '198.51.100.77'] as $ip) {
    $agg->add(LogParser::parse($ip . ' - - [01/Oct/2026:10:00:00 +0000] "GET /evil/old-joomla HTTP/1.1" 404 10 "-" "' . $gua . '"'));
}
$row = $agg->finish()['2026-10-01'];
T::eq(1, $row['attackRequests'], 'verified crawler hits are not attacks');
T::eq(['198.51.100.77'], $row['breakdown']['attackIpList'], 'only fake bot is an attacker');
T::eq(2, $row['breakdown']['botAttackLike'], 'crawler attack-like hits counted separately');
T::eq(3, $row['botRequests'], 'all three counted as bot requests');
T::eq('Googlebot', $row['breakdown']['topIps'][0]['bot'], 'topIps bot field for crawler');
T::eq(null, $row['breakdown']['topAttackIps'][0]['bot'], 'topAttackIps bot field null for fake');
T::ok(isset($row['breakdown']['bots']['Googlebot (unverified)']), 'fake bot labelled unverified');
T::eq(0, $row['breakdown']['report']['attackRequests'], 'report mode has its own regex (no match here)');
$sum = RangeSummarizer::summarize([$row + ['day' => '2026-10-01']]);
T::eq('Googlebot', $sum['breakdown']['topIps'][0]['bot'], 'summary keeps bot field');

// ---------- Інтеграційні сценарії на синтетичних логах
$work = sys_get_temp_dir() . '/sg-fixtures-' . getmypid();
passthru_free_generate($work);
$expected = json_decode((string) file_get_contents($work . '/expected.json'), true);
$home = $work . '/home';
$tz = new DateTimeZone('Europe/Kyiv');
$now = (new DateTimeImmutable('2026-10-05 09:00:00', $tz))->getTimestamp();

$make = static function () use ($tz): array {
    $c = new MemoryCursors();
    $p = new MemoryPending();
    $d = new MemoryDays();
    $e = new IngestEngine($tz, static function () {
        return new FakeClassifier();
    }, new IpMatcher('10.9.9.9'), $c, $p, $d);

    return [$e, $c, $p, $d];
};
$discover = static function () use ($home): array {
    return (new SourceLocator($home, 'example.org'))->discover();
};
$check = static function (MemoryDays $d, array $exp, string $label, array $extraTotal = [], bool $overlapInFiles = true): void {
    foreach ($exp as $day => $e) {
        $row = $d->rows[$day] ?? null;
        if ($row === null) {
            T::ok(false, "$label: day $day missing");
            continue;
        }
        T::eq($e['total'] + ($extraTotal[$day] ?? 0), $row['totalRequests'], "$label: $day total");
        T::eq($e['fakeAttacks'], $row['attackRequests'], "$label: $day attacks");
        // «Як у звіті» — усі рядки всіх файлів; поки перекриття живого логу з архівом є у файлах, воно рахується двічі.
        T::eq($overlapInFiles ? $e['reportAttacksRaw'] : $e['reportAttacks'], $row['breakdown']['report']['attackRequests'], "$label: $day report attacks (all files)");
        T::eq(($overlapInFiles ? $e['totalRaw'] : $e['total']) + ($extraTotal[$day] ?? 0), $row['breakdown']['report']['totalRequests'], "$label: $day report total (all files)");
        T::eq($e['blocked403'], $row['blocked403'], "$label: $day 403");
        T::eq($e['overload508'], $row['overload508'], "$label: $day 508");
        T::eq($e['loginFailed'], $row['loginFailed'], "$label: $day login failed");
        T::eq($e['errors404'], $row['errors404'], "$label: $day 404");
        T::eq($e['excluded'], $row['breakdown']['excluded'], "$label: $day excluded");
    }
};

// 1. Перший запуск: перекриття архіву й живого логу не рахується двічі.
[$engine, $cursors, $pending, $days] = $make();
$sources = $discover();
T::eq(3, count($sources), 'three sources discovered');
$r = $engine->run($sources, ['now' => $now]);
T::ok($r['finished'], 'run finished');
T::eq([], $r['errors'], 'no errors');
T::eq($expected['overlapLines'], $r['deduplicated'], 'overlap lines deduplicated exactly');
T::eq(5, $r['malformed'], 'malformed lines skipped (blank, garbage, binary, truncated, bad date)');
$check($days, $expected['days'], 'initial');
T::ok(isset($days->rows['2026-10-01']) && isset($days->rows['2026-10-02']), 'boundary days present');

// 2. Повторний запуск — нічого нового.
$w = $days->writes;
$r = $engine->run($discover(), ['now' => $now]);
T::eq(0, $r['lines'], 'rerun reads nothing');
T::eq($w, $days->writes, 'rerun writes nothing');

// 3. Дописали недописаний рядок — лише він новий.
file_put_contents($home . '/access-logs/example.org-ssl_log', "\n", FILE_APPEND);
clearstatcache();
$r = $engine->run($discover(), ['now' => $now]);
T::eq(1, $r['lines'], 'completed partial line read once');
$check($days, $expected['days'], 'after partial', ['2026-10-04' => 1]);

// 4. Ротація cPanel: нові рядки живого логу дописано в архів окремим gzip-членом, живий лог обрізано
//    і почато знову рядками за 05.10.
$live = $home . '/access-logs/example.org-ssl_log';
$gz = $home . '/logs/example.org-ssl_log-Oct-2026.gz';
$cutTs = (new DateTimeImmutable('2026-10-03 22:00:00', $tz))->getTimestamp();
$moved = [];
foreach (file($live, FILE_IGNORE_NEW_LINES) as $line) {
    $ts = LogParser::timestamp($line);
    if ($ts !== null && $ts >= $cutTs) {
        $moved[] = $line;
    }
}
file_put_contents($gz, gzencode(implode("\n", $moved) . "\n"), FILE_APPEND);
$oct5 = [];
$t5 = (new DateTimeImmutable('2026-10-05 08:00:00', $tz))->getTimestamp();
for ($i = 0; $i < 10; ++$i) {
    $oct5[] = '203.0.113.5 - - [' . gmdate('d/M/Y:H:i:s', $t5 + $i + 3 * 3600) . ' +0300] "GET /new HTTP/2.0" 200 10 "-" "Mozilla/5.0"';
}
file_put_contents($live, implode("\n", $oct5) . "\n");
clearstatcache();
$r = $engine->run($discover(), ['now' => $now]);
T::ok($r['finished'], 'after rotation finished');
T::eq(count($moved) + 10, $r['lines'], 'rotation: only appended archive lines + new live lines read');
T::ok(in_array('2026-10-04', $r['days'], true) && in_array('2026-10-05', $r['days'], true), 'rotation recomputed touched days');
$check($days, $expected['days'], 'after rotation', ['2026-10-04' => 1], false);
T::eq(10, $days->rows['2026-10-05']['totalRequests'], 'new day after rotation');

// 5. Перебудова з нуля дає те саме.
$snap = $days->rows;
$r = $engine->run($discover(), ['now' => $now, 'rebuild' => true]);
$same = true;
foreach ($snap as $day => $row) {
    foreach (RangeSummarizer::COLUMNS as $col) {
        $same = $same && $days->rows[$day][$col] === $row[$col];
    }
}
T::ok($same, 'rebuild identical');

// 6. Обрив за часом: днів не пише, курсор і черга зберігаються; наступний запуск добирає.
passthru_free_generate($work);
clearstatcache();
[$engine, $cursors, $pending, $days] = $make();
$r = $engine->run($discover(), ['now' => $now, 'deadlineAt' => 0.0]);
T::ok(!$r['finished'], 'cut run not finished');
T::eq([], $r['days'], 'cut run writes no days');
T::ok($pending->days !== [], 'cut run keeps pending days');
$firstPath = array_key_first($cursors->rows);
T::ok(!$cursors->rows[$firstPath]['completed'] && $cursors->rows[$firstPath]['position'] > 0, 'cut cursor saved mid-file');
$guard = 0;
do {
    $r = $engine->run($discover(), ['now' => $now]);
} while (!$r['finished'] && ++$guard < 5);
T::ok($r['finished'], 'resumed run finished');
T::eq([], $pending->days, 'pending drained');
$check($days, $expected['days'], 'after resume');

// 7. Обрив у проході B: нових рядків немає, черга з кількох днів, час уже вичерпано —
//    нічого не пишеться, черга лишається; наступний запуск її добирає з тими самими цифрами.
[$engine, $cursors, $pending, $days] = $make();
$engine->run($discover(), ['now' => $now]);
$all = $days->rows;
T::eq(count($expected['days']), count($all), 'all days written');
$pending->days = ['2026-10-02', '2026-10-03'];
$w = $days->writes;
$r = $engine->run($discover(), ['now' => $now, 'deadlineAt' => 0.0]);
T::ok(!$r['finished'], 'pass B cut: not finished');
T::eq($w, $days->writes, 'pass B cut: nothing written');
T::eq(['2026-10-02', '2026-10-03'], $pending->days, 'pass B cut: pending kept');
$r = $engine->run($discover(), ['now' => $now]);
T::ok($r['finished'], 'pass B resumed');
T::eq(['2026-10-02', '2026-10-03'], $r['days'], 'pass B resumed: pending days recomputed');
T::eq([], $pending->days, 'pass B resumed: pending drained');
T::eq($all, $days->rows, 'pass B resumed: rows identical');

// 8. --days=2: лише останні два дні.
[$engine, $cursors, $pending, $days] = $make();
$r = $engine->run($discover(), ['now' => (new DateTimeImmutable('2026-10-04 12:00:00', $tz))->getTimestamp(), 'days' => 2]);
T::eq(['2026-10-03', '2026-10-04'], array_keys($days->rows), 'days window');

// 9. Підсумок діапазону: точне об'єднання атакуючих IP.
$sum = RangeSummarizer::summarize(array_values($all));
T::eq(4, $sum['attackIps'], 'range attack IPs union (4 attackers)');
T::eq(array_sum(array_column($expected['days'], 'total')), $sum['totalRequests'], 'range total');
T::ok(!$sum['attackIpsApprox'], 'attack IPs exact');
T::ok($sum['uniqueIps'] > 50 && $sum['uniqueIps'] < 80, 'range unique IPs estimate plausible (' . $sum['uniqueIps'] . ')');
T::eq(24, count($sum['breakdown']['hours']), 'hours merged');

exit(T::done());

/** Створює фікстури в $dir (через include, без exec). */
function passthru_free_generate(string $dir): void
{
    $argvBackup = $GLOBALS['argv'] ?? [];
    $GLOBALS['argv'] = ['fixtures-gen.php', $dir];
    $argv = $GLOBALS['argv'];
    ob_start();
    (static function () use ($argv): void {
        include __DIR__ . '/fixtures-gen.php';
    })();
    ob_end_clean();
    $GLOBALS['argv'] = $argvBackup;
}
