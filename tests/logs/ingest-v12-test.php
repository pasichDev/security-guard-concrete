<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

/*
 * Покажчик днів, ліміти часу й пам'яті, --days, дедуплікація Apache/nginx, розбір рядків:
 *   docker run --rm -v "$PWD":/s -w /s php:8.2-cli php tests/logs/ingest-v12-test.php
 */

declare(strict_types=1);

use PasichDev\SecurityGuard\Logs\CardinalitySketch;
use PasichDev\SecurityGuard\Logs\DayAggregator;
use PasichDev\SecurityGuard\Logs\IngestEngine;
use PasichDev\SecurityGuard\Logs\IpMatcher;
use PasichDev\SecurityGuard\Logs\LogIngest;
use PasichDev\SecurityGuard\Logs\LogParser;
use PasichDev\SecurityGuard\Logs\SourceLocator;
use PasichDev\SecurityGuard\Stats\RangeSummarizer;
use PasichDev\SecurityGuard\Tests\Logs\FakeClassifier;
use PasichDev\SecurityGuard\Tests\Logs\MemoryCursors;
use PasichDev\SecurityGuard\Tests\Logs\MemoryDays;
use PasichDev\SecurityGuard\Tests\Logs\MemoryIndex;
use PasichDev\SecurityGuard\Tests\Logs\MemoryPending;
use PasichDev\SecurityGuard\Tests\Logs\T;

require __DIR__ . '/bootstrap.php';

// ---------- Розбір рядків
$p = LogParser::parse('198.51.100.1 - - [01/Oct/2026:10:00:00 +0000] "GET /a\"b?x=\"1\" HTTP/1.1" 200 5 "https://example.org/\"r\"" "UA"');
T::eq('/a"b?x="1"', $p['uri'], 'escaped quotes unescaped in URI');
T::eq('/a\"b?x=\"1\"', $p['rawUri'], 'raw URI kept as logged');
T::eq('https://example.org/"r"', $p['referer'], 'escaped quotes unescaped in referer');
T::eq(null, LogParser::parse('198.51.100.1 - - [31/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "-"'), '31 Feb rejected');
T::eq(null, LogParser::parse('198.51.100.1 - - [30/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "-"'), '30 Feb rejected');
T::ok(LogParser::parse('198.51.100.1 - - [29/Feb/2028:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "-"') !== null, '29 Feb of a leap year accepted');
T::eq(null, LogParser::parse('198.51.100.1 - - [01/Oct/2026:24:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "-"'), 'hour 24 rejected');
T::eq(null, LogParser::parse('198.51.100.1 - - [01/Oct/2026:10:61:00 +0000] "GET / HTTP/1.1" 200 5 "-" "-"'), 'minute 61 rejected');
$p = LogParser::parse('198.51.100.1 - John Q Doe [01/Oct/2026:10:00:00 +0000] "POST /login/authenticate/concrete HTTP/1.1" 200 5 "-" "UA x"');
T::ok($p !== null && !$p['partial'] && $p['method'] === 'POST' && $p['status'] === 200 && $p['ua'] === 'UA x', 'authuser with spaces parsed');

// ---------- Обмеження пам'яті на мапи IP
$agg = new DayAggregator(new DateTimeZone('UTC'), new FakeClassifier());
$n = DayAggregator::IP_MAP_MAX + 2000;
for ($i = 0; $i < $n; ++$i) {
    $agg->add(['ip' => '10.' . ($i >> 16) . '.' . (($i >> 8) & 255) . '.' . ($i & 255), 'ts' => 1790000000, 'method' => 'GET', 'uri' => '/', 'rawUri' => '/',
        'path' => '/', 'status' => 200, 'bytes' => 1, 'referer' => '', 'ua' => '', 'partial' => false]);
}
$row = current($agg->finish());
T::ok($row['breakdown']['ipMapsCapped'], 'IP map capped above IP_MAP_MAX');
T::ok(abs($row['uniqueIps'] - $n) < $n * 0.05, "uniqueIps from HLL after cap ({$row['uniqueIps']} ~ $n)");
T::eq($n, $row['totalRequests'], 'totals unaffected by the cap');

// ---------- Слабкі збіги правил не рахуються атаками
$weakCls = new class implements \PasichDev\SecurityGuard\Logs\AttackClassifierInterface {
    public function classify(string $method, string $uri, string $userAgent): ?array
    {
        if (strpos($uri, '/strong') === 0) {
            return ['rule' => 'S', 'category' => 'injection', 'strength' => 'strong'];
        }

        return strpos($uri, '/weak') === 0 ? ['rule' => 'W', 'category' => 'xss', 'strength' => 'weak'] : null;
    }
};
$agg = new DayAggregator(new DateTimeZone('UTC'), $weakCls);
foreach (['/strong', '/weak', '/weak', '/wp-login.php'] as $u) {
    $agg->add(['ip' => '198.51.100.7', 'ts' => 1790000000, 'method' => 'GET', 'uri' => $u, 'rawUri' => $u, 'path' => $u, 'status' => 200,
        'bytes' => 1, 'referer' => '', 'ua' => '', 'partial' => false]);
}
$row = current($agg->finish());
T::eq(1, $row['attackRequests'], 'only strong hits are attacks');
T::eq(2, $row['breakdown']['weakAttackLike'], 'weak hits counted separately');
T::eq(1, $row['breakdown']['report']['attackRequests'], 'report-compat unaffected');

// ---------- hostWafIps за діапазон: обрізані списки → HLL
$mkDay = static function (string $day, int $from, int $count): array {
    $sk = new CardinalitySketch();
    $list = [];
    for ($i = $from; $i < $from + $count; ++$i) {
        $sk->add('192.0.2.' . $i);
        if (count($list) < 3) {
            $list[] = '192.0.2.' . $i;
        }
    }

    return ['day' => $day, 'hostWafBlocked' => $count, 'hostWafIps' => $count, 'breakdown' => ['hostWaf' => [
        'ipList' => $list, 'ipListTruncated' => true, 'ipSketch' => $sk->serialize(), 'categories' => [], 'topRules' => [], 'topIps' => [], 'topUrls' => [],
    ]]];
};
$s = RangeSummarizer::summarize([$mkDay('2026-10-01', 0, 200), $mkDay('2026-10-02', 100, 150)]);
T::ok($s['hostWafIps'] >= 240 && $s['hostWafIps'] <= 260, "hostWafIps from HLL union ({$s['hostWafIps']} ~ 250)");
T::ok($s['hostWafIpsApprox'], 'marked approximate');

// ---------- Відбиток списку виключень
T::eq(LogIngest::excludeFingerprint(new IpMatcher("198.51.100.1\n10.0.0.0/8")), LogIngest::excludeFingerprint(new IpMatcher('10.0.0.0/8, 198.51.100.1 198.51.100.1')), 'exclude fingerprint ignores order and duplicates');
T::ok(LogIngest::excludeFingerprint(new IpMatcher('198.51.100.1')) !== LogIngest::excludeFingerprint(new IpMatcher('')), 'exclude fingerprint changes with the list');

// ---------- Сценарії на синтетичних логах
$work = sys_get_temp_dir() . '/sg-v12-' . getmypid();
$GLOBALS['argv'] = ['fixtures-gen.php', $work];
(static function (): void {
    $argv = $GLOBALS['argv'];
    ob_start();
    include __DIR__ . '/fixtures-gen.php';
    ob_end_clean();
})();
$home = $work . '/home';
$tz = new DateTimeZone('Europe/Kyiv');
$now = (new DateTimeImmutable('2026-10-05 09:00:00', $tz))->getTimestamp();
$src = static function () use ($home): array {
    clearstatcache();

    return (new SourceLocator($home, 'example.org'))->discover();
};
$make = static function (bool $withIndex = true) use ($tz): array {
    $c = new MemoryCursors();
    $p = new MemoryPending();
    $d = new MemoryDays();
    $i = $withIndex ? new MemoryIndex() : null;
    $e = new IngestEngine($tz, static function () {
        return new FakeClassifier();
    }, new IpMatcher('10.9.9.9'), $c, $p, $d, null, null, $i);

    return [$e, $c, $p, $d, $i];
};

// Покажчик днів: результат той самий, а перерахунок одного дня читає лише його частину файлів.
[$e0, , , $d0] = $make(false);
$r0 = $e0->run($src(), ['now' => $now]);
[$e, $c, $p, $d, $idx] = $make(true);
$r = $e->run($src(), ['now' => $now]);
T::eq($d0->rows, $d->rows, 'index does not change results');
$gz = $home . '/logs/example.org-ssl_log-Oct-2026.gz';
T::ok(!empty($idx->index[$gz]['from0']) && isset($idx->index[$gz]['days']['2026-10-02']), 'index built for the gz archive');
$total = 0;
foreach ($src() as $path => $_) {
    $total += count(gzfile($path)); // gzfile читає і звичайні файли, і склеєні gzip-члени
}
$p->days = ['2026-10-02'];
$w = $d->writes;
$r = $e->run($src(), ['now' => $now]);
T::eq(['2026-10-02'], $r['days'], 'one pending day recomputed');
T::ok($r['scanned'] > 0 && $r['scanned'] < $total / 2, "recompute of one day scans part of the files ({$r['scanned']} of $total lines)");
T::eq($d0->rows['2026-10-02'], $d->rows['2026-10-02'], 'recomputed day identical');

// Ліміт часу всередині перерахунку: день не пишеться, лишається в черзі.
$p->days = ['2026-10-02'];
$w = $d->writes;
$calls = 0;
$r = $e->run($src(), ['now' => $now, 'deadlineAt' => 50.0, 'checkEvery' => 10, 'clock' => static function () use (&$calls): float {
    return ++$calls <= 1 ? 0.0 : 100.0;
}]);
T::ok(!$r['finished'], 'cut inside computeDays: not finished');
T::eq($w, $d->writes, 'cut inside computeDays: nothing written');
T::eq(['2026-10-02'], $p->days, 'cut inside computeDays: day stays pending');
$r = $e->run($src(), ['now' => $now]);
T::ok($r['finished'] && $p->days === [], 'resumed and drained');
T::eq($d0->rows['2026-10-02'], $d->rows['2026-10-02'], 'resumed day identical');

// Ліміт дедуплікації: перевищення позначається, підрахунок не падає.
[$e, , , $d] = $make(true);
$r = $e->run($src(), ['now' => $now, 'seenMax' => 5]);
T::ok($r['finished'] && $r['dedupOverflow'], 'dedup map bounded and overflow reported');

// --days: старіші дні з нових рядків не губляться — лишаються в черзі.
[$e, $c, $p, $d] = $make(true);
$r = $e->run($src(), ['now' => (new DateTimeImmutable('2026-10-04 12:00:00', $tz))->getTimestamp(), 'days' => 2]);
T::eq(['2026-10-03', '2026-10-04'], array_keys($d->rows), '--days computes only the window');
T::ok(in_array('2026-10-01', $p->days, true) && in_array('2026-10-02', $p->days, true), '--days keeps older days pending');
T::ok($r['finished'], '--days run finished for its window');
$r = $e->run($src(), ['now' => $now]);
T::eq([], $p->days, 'next run drains the older days');
T::eq($d0->rows, $d->rows, 'all days equal to a full run');

// Той самий запит в Apache- і nginx-архіві одного потоку (різний формат рядка) рахується один раз,
// у цифрах «як у звіті» — двічі; законні однакові запити в одну секунду — усі.
$h2 = $work . '/home2';
@mkdir($h2 . '/logs', 0777, true);
@mkdir($h2 . '/access-logs', 0777, true);
$ap = [
    '198.51.100.10 - - [08/Oct/2026:22:12:27 +0300] "GET /images/a.jpg HTTP/1.0" 200 100 "-" "UA"',
    '198.51.100.11 - - [08/Oct/2026:22:12:30 +0300] "GET /only-apache HTTP/1.0" 200 100 "-" "UA"',
];
$ng = [
    '198.51.100.10 - - [08/Oct/2026:22:12:27 +0300] "GET /images/a.jpg HTTP/1.1" 301 289 "-" "UA"',
    '198.51.100.12 - - [08/Oct/2026:22:12:28 +0300] "GET /same HTTP/2.0" 200 10 "-" "UA"',
    '198.51.100.12 - - [08/Oct/2026:22:12:28 +0300] "GET /same HTTP/2.0" 200 10 "-" "UA"',
    '198.51.100.13 - - [08/Oct/2026:22:20:00 +0300] "GET /wp-login.php HTTP/2.0" 404 10 "-" "UA"',
];
file_put_contents($h2 . '/logs/example.org-ssl_log-Oct-2026.gz', gzencode(implode("\n", $ap) . "\n"));
file_put_contents($h2 . '/logs/example.org-ssl_log-Oct-2026_NGINX.gz', gzencode(implode("\n", $ng) . "\n"));
T::eq(SourceLocator::streamOf($h2 . '/logs/example.org-ssl_log-Oct-2026.gz'), SourceLocator::streamOf($h2 . '/logs/example.org-ssl_log-Oct-2026_NGINX.gz'), 'Apache and nginx archives share a stream');
[$e, , , $d] = $make(true);
clearstatcache();
$r = $e->run((new SourceLocator($h2, 'example.org'))->discover(), ['now' => $now]);
$row = $d->rows['2026-10-08'];
T::eq(5, $row['totalRequests'], 'same request in Apache and nginx archive counted once');
T::eq(1, $r['deduplicated'], 'one duplicate removed');
T::eq(6, $row['breakdown']['report']['totalRequests'], 'report-compat counts every line of every file');
T::eq(1, $row['breakdown']['report']['attackRequests'], 'report attacks');

exit(T::done());

