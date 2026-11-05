<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

/*
 * Генерує синтетичні логи cPanel у tests/fixtures/logs/ (каталог не в git):
 *   home/logs/example.org-ssl_log-Oct-2026.gz  — архів з двох склеєних gzip-членів
 *   home/access-logs/example.org-ssl_log       — живий лог; його початок перекривається з кінцем архіву
 *   home/access-logs/example.org               — http-потік (окремий потік, не дедуплікується з https)
 *   expected.json                               — правильні цифри по днях (Europe/Kyiv)
 * Покриває: перекриття при ротації, gz, биті рядки, межу доби в часовому поясі,
 * законні однакові рядки в одну секунду, виключену IP.
 */

declare(strict_types=1);

$out = $argv[1] ?? dirname(__DIR__) . '/fixtures/logs';
$home = $out . '/home';
@mkdir($home . '/logs', 0777, true);
@mkdir($home . '/access-logs', 0777, true);
foreach ([$home . '/logs/example.org-ssl_log-Oct-2026.gz', $home . '/access-logs/example.org-ssl_log', $home . '/access-logs/example.org'] as $f) {
    @unlink($f);
}

mt_srand(20261001);
$tz = new DateTimeZone('Europe/Kyiv');
$excludedIp = '10.9.9.9';

$ips = [];
for ($i = 1; $i <= 60; ++$i) {
    $ips[] = '203.0.113.' . $i;
}
$attackers = ['198.51.100.7', '198.51.100.8', '198.51.100.9', '2001:db8::66'];
$uas = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15',
];

/** Логічні запити: [ts, line, flags]. */
$requests = [];
$fmt = static function (int $ts, string $ip, string $req, int $status, int $bytes, string $ua, string $offset = '+0300'): string {
    $sign = $offset[0] === '-' ? -1 : 1;
    $sec = $sign * ((int) substr($offset, 1, 2) * 3600 + (int) substr($offset, 3, 2) * 60);
    $local = gmdate('d/M/Y:H:i:s', $ts + $sec);

    return sprintf('%s - - [%s %s] "%s" %d %d "-" "%s"', $ip, $local, $offset, $req, $status, $bytes, $ua);
};
$add = static function (int $ts, string $ip, string $method, string $path, int $status, string $ua, array $flags = []) use (&$requests, $fmt): string {
    $req = $method === '' ? $path : "$method $path HTTP/1.1";
    $line = $fmt($ts, $ip, $req, $status, 100 + ($ts % 900), $ua, $flags['offset'] ?? '+0300');
    $requests[] = ['ts' => $ts, 'line' => $line, 'ip' => $ip, 'method' => $method, 'path' => $path, 'status' => $status, 'stream' => $flags['stream'] ?? 'ssl'];

    return $line;
};

$start = (new DateTimeImmutable('2026-10-01 00:00:00', $tz))->getTimestamp();
$end = (new DateTimeImmutable('2026-10-05 00:00:00', $tz))->getTimestamp();
for ($ts = $start; $ts < $end; $ts += mt_rand(20, 120)) {
    $r = mt_rand(1, 100);
    $ip = $ips[mt_rand(0, count($ips) - 1)];
    $ua = $uas[mt_rand(0, 2)];
    if ($r <= 8) {
        $add($ts, $attackers[mt_rand(0, 3)], 'GET', '/evil/x.php?id=' . mt_rand(1, 9), 404, 'curl/8.0');
    } elseif ($r <= 12) {
        $add($ts, $attackers[mt_rand(0, 3)], 'GET', '/wp-login.php', 403, 'Mozilla/5.0');
    } elseif ($r <= 14) {
        $add($ts, $ip, 'POST', '/login/authenticate/concrete', 200, $ua);
    } elseif ($r === 15) {
        $add($ts, $ip, 'POST', '/login/authenticate/concrete', 302, $ua);
    } elseif ($r === 16) {
        $add($ts, $ip, 'GET', '/', 508, $ua);
    } elseif ($r === 17) {
        $add($ts, $excludedIp, 'GET', '/dashboard', 200, $ua);
    } elseif ($r === 18) {
        // Два однакові запити в ту саму секунду — законний дубль, рахується двічі.
        $add($ts, $ip, 'GET', '/same', 200, $ua);
        $add($ts, $ip, 'GET', '/same', 200, $ua);
    } elseif ($r === 19) {
        $add($ts, $ip, '', '-', 400, '-');
    } else {
        $add($ts, $ip, 'GET', '/page/' . mt_rand(1, 40), 200, $ua);
    }
}
// Межа доби в Києві (UTC+3 у жовтні): 23:59:59 і 00:00:00 — різні дні, навіть якщо записані з +0000.
$b = (new DateTimeImmutable('2026-10-02 00:00:00', $tz))->getTimestamp();
$add($b - 1, '192.0.2.1', 'GET', '/boundary-before', 200, $uas[0], ['offset' => '+0000']);
$add($b, '192.0.2.1', 'GET', '/boundary-after', 200, $uas[0], ['offset' => '+0000']);
// http-потік: окремі запити + один рядок, ідентичний https-рядку (різні запити, рахувати обидва).
$httpLines = [];
foreach ($requests as $q) {
    if ($q['path'] === '/page/7' && count($httpLines) < 1) {
        $requests[] = ['stream' => 'http'] + $q;
        $httpLines[] = $q['line'];
    }
}
for ($ts = $start + 3600; $ts < $end; $ts += 7200) {
    $httpLines[] = $add($ts, '203.0.113.200', 'GET', '/', 301, $uas[0], ['stream' => 'http']);
}

usort($requests, static function (array $a, array $c): int {
    return $a['ts'] <=> $c['ts'];
});

// Ротація: архів — до 03.10 22:00, живий лог — з 03.10 21:30 (перекриття 30 хв).
$cut = (new DateTimeImmutable('2026-10-03 22:00:00', $tz))->getTimestamp();
$liveFrom = (new DateTimeImmutable('2026-10-03 21:30:00', $tz))->getTimestamp();
$mid = (new DateTimeImmutable('2026-10-02 12:00:00', $tz))->getTimestamp();
$arch1 = $arch2 = $live = [];
foreach ($requests as $q) {
    if ($q['stream'] !== 'ssl') {
        continue;
    }
    if ($q['ts'] < $cut) {
        if ($q['ts'] < $mid) {
            $arch1[] = $q['line'];
        } else {
            $arch2[] = $q['line'];
        }
    }
    if ($q['ts'] >= $liveFrom) {
        $live[] = $q['line'];
    }
}
// Два gzip-члени в одному файлі (cPanel дописує архів щодня).
$gz = $home . '/logs/example.org-ssl_log-Oct-2026.gz';
file_put_contents($gz, gzencode(implode("\n", $arch1) . "\n"));
file_put_contents($gz, gzencode(implode("\n", $arch2) . "\n"), FILE_APPEND);

// Биті рядки в живому лозі (не рахуються) + недописаний останній рядок.
$garbage = ['garbage line', '', "\x00\x01\x02binary", '1.2.3.4 - - [03/Oct/2026:10:0', '5.6.7.8 - - [99/Foo/2026:10:00:00 +0300] "GET / HTTP/1.1" 200 1'];
array_splice($live, 10, 0, $garbage);
$partial = $fmt($end - 5, '203.0.113.1', 'GET /partial HTTP/1.1', 200, 1, $uas[0]);
file_put_contents($home . '/access-logs/example.org-ssl_log', implode("\n", $live) . "\n" . $partial);
file_put_contents($home . '/access-logs/example.org', implode("\n", $httpLines) . "\n");

// Очікувані цифри: кожен логічний запит один раз (крім недописаного рядка).
$expected = [];
foreach ($requests as $q) {
    $day = (new DateTimeImmutable('@' . $q['ts']))->setTimezone($tz)->format('Y-m-d');
    $e = &$expected[$day];
    $e = ($e ?? []) + ['total' => 0, 'excluded' => 0, 'fakeAttacks' => 0, 'reportAttacks' => 0, 'blocked403' => 0, 'overload508' => 0, 'loginFailed' => 0, 'errors404' => 0];
    if ($q['ip'] === $excludedIp) {
        ++$e['excluded'];
        unset($e);
        continue;
    }
    ++$e['total'];
    $e['fakeAttacks'] += stripos($q['path'], '/evil') !== false ? 1 : 0;
    $e['reportAttacks'] += preg_match('~wp-~i', $q['path']) ? 1 : 0;
    $e['blocked403'] += $q['status'] === 403 ? 1 : 0;
    $e['overload508'] += $q['status'] === 508 ? 1 : 0;
    $e['errors404'] += $q['status'] === 404 ? 1 : 0;
    $e['loginFailed'] += ($q['method'] === 'POST' && $q['status'] === 200 && strpos($q['path'], '/login/authenticate/') === 0) ? 1 : 0;
    unset($e);
}
ksort($expected);
file_put_contents($out . '/expected.json', json_encode([
    'days' => $expected,
    'partialLine' => $partial,
    'overlapLines' => count(array_filter($requests, static function ($q) use ($liveFrom, $cut) {
        return $q['stream'] === 'ssl' && $q['ts'] >= $liveFrom && $q['ts'] < $cut;
    })),
], JSON_PRETTY_PRINT));

echo "fixtures written to $out\n";
