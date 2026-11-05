<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

/*
 * Відмови сервера хостингу (403 до PHP) і оновлення діапазонів краулерів — без мережі й без Concrete:
 *   docker run --rm -v "$PWD":/s -w /s php:8.2-cli php tests/logs/hostwaf-ranges-test.php
 */

declare(strict_types=1);

use PasichDev\SecurityGuard\Logs\CrawlerVerifier;
use PasichDev\SecurityGuard\Logs\HostWafDetector;
use PasichDev\SecurityGuard\Logs\HostWafStateStoreInterface;
use PasichDev\SecurityGuard\Logs\IngestEngine;
use PasichDev\SecurityGuard\Logs\IpMatcher;
use PasichDev\SecurityGuard\Logs\SourceLocator;
use PasichDev\SecurityGuard\Stats\RangeSummarizer;
use PasichDev\SecurityGuard\Tests\Logs\FakeClassifier;
use PasichDev\SecurityGuard\Tests\Logs\MemoryCursors;
use PasichDev\SecurityGuard\Tests\Logs\MemoryDays;
use PasichDev\SecurityGuard\Tests\Logs\MemoryPending;
use PasichDev\SecurityGuard\Tests\Logs\T;
use PasichDev\SecurityGuard\Update\BotRangeStoreInterface;
use PasichDev\SecurityGuard\Update\BotRangeUpdater;
use PasichDev\SecurityGuard\Update\RangeListParser;

require __DIR__ . '/bootstrap.php';

final class MemoryHostWafState implements HostWafStateStoreInterface
{
    public $state = [];

    public function getHostWafState(): array
    {
        return $this->state;
    }

    public function setHostWafState(array $state): void
    {
        $this->state = $state;
    }
}

final class MemoryRangeStore implements BotRangeStoreInterface
{
    public $rows = [];
    public $saves = 0;

    public function rangesByBot(): array
    {
        return array_map(static function ($r) {
            return $r['ranges'];
        }, $this->rows);
    }

    public function meta(): array
    {
        return array_map(static function ($r) {
            return ['count' => count($r['ranges']), 'source' => $r['source'], 'fetchedAt' => $r['fetchedAt']];
        }, $this->rows);
    }

    public function save(string $bot, array $ranges, string $source, int $fetchedAt): void
    {
        $this->rows[$bot] = ['ranges' => $ranges, 'source' => $source, 'fetchedAt' => $fetchedAt];
        ++$this->saves;
    }
}

// =================== Відбиток сторінки 403 сервера

$line = static function (string $ip, string $day, int $sec, string $path, int $status, int $bytes, string $proto = 'HTTP/2.0'): string {
    return sprintf('%s - - [%s/Oct/2026:10:%02d:%02d +0000] "GET %s %s" %d %d "-" "Mozilla/5.0"', $ip, $day, intdiv($sec, 60) % 60, $sec % 60, $path, $proto, $status, $bytes);
};

/**
 * Змішані 403: сторінка сервера (12588 без стиснення, 3809 gzip, 3387 br, 3821 gzip у HTTP/1.1),
 * власна сторінка пакета (~300 Б), динамічні 403 Concrete (різні розміри), один сканер
 * з однаковим розміром на багатьох URL (1 IP), порожні 403.
 * @return array{lines: string[], expected: array<string, array{hw:int, ips: array<string, true>}>}
 */
$scenario = static function (int $serverIps = 12) use ($line): array {
    $lines = [];
    $exp = [];
    $sec = 0;
    foreach (['01', '02'] as $day) {
        $exp["2026-10-$day"] = ['hw' => 0, 'ips' => []];
        for ($i = 1; $i <= $serverIps; ++$i) {
            foreach ([12588, 3809, 3387, 3821] as $k => $size) {
                for ($p = 0; $p < 7; ++$p) {
                    $ip = '198.51.100.' . $i;
                    $path = $p === 0 ? '/evil/x' . $k : '/probe/' . $i . '/' . $k . '/' . $p . '.env';
                    $lines[] = $line($ip, $day, ++$sec, $path, 403, $size, $size === 3821 ? 'HTTP/1.1' : 'HTTP/2.0');
                    ++$exp["2026-10-$day"]['hw'];
                    $exp["2026-10-$day"]['ips'][$ip] = true;
                }
            }
        }
        for ($i = 1; $i <= 30; ++$i) {
            $lines[] = $line('203.0.113.' . $i, $day, ++$sec, '/blocked/' . $i, 403, 312);          // сторінка пакета
            $lines[] = $line('203.0.113.' . $i, $day, ++$sec, '/members/' . $i, 403, 20000 + $i * 37); // Concrete
            $lines[] = $line('192.0.2.200', $day, ++$sec, '/scan/' . $i, 403, 5000);               // один сканер
            $lines[] = $line('203.0.113.' . $i, $day, ++$sec, '/.git/' . $i, 403, 0);                 // порожні
            $lines[] = $line('203.0.113.' . $i, $day, ++$sec, '/page/' . $i, 200, 12588);             // не 403
        }
    }

    return ['lines' => $lines, 'expected' => $exp];
};

$sc = $scenario();
$det = new HostWafDetector();
foreach ($sc['lines'] as $l) {
    $det->observeLine($l);
}
T::eq([3387, 3809, 3821, 12588], $det->confirmed(), 'server page sizes detected, others rejected');
$again = new HostWafDetector($det->state());
foreach ($sc['lines'] as $l) {
    $again->observeLine($l);
}
T::eq($det->state(), $again->state(), 're-reading the same lines changes nothing');
T::eq(json_decode((string) json_encode($det->state()), true), (new HostWafDetector(json_decode((string) json_encode($det->state()), true)))->state(), 'state survives JSON round trip');
T::eq([3387, 12588], HostWafDetector::parseSizes(' 12588, 3387;x 3387'), 'parse explicit sizes');

// Сценарій у файлах: повний запуск, явні розміри, вимкнено, поступове накопичення ознак.
$home = sys_get_temp_dir() . '/sg-hw-' . getmypid();
@mkdir($home . '/access-logs', 0777, true);
$live = $home . '/access-logs/example.org-ssl_log';
file_put_contents($live, implode("\n", $sc['lines']) . "\n");
$tz = new DateTimeZone('UTC');
$make = static function (?MemoryHostWafState $state = null) use ($tz): array {
    $d = new MemoryDays();
    $e = new IngestEngine($tz, static function () {
        return new FakeClassifier();
    }, new IpMatcher(''), new MemoryCursors(), new MemoryPending(), $d, new CrawlerVerifier(), $state ?? new MemoryHostWafState());

    return [$e, $d];
};
$src = static function () use ($home): array {
    clearstatcache();

    return (new SourceLocator($home, 'example.org'))->discover();
};

[$e, $d] = $make();
$r = $e->run($src());
T::eq([3387, 3809, 3821, 12588], $r['hostWafSizes'], 'engine reports detected sizes');
foreach ($sc['expected'] as $day => $x) {
    T::eq($x['hw'], $d->rows[$day]['hostWafBlocked'], "$day hostWafBlocked");
    T::eq(count($x['ips']), $d->rows[$day]['hostWafIps'], "$day hostWafIps");
    T::eq($x['hw'] + 120, $d->rows[$day]['blocked403'], "$day all 403 still counted");
    T::eq(['unclassified' => $x['hw'] - 48, 'injection' => 48], $d->rows[$day]['breakdown']['hostWaf']['categories'], "$day hostWaf categories");
    T::ok(array_key_exists('bot', $d->rows[$day]['breakdown']['hostWaf']['topIps'][0]), "$day hostWaf topIps have bot field");
}
$auto = $d->rows;

[$e, $d] = $make();
$e->run($src(), ['hostWafDetect' => false]);
T::eq(0, $d->rows['2026-10-01']['hostWafBlocked'], 'detection off');
$same = true;
foreach ($auto as $day => $row) {
    $same = $same && $row['breakdown']['report'] === $d->rows[$day]['breakdown']['report'] && $row['totalRequests'] === $d->rows[$day]['totalRequests']
        && $row['attackRequests'] === $d->rows[$day]['attackRequests'] && $row['blocked403'] === $d->rows[$day]['blocked403'];
}
T::ok($same, 'host WAF detection does not change report-compat or other columns');

[$e, $d] = $make();
$r = $e->run($src(), ['hostWafSizes' => '12588']);
T::eq([12588], $r['hostWafSizes'], 'explicit sizes override detection');
T::eq(12 * 7, $d->rows['2026-10-01']['hostWafBlocked'], 'explicit size counted only');

// Поступово: спершу ознак замало (01.10 — сторінка сервера лише з 5 IP), потім у живий
// лог дописуються рядки за 02.10 — розмір підтверджується, і 01.10 (нових рядків там немає)
// теж перераховується. Результат має збігтися з повним запуском по тому самому файлу.
$isServer = static function (string $l): bool {
    return (bool) preg_match('/" 403 (12588|3809|3387|3821) /', $l);
};
$first = $rest = [];
foreach ($sc['lines'] as $l) {
    $day1 = strpos($l, '[01/Oct') !== false;
    $ipN = preg_match('/^198\.51\.100\.(\d+) /', $l, $mm) ? (int) $mm[1] : 0;
    if ($day1 && $isServer($l) && $ipN > 5) {
        continue; // на 01.10 лише 5 IP бачать сторінку сервера
    }
    if ($day1) {
        $first[] = $l;
    } else {
        $rest[] = $l;
    }
}
file_put_contents($live, implode("\n", $first) . "\n");
$state = new MemoryHostWafState();
[$e, $d] = $make($state);
$r = $e->run($src());
T::eq([], $r['hostWafSizes'], 'not enough evidence yet');
T::eq(0, $d->rows['2026-10-01']['hostWafBlocked'], 'nothing counted before confirmation');
file_put_contents($live, implode("\n", $rest) . "\n", FILE_APPEND);
$r = $e->run($src());
T::eq([3387, 3809, 3821, 12588], $r['hostWafSizes'], 'confirmed after more data');
T::ok(in_array('2026-10-01', $r['days'], true), 'day without new lines recomputed after confirmation');
T::eq(5 * 28, $d->rows['2026-10-01']['hostWafBlocked'], '01.10 counted with the new fingerprint');
[$e2, $d2] = $make();
$e2->run($src());
T::eq($d2->rows, $d->rows, 'incremental equals full run');
T::ok($state->state['confirmed'] === [3387, 3809, 3821, 12588], 'state persisted');
file_put_contents($live, implode("\n", $sc['lines']) . "\n");

$sum = RangeSummarizer::summarize(array_values($auto));
T::eq($auto['2026-10-01']['hostWafBlocked'] * 2, $sum['hostWafBlocked'], 'range hostWafBlocked');
T::eq(12, $sum['hostWafIps'], 'range hostWafIps = union of days');
T::eq(48 * 2, $sum['breakdown']['hostWaf']['categories']['injection'], 'range hostWaf categories');
T::ok(!$sum['hostWafIpsApprox'], 'range hostWafIps exact');

// =================== Розбір офіційних списків діапазонів

$p = RangeListParser::parse('{"creationTime":"2026-11-04T15:45:59","prefixes":[{"ipv4Prefix":"66.249.64.0/27"},{"ipv6Prefix":"2001:4860:4801:10::/64"},{"ipv4Prefix":"157.55.39.1/32"},{"ipv4Prefix":"66.249.64.0/27"}]}');
T::eq(['66.249.64.0/27', '2001:4860:4801:10::/64', '157.55.39.1'], $p['prefixes'], 'parse, dedupe, /32 as bare IP');
T::eq('2026-11-04T15:45:59', $p['creationTime'], 'creationTime');
$bad = [
    'not json' => 'nope',
    'no prefixes' => '{"items":[]}',
    'empty' => '{"prefixes":[]}',
    'both keys' => '{"prefixes":[{"ipv4Prefix":"1.2.3.0/24","ipv6Prefix":"::/64"}]}',
    'v6 in v4 key' => '{"prefixes":[{"ipv4Prefix":"2001:db8::/64"}]}',
    'garbage cidr' => '{"prefixes":[{"ipv4Prefix":"1.2.3.0/24; rm"}]}',
    'too wide v4' => '{"prefixes":[{"ipv4Prefix":"10.0.0.0/8"}]}',
    'too wide v6' => '{"prefixes":[{"ipv6Prefix":"2001::/16"}]}',
    'host bits' => '{"prefixes":[{"ipv4Prefix":"66.249.64.1/27"}]}',
    'bad length' => '{"prefixes":[{"ipv4Prefix":"66.249.64.0/33"}]}',
    'not object' => '{"prefixes":["66.249.64.0/27"]}',
];
foreach ($bad as $label => $json) {
    $threw = false;
    try {
        RangeListParser::parse($json);
    } catch (InvalidArgumentException $ex) {
        $threw = true;
    }
    T::ok($threw, "reject: $label");
}

// =================== Оновлювач (фейкова мережа)

$mk = static function (array $cidrs): string {
    return (string) json_encode(['creationTime' => '2026-11-05T00:00:00', 'prefixes' => array_map(static function ($c) {
        return strpos($c, ':') !== false ? ['ipv6Prefix' => $c] : ['ipv4Prefix' => $c];
    }, $cidrs)]);
};
$many = static function (string $base, int $n): array {
    $out = [];
    [$a, $b] = array_map('intval', explode('.', $base));
    for ($i = 0; $i < $n; ++$i) {
        $out[] = $a . '.' . ($b + intdiv($i, 256)) . '.' . ($i % 256) . '.0/24';
    }

    return $out;
};
$net = [
    BotRangeUpdater::SOURCES['Googlebot'][0] => $mk(array_merge($many('66.100', 300), ['192.0.2.0/24'])),
    BotRangeUpdater::SOURCES['Googlebot'][1] => $mk($many('66.200', 300)),
    BotRangeUpdater::SOURCES['Bingbot'][0] => $mk($many('157.56', 30)),
    BotRangeUpdater::SOURCES['Applebot'][0] => $mk($many('17.242', 30)),
    BotRangeUpdater::SOURCES['DuckDuckBot'][0] => $mk($many('20.200', 500)),
];
$fetch = static function (string $url) use (&$net): string {
    if (!isset($net[$url])) {
        throw new RuntimeException('HTTP 503');
    }

    return $net[$url];
};
$store = new MemoryRangeStore();
$u = new BotRangeUpdater($fetch, $store);

$r = $u->update(true, 1000);
T::eq(0, $store->saves, 'dry run saves nothing');
T::eq(601, $r['updated']['Googlebot'] ?? null, 'dry run reports counts (two Google lists merged)');

$r = $u->update(false, 1000);
T::eq([], $r['errors'], 'all lists accepted');
T::eq(['Googlebot' => 601, 'Bingbot' => 30, 'Applebot' => 30, 'DuckDuckBot' => 500], $r['updated'], 'updated counts');
T::eq(1000, $store->rows['Bingbot']['fetchedAt'], 'fetchedAt stored');
T::ok(strpos($store->rows['Googlebot']['source'], 'googlebot.json@2026-11-05') !== false, 'source label');

$r = $u->update(false, 2000);
T::eq(['Googlebot' => 601, 'Bingbot' => 30, 'Applebot' => 30, 'DuckDuckBot' => 500], $r['unchanged'], 'second run unchanged');

$net[BotRangeUpdater::SOURCES['Bingbot'][0]] = $mk($many('157.56', 10));       // зменшився втричі
unset($net[BotRangeUpdater::SOURCES['Googlebot'][1]]);                         // одне з двох джерел Google недоступне
$net[BotRangeUpdater::SOURCES['Applebot'][0]] = '{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"}]}';
$r = $u->update(false, 3000);
T::ok(isset($r['errors']['Bingbot']) && strpos($r['errors']['Bingbot'], 'shrank') !== false, 'shrink >50% rejected');
T::eq(30, count($store->rows['Bingbot']['ranges']), 'old Bing list kept');
T::ok(isset($r['errors']['Googlebot']), 'partial Google fetch rejected as a whole');
T::eq(601, count($store->rows['Googlebot']['ranges']), 'old Google list kept');
T::ok(isset($r['errors']['Applebot']), 'invalid list rejected');
T::eq(['DuckDuckBot' => 500], $r['unchanged'], 'healthy source still checked');

// Перший запуск без збережених: порівняння з вбудованим списком (Bing — 28 префіксів).
$store2 = new MemoryRangeStore();
$net2 = $net;
$net2[BotRangeUpdater::SOURCES['Bingbot'][0]] = $mk($many('157.56', 5));
$r = (new BotRangeUpdater(static function (string $url) use ($net2): string {
    if (!isset($net2[$url])) {
        throw new RuntimeException('HTTP 503');
    }

    return $net2[$url];
}, $store2))->update(false, 1);
T::ok(isset($r['errors']['Bingbot']), 'shrink check against embedded list when nothing stored');

// =================== Збережені діапазони замінюють вбудовані
$gua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
$v = new CrawlerVerifier([], ['Googlebot' => ['192.0.2.0/24']]);
T::eq('Googlebot', $v->verify('192.0.2.9', $gua), 'stored range verifies');
T::eq(null, $v->verify('66.249.66.1', $gua), 'embedded range replaced by stored for that bot');
T::eq('Bingbot', $v->verify('157.55.39.1', 'Mozilla/5.0 (compatible; bingbot/2.0)'), 'other bots keep embedded ranges');

exit(T::done());
