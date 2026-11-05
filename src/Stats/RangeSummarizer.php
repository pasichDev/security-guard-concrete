<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Stats;

use PasichDev\SecurityGuard\Logs\CardinalitySketch;

/**
 * Злиття денних рядків SecurityGuardDailyStats у підсумок діапазону. Чистий PHP.
 *
 * - attackIps за діапазон — точне об'єднання attackIpList днів; якщо список
 *   якогось дня обрізаний — оцінка за HyperLogLog (attackIpsApprox = true).
 * - uniqueIps за діапазон — завжди оцінка за HyperLogLog (~3 %), бо повних
 *   списків IP не зберігаємо; для одного дня — точне значення з колонки.
 * - Топи (IP, URL) зливаються з денних топ-20, тож це наближення для довгих діапазонів.
 */
final class RangeSummarizer
{
    public const COLUMNS = [
        'totalRequests', 'uniqueIps', 'attackRequests', 'attackIps', 'blocked403', 'loginFailed',
        'overload508', 'errors404', 'errors5xx', 'bytes', 'botRequests', 'hostWafBlocked', 'hostWafIps',
    ];
    private const TOP_N = 20;

    /**
     * @param array<int, array> $rows рядки днів з розкодованим 'breakdown'
     */
    public static function summarize(array $rows): array
    {
        $sum = array_fill_keys(self::COLUMNS, 0);
        $ipSketch = new CardinalitySketch();
        $attackSketch = new CardinalitySketch();
        $attackSet = [];
        $attackExact = true;
        $rSet = [];
        $rExact = true;
        $cats = $rules = $statuses = $bots = $rCats = [];
        $hours = array_fill(0, 24, 0);
        $hoursAttacks = array_fill(0, 24, 0);
        $topIps = $topAttackIps = $topUrls = $top404 = [];
        $report = ['totalRequests' => 0, 'blocked403' => 0, 'overload508' => 0, 'attackRequests' => 0, 'loginFailed' => 0];
        $hwSketch = new CardinalitySketch();
        $verifiedBotRequests = 0;
        $hwSet = [];
        $hwExact = true;
        $hwCats = $hwRules = $hwTopIps = $hwTopUrls = [];
        $botAttackLike = 0;
        $weakAttackLike = 0;
        $byDay = [];
        $lastUpdate = 0;

        foreach ($rows as $row) {
            foreach (self::COLUMNS as $c) {
                $sum[$c] += (int) ($row[$c] ?? 0);
            }
            $lastUpdate = max($lastUpdate, (int) ($row['updatedAt'] ?? 0));
            $b = is_array($row['breakdown'] ?? null) ? $row['breakdown'] : [];
            $byDay[(string) ($row['day'] ?? '')] = [
                'totalRequests' => (int) ($row['totalRequests'] ?? 0),
                'attackRequests' => (int) ($row['attackRequests'] ?? 0),
                'overload508' => (int) ($row['overload508'] ?? 0),
            ];

            if (isset($b['ipSketch']) && is_string($b['ipSketch'])) {
                $ipSketch->merge(new CardinalitySketch($b['ipSketch']));
            }
            if (isset($b['attackIpSketch']) && is_string($b['attackIpSketch'])) {
                $attackSketch->merge(new CardinalitySketch($b['attackIpSketch']));
            }
            foreach ((array) ($b['attackIpList'] ?? []) as $ip) {
                $attackSet[(string) $ip] = true;
            }
            if (!empty($b['attackIpListTruncated'])) {
                $attackExact = false;
            }
            $verifiedBotRequests += (int) ($b['verifiedBotRequests'] ?? 0);
            $hw = is_array($b['hostWaf'] ?? null) ? $b['hostWaf'] : [];
            foreach ((array) ($hw['ipList'] ?? []) as $ip) {
                $hwSet[(string) $ip] = true;
            }
            if (!empty($hw['ipListTruncated'])) {
                $hwExact = false;
            }
            if (isset($hw['ipSketch']) && is_string($hw['ipSketch'])) {
                $hwSketch->merge(new CardinalitySketch($hw['ipSketch']));
            }
            self::addMap($hwCats, $hw['categories'] ?? []);
            self::addMap($hwRules, $hw['topRules'] ?? []);
            self::addTop($hwTopIps, $hw['topIps'] ?? [], 'ip');
            self::addTop($hwTopUrls, $hw['topUrls'] ?? [], 'url');
            $botAttackLike += (int) ($b['botAttackLike'] ?? 0);
            $weakAttackLike += (int) ($b['weakAttackLike'] ?? 0);
            self::addMap($cats, $b['categories'] ?? []);
            self::addMap($rules, $b['rules'] ?? []);
            self::addMap($statuses, $b['statuses'] ?? []);
            self::addMap($bots, $b['bots'] ?? []);
            foreach ((array) ($b['hours'] ?? []) as $h => $n) {
                if (isset($hours[$h])) {
                    $hours[$h] += (int) $n;
                }
            }
            foreach ((array) ($b['hoursAttacks'] ?? []) as $h => $n) {
                if (isset($hoursAttacks[$h])) {
                    $hoursAttacks[$h] += (int) $n;
                }
            }
            self::addTop($topIps, $b['topIps'] ?? [], 'ip', ['attacks']);
            self::addTop($topAttackIps, $b['topAttackIps'] ?? [], 'ip');
            self::addTop($topUrls, $b['topUrls'] ?? [], 'url');
            self::addTop($top404, $b['top404'] ?? [], 'url');

            $r = is_array($b['report'] ?? null) ? $b['report'] : [];
            // Старі рядки (до v1.2) не мають report.totalRequests/403/508 — тоді беремо колонки.
            $report['totalRequests'] += (int) ($r['totalRequests'] ?? ($row['totalRequests'] ?? 0));
            $report['blocked403'] += (int) ($r['blocked403'] ?? ($row['blocked403'] ?? 0));
            $report['overload508'] += (int) ($r['overload508'] ?? ($row['overload508'] ?? 0));
            $report['attackRequests'] += (int) ($r['attackRequests'] ?? 0);
            $report['loginFailed'] += (int) ($r['loginFailed'] ?? 0);
            foreach ((array) ($r['attackIpList'] ?? []) as $ip) {
                $rSet[(string) $ip] = true;
            }
            if (!empty($r['attackIpListTruncated'])) {
                $rExact = false;
            }
            self::addMap($rCats, $r['categories'] ?? []);
        }

        $days = count($rows);
        if ($days > 1) {
            $sum['uniqueIps'] = $ipSketch->count();
            $sum['attackIps'] = $attackExact ? count($attackSet) : max(count($attackSet), $attackSketch->count());
            // Списки IP днів обрізані до 1000 — тоді об'єднання недорахувало б; беремо HLL.
            $sum['hostWafIps'] = $hwExact ? count($hwSet) : max(count($hwSet), $hwSketch->count());
        }
        $report['attackIps'] = $days === 1 && isset($rows[0]['breakdown']['report']['attackIps'])
            ? (int) $rows[0]['breakdown']['report']['attackIps']
            : count($rSet);
        $report['attackIpsApprox'] = !$rExact;
        $report['categories'] = self::sortDesc($rCats);

        ksort($statuses);

        return $sum + [
            'days' => $days,
            'uniqueIpsApprox' => $days > 1,
            'attackIpsApprox' => $days > 1 && !$attackExact,
            'hostWafIpsApprox' => $days > 1 && !$hwExact,
            'updatedAt' => $lastUpdate,
            'byDay' => $byDay,
            'breakdown' => [
                'categories' => self::sortDesc($cats),
                'rules' => array_slice(self::sortDesc($rules), 0, self::TOP_N, true),
                'statuses' => $statuses,
                'bots' => array_slice(self::sortDesc($bots), 0, self::TOP_N, true),
                'verifiedBotRequests' => $verifiedBotRequests,
                'botAttackLike' => $botAttackLike,
                'weakAttackLike' => $weakAttackLike,
                'hours' => $hours,
                'hoursAttacks' => $hoursAttacks,
                'topIps' => self::finishTop($topIps, 'ip'),
                'topAttackIps' => self::finishTop($topAttackIps, 'ip'),
                'topUrls' => self::finishTop($topUrls, 'url'),
                'top404' => self::finishTop($top404, 'url'),
                'countries' => [],
                'hostWaf' => [
                    'categories' => self::sortDesc($hwCats),
                    'topRules' => array_slice(self::sortDesc($hwRules), 0, self::TOP_N, true),
                    'topIps' => self::finishTop($hwTopIps, 'ip'),
                    'topUrls' => self::finishTop($hwTopUrls, 'url'),
                ],
                'report' => $report,
            ],
        ];
    }

    private static function addMap(array &$into, $map): void
    {
        if (!is_array($map)) {
            return;
        }
        foreach ($map as $k => $n) {
            $into[$k] = ($into[$k] ?? 0) + (int) $n;
        }
    }

    private static function addTop(array &$into, $list, string $key, array $extra = []): void
    {
        if (!is_array($list)) {
            return;
        }
        foreach ($list as $item) {
            if (!is_array($item) || !isset($item[$key])) {
                continue;
            }
            $k = (string) $item[$key];
            if (!isset($into[$k])) {
                $into[$k] = ['count' => 0] + array_fill_keys($extra, 0);
                if ($key === 'ip') {
                    $into[$k]['bot'] = null;
                }
            }
            if ($key === 'ip' && !empty($item['bot']) && $into[$k]['bot'] === null) {
                $into[$k]['bot'] = (string) $item['bot'];
            }
            $into[$k]['count'] += (int) ($item['count'] ?? 0);
            foreach ($extra as $e) {
                $into[$k][$e] += (int) ($item[$e] ?? 0);
            }
        }
    }

    private static function finishTop(array $map, string $key): array
    {
        uasort($map, static function (array $a, array $b): int {
            return $b['count'] <=> $a['count'];
        });
        $out = [];
        foreach (array_slice($map, 0, self::TOP_N, true) as $k => $v) {
            $out[] = [$key => (string) $k] + $v;
        }

        return $out;
    }

    private static function sortDesc(array $m): array
    {
        arsort($m);

        return $m;
    }
}
