<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Waf;

use Concrete\Core\Application\Application;
use Concrete\Core\Database\Connection\Connection;
use PasichDev\SecurityGuard\Contract\EventLogInterface;
use PasichDev\SecurityGuard\Contract\StateCacheInterface;
use PasichDev\SecurityGuard\Geo\CountryGuesser;
use PasichDev\SecurityGuard\Ip\IpRange;
use PasichDev\SecurityGuard\State\Counters;

/** Журнал подій WAF (SecurityGuardEvents). Однакові (ip+rule+action) події — не частіше event_log_throttle_seconds. */
final class EventLog implements EventLogInterface
{
    /** @var Application */
    private $app;

    /** @var StateCacheInterface */
    private $state;

    /** @var Connection|null */
    private $db;

    public function __construct(Application $app, StateCacheInterface $state)
    {
        $this->app = $app;
        $this->state = $state;
    }

    public function log(string $ip, string $rule, string $category, string $action, array $request = []): void
    {
        $settings = $this->state->load()['settings'];
        if (empty($settings['log_events'])) {
            return;
        }
        $ip = IpRange::normalize($ip) ?: Text::cut($ip, 45);
        $throttle = (int) ($settings['event_log_throttle_seconds'] ?? 60);
        // Поставлений бан пишемо завжди; решту — з тротлінгом.
        if ($action !== 'banned' && $throttle > 0
            && !Counters::store()->add('ev:' . md5($ip . '|' . $rule . '|' . $action), 1, $throttle)) {
            return;
        }
        $country = (string) ($request['country'] ?? '');
        if ($country === '' && !empty($settings['geo_lookup'])) {
            $country = CountryGuesser::guess($ip);
        }
        $this->db()->insert('SecurityGuardEvents', [
            'ip' => $ip,
            'rule' => Text::cut($rule, 64),
            'category' => Text::cut($category, 32),
            'action' => Text::cut($action, 16),
            'method' => Text::cut(strtoupper((string) ($request['method'] ?? 'GET')), 10),
            'url' => Text::url((string) ($request['url'] ?? ''), 500),
            'userAgent' => Text::cut((string) ($request['userAgent'] ?? ''), 255),
            'referrer' => Text::url((string) ($request['referrer'] ?? ''), 255),
            'country' => Text::cut($country, 2),
            'createdAt' => time(),
        ]);
    }

    public function query(array $filters = [], int $limit = 50, int $offset = 0): array
    {
        [$where, $params] = $this->where($filters);
        $db = $this->db();
        $total = (int) $db->fetchOne('SELECT COUNT(*) FROM SecurityGuardEvents' . $where, $params);
        $rows = $db->fetchAllAssociative(
            'SELECT * FROM SecurityGuardEvents' . $where . ' ORDER BY id DESC LIMIT ' . max(1, $limit) . ' OFFSET ' . max(0, $offset),
            $params
        );
        foreach ($rows as &$row) {
            $row['id'] = (int) $row['id'];
            $row['createdAt'] = (int) $row['createdAt'];
        }
        unset($row);

        return ['rows' => $rows, 'total' => $total];
    }

    public function summary(int $from, int $to): array
    {
        $db = $this->db();
        $params = [$from, $to];
        $range = ' WHERE createdAt >= ? AND createdAt < ?';
        $out = [
            'total' => (int) $db->fetchOne('SELECT COUNT(*) FROM SecurityGuardEvents' . $range, $params),
            'uniqueIps' => (int) $db->fetchOne('SELECT COUNT(DISTINCT ip) FROM SecurityGuardEvents' . $range, $params),
            'byCategory' => [],
            'byAction' => [],
            'byDay' => [],
            'topIps' => [],
            'topRules' => [],
        ];
        foreach ($db->fetchAllAssociative('SELECT category, COUNT(*) n FROM SecurityGuardEvents' . $range . ' GROUP BY category ORDER BY n DESC', $params) as $r) {
            $out['byCategory'][(string) $r['category']] = (int) $r['n'];
        }
        foreach ($db->fetchAllAssociative('SELECT action, COUNT(*) n FROM SecurityGuardEvents' . $range . ' GROUP BY action ORDER BY n DESC', $params) as $r) {
            $out['byAction'][(string) $r['action']] = (int) $r['n'];
        }
        // Дні — у часовому поясі сайту (як SecurityGuardDailyStats.day і панель). Групуємо
        // 15-хвилинними кошиками й розкладаємо по днях у PHP: так правильно і через
        // перехід на літній/зимовий час, і для поясів зі зсувом на пів години.
        $tz = $this->siteTimezone();
        $rows = $db->fetchAllAssociative(
            'SELECT FLOOR(createdAt / 900) b, COUNT(*) n FROM SecurityGuardEvents' . $range . ' GROUP BY b',
            $params
        );
        foreach ($rows as $r) {
            $day = (new \DateTimeImmutable('@' . ((int) $r['b'] * 900)))->setTimezone($tz)->format('Y-m-d');
            $out['byDay'][$day] = ($out['byDay'][$day] ?? 0) + (int) $r['n'];
        }
        ksort($out['byDay']);
        foreach ($db->fetchAllAssociative('SELECT ip, COUNT(*) n, MAX(country) country FROM SecurityGuardEvents' . $range . ' GROUP BY ip ORDER BY n DESC LIMIT 10', $params) as $r) {
            $out['topIps'][] = ['ip' => (string) $r['ip'], 'count' => (int) $r['n'], 'country' => (string) $r['country']];
        }
        foreach ($db->fetchAllAssociative('SELECT rule, category, COUNT(*) n FROM SecurityGuardEvents' . $range . ' GROUP BY rule, category ORDER BY n DESC LIMIT 10', $params) as $r) {
            $out['topRules'][] = ['rule' => (string) $r['rule'], 'category' => (string) $r['category'], 'count' => (int) $r['n']];
        }

        return $out;
    }

    /** Часовий пояс сайту — той самий, що в LogIngest::timezone(). */
    private function siteTimezone(): \DateTimeZone
    {
        try {
            $tz = (string) $this->app->make('site')->getSite()->getTimezone();
            if ($tz !== '') {
                return new \DateTimeZone($tz);
            }
        } catch (\Throwable $e) {
        }

        return new \DateTimeZone(date_default_timezone_get() ?: 'UTC');
    }

    public function purgeOlderThan(int $days): int
    {
        $cutoff = time() - max(1, $days) * 86400;
        $total = 0;
        // Порціями, щоб не тримати довгий замок таблиці на shared-хостингу.
        for ($i = 0; $i < 50; $i++) {
            $n = (int) $this->db()->executeStatement('DELETE FROM SecurityGuardEvents WHERE createdAt < ? LIMIT 5000', [$cutoff]);
            $total += $n;
            if ($n < 5000) {
                break;
            }
        }

        return $total;
    }

    private function where(array $filters): array
    {
        $sql = [];
        $params = [];
        foreach (['category', 'action', 'ip', 'rule'] as $key) {
            if (isset($filters[$key]) && $filters[$key] !== '') {
                $sql[] = $key . ' = ?';
                $params[] = (string) $filters[$key];
            }
        }
        if (!empty($filters['from'])) {
            $sql[] = 'createdAt >= ?';
            $params[] = (int) $filters['from'];
        }
        if (!empty($filters['to'])) {
            $sql[] = 'createdAt < ?';
            $params[] = (int) $filters['to'];
        }
        if (isset($filters['search']) && trim((string) $filters['search']) !== '') {
            $like = '%' . addcslashes(trim((string) $filters['search']), '%_\\') . '%';
            $sql[] = '(url LIKE ? OR userAgent LIKE ? OR ip LIKE ? OR rule LIKE ?)';
            array_push($params, $like, $like, $like, $like);
        }

        return [$sql ? ' WHERE ' . implode(' AND ', $sql) : '', $params];
    }

    private function db(): Connection
    {
        return $this->db ?? ($this->db = $this->app->make(Connection::class));
    }
}
