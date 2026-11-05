<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Waf;

use Concrete\Core\Application\Application;
use Concrete\Core\Database\Connection\Connection;
use PasichDev\SecurityGuard\Contract\ScoreServiceInterface;
use PasichDev\SecurityGuard\Contract\StateCacheInterface;
use PasichDev\SecurityGuard\Ip\IpRange;

/**
 * Поведінкові бали в базі (SecurityGuardScores) — для панелі. Рішення на
 * запиті приймаються за лічильниками в пам'яті; сюди бал скидається лише
 * коли він помітний (див. Firewall), не на кожному запиті.
 */
final class ScoreService implements ScoreServiceInterface
{
    private const MAX_EVENTS = 20;

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

    public function add(string $ip, int $points, array $events): int
    {
        // Ключ — IpRange::subject(): IPv4 як є, IPv6 — /64 (як і для банів).
        $ip = IpRange::subject($ip);
        if ($ip === '') {
            return 0;
        }
        $now = time();
        $ttl = $this->ttl();
        $db = $this->db();
        $row = $db->fetchAssociative('SELECT * FROM SecurityGuardScores WHERE ip = ?', [$ip]) ?: null;
        if ($row !== null && $now - (int) $row['updatedAt'] > $ttl) {
            $row = null;
            $db->delete('SecurityGuardScores', ['ip' => $ip]);
        }
        $score = ($row !== null ? (int) $row['score'] : 0) + $points;
        $old = $row !== null ? json_decode((string) $row['events'], true) : [];
        $all = array_slice(array_merge(is_array($old) ? $old : [], array_values(array_map('strval', $events))), -self::MAX_EVENTS);
        $data = ['score' => $score, 'events' => json_encode($all), 'updatedAt' => $now];
        if ($row !== null) {
            $db->update('SecurityGuardScores', $data, ['ip' => $ip]);
        } else {
            $db->insert('SecurityGuardScores', $data + ['ip' => $ip, 'firstSeen' => $now]);
        }

        return $score;
    }

    public function reset(string $ip): void
    {
        $this->db()->delete('SecurityGuardScores', ['ip' => IpRange::subject($ip)]);
    }

    public function list(int $limit = 50, int $offset = 0): array
    {
        $since = time() - $this->ttl();
        $db = $this->db();
        $total = (int) $db->fetchOne('SELECT COUNT(*) FROM SecurityGuardScores WHERE updatedAt >= ?', [$since]);
        $rows = $db->fetchAllAssociative(
            'SELECT * FROM SecurityGuardScores WHERE updatedAt >= ? ORDER BY score DESC, updatedAt DESC LIMIT ' . max(1, $limit) . ' OFFSET ' . max(0, $offset),
            [$since]
        );
        foreach ($rows as &$row) {
            $events = json_decode((string) $row['events'], true);
            $row['events'] = is_array($events) ? $events : [];
            $row['score'] = (int) $row['score'];
            $row['firstSeen'] = (int) $row['firstSeen'];
            $row['updatedAt'] = (int) $row['updatedAt'];
        }
        unset($row);

        return ['rows' => $rows, 'total' => $total];
    }

    public function purgeExpired(): int
    {
        return (int) $this->db()->executeStatement('DELETE FROM SecurityGuardScores WHERE updatedAt < ?', [time() - $this->ttl()]);
    }

    private function ttl(): int
    {
        return max(60, (int) ($this->state->load()['settings']['behavior_ttl'] ?? 3600));
    }

    private function db(): Connection
    {
        return $this->db ?? ($this->db = $this->app->make(Connection::class));
    }
}
