<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Stats;

use Concrete\Core\Database\Connection\Connection;
use PasichDev\SecurityGuard\Contract\StatsRepositoryInterface;
use PasichDev\SecurityGuard\Logs\DayWriterInterface;

/** Таблиця SecurityGuardDailyStats: читання для панелі й запис агрегатів дня. */
final class StatsRepository implements StatsRepositoryInterface, DayWriterInterface
{
    public const TABLE = 'SecurityGuardDailyStats';
    private const INT_COLUMNS = RangeSummarizer::COLUMNS;

    /** @var Connection */
    private $db;

    public function __construct(Connection $db)
    {
        $this->db = $db;
    }

    public function getDays(string $fromDay, string $toDay): array
    {
        if (strcmp($fromDay, $toDay) > 0) {
            [$fromDay, $toDay] = [$toDay, $fromDay];
        }
        $rows = $this->db->fetchAllAssociative(
            'SELECT * FROM ' . self::TABLE . ' WHERE day >= ? AND day <= ? ORDER BY day',
            [$fromDay, $toDay]
        );
        $out = [];
        foreach ($rows as $r) {
            $out[] = self::hydrate($r);
        }

        return $out;
    }

    public function summarize(string $fromDay, string $toDay): array
    {
        return ['from' => $fromDay, 'to' => $toDay] + RangeSummarizer::summarize($this->getDays($fromDay, $toDay));
    }

    public function lastIngestAt(): int
    {
        $t = (int) $this->db->fetchOne('SELECT MAX(updatedAt) FROM SecurityGuardLogCursors');
        if ($t > 0) {
            return $t;
        }

        return (int) $this->db->fetchOne('SELECT MAX(updatedAt) FROM ' . self::TABLE);
    }

    /** Перезаписує рядок дня повністю (ідемпотентно). */
    public function saveDay(string $day, array $row): void
    {
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $day)) {
            return;
        }
        $cols = ['day'];
        $vals = [$day];
        foreach (self::INT_COLUMNS as $c) {
            $cols[] = $c;
            $vals[] = max(0, (int) ($row[$c] ?? 0));
        }
        $cols[] = 'breakdown';
        $vals[] = (string) json_encode($row['breakdown'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        $cols[] = 'updatedAt';
        $vals[] = time();
        $update = [];
        foreach (array_slice($cols, 1) as $c) {
            $update[] = $c . ' = VALUES(' . $c . ')';
        }
        $this->db->executeStatement(
            'INSERT INTO ' . self::TABLE . ' (' . implode(', ', $cols) . ') VALUES (' . implode(', ', array_fill(0, count($cols), '?')) . ')'
            . ' ON DUPLICATE KEY UPDATE ' . implode(', ', $update),
            $vals
        );
    }


    private static function hydrate(array $r): array
    {
        $out = ['day' => (string) $r['day']];
        foreach (self::INT_COLUMNS as $c) {
            $out[$c] = (int) ($r[$c] ?? 0);
        }
        $b = json_decode((string) ($r['breakdown'] ?? ''), true);
        $out['breakdown'] = is_array($b) ? $b : [];
        $out['updatedAt'] = (int) ($r['updatedAt'] ?? 0);

        return $out;
    }
}
