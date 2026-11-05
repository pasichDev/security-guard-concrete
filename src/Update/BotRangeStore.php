<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Update;

use Concrete\Core\Database\Connection\Connection;
use Throwable;

final class BotRangeStore implements BotRangeStoreInterface
{
    public const TABLE = 'SecurityGuardBotRanges';

    /** @var Connection */
    private $db;

    public function __construct(Connection $db)
    {
        $this->db = $db;
    }

    public function rangesByBot(): array
    {
        $out = [];
        foreach ($this->rows() as $r) {
            $list = json_decode((string) $r['ranges'], true);
            if (is_array($list) && $list) {
                $out[(string) $r['bot']] = array_values(array_filter($list, 'is_string'));
            }
        }

        return $out;
    }

    public function meta(): array
    {
        $out = [];
        foreach ($this->rows() as $r) {
            $list = json_decode((string) $r['ranges'], true);
            $out[(string) $r['bot']] = [
                'count' => is_array($list) ? count($list) : 0,
                'source' => (string) $r['source'],
                'fetchedAt' => (int) $r['fetchedAt'],
            ];
        }

        return $out;
    }

    public function save(string $bot, array $ranges, string $source, int $fetchedAt): void
    {
        $this->db->executeStatement(
            'INSERT INTO ' . self::TABLE . ' (bot, ranges, source, fetchedAt) VALUES (?, ?, ?, ?)'
            . ' ON DUPLICATE KEY UPDATE ranges = VALUES(ranges), source = VALUES(source), fetchedAt = VALUES(fetchedAt)',
            [substr($bot, 0, 32), (string) json_encode(array_values($ranges), JSON_UNESCAPED_SLASHES), substr($source, 0, 255), $fetchedAt]
        );
    }

    /** Таблиці може ще не бути (пакет не оновлено) — тоді працюємо з вбудованими діапазонами. */
    private function rows(): array
    {
        try {
            return $this->db->fetchAllAssociative('SELECT bot, ranges, source, fetchedAt FROM ' . self::TABLE);
        } catch (Throwable $e) {
            return [];
        }
    }
}
