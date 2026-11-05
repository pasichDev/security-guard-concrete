<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

use Concrete\Core\Database\Connection\Connection;

/** Курсори у таблиці SecurityGuardLogCursors. */
final class DbCursorStore implements CursorStoreInterface
{
    public const TABLE = 'SecurityGuardLogCursors';

    /** @var Connection */
    private $db;

    public function __construct(Connection $db)
    {
        $this->db = $db;
    }

    public function load(): array
    {
        $out = [];
        foreach ($this->db->fetchAllAssociative('SELECT path, fingerprint, size, position, completed, updatedAt FROM ' . self::TABLE) as $r) {
            $out[(string) $r['path']] = [
                'path' => (string) $r['path'],
                'fingerprint' => (string) $r['fingerprint'],
                'size' => (int) $r['size'],
                'position' => (int) $r['position'],
                'completed' => (bool) $r['completed'],
                'updatedAt' => (int) $r['updatedAt'],
            ];
        }

        return $out;
    }

    public function save(array $cursors): void
    {
        foreach ($cursors as $path => $r) {
            $path = (string) $path;
            if ($path === '' || strlen($path) > 255) {
                continue;
            }
            $this->db->executeStatement(
                'INSERT INTO ' . self::TABLE . ' (path, fingerprint, size, position, completed, updatedAt) VALUES (?, ?, ?, ?, ?, ?)'
                . ' ON DUPLICATE KEY UPDATE fingerprint = VALUES(fingerprint), size = VALUES(size), position = VALUES(position),'
                . ' completed = VALUES(completed), updatedAt = VALUES(updatedAt)',
                [$path, substr((string) $r['fingerprint'], 0, 64), (int) $r['size'], (int) $r['position'], empty($r['completed']) ? 0 : 1, (int) $r['updatedAt']]
            );
        }
    }
}
