<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Waf;

use Concrete\Core\Application\Application;
use Concrete\Core\Database\Connection\Connection;
use PasichDev\SecurityGuard\Contract\StateCacheInterface;
use PasichDev\SecurityGuard\Contract\WhitelistInterface;
use PasichDev\SecurityGuard\Ip\IpRange;

/** Білий список (SecurityGuardWhitelist) + перевірка діапазонів без БД. */
final class Whitelist implements WhitelistInterface
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

    /** Повторне додавання того самого діапазону оновлює опис і термін. */
    public function add(string $range, string $description = '', int $expiresAt = 0, bool $auto = false): void
    {
        $range = self::canonical($range);
        if (!IpRange::isValidRange($range)) {
            throw new \InvalidArgumentException('Invalid IP address or range');
        }
        $now = time();
        $db = $this->db();
        $existing = $db->fetchAssociative('SELECT id, auto, expiresAt FROM SecurityGuardWhitelist WHERE ipRange = ?', [$range]);
        if ($existing) {
            // Ручний безстроковий запис не перетворюємо на автоматичний з терміном.
            if ($auto && !(int) $existing['auto']) {
                return;
            }
            $db->update('SecurityGuardWhitelist', [
                'description' => Text::cut($description, 255),
                'auto' => $auto ? 1 : 0,
                'expiresAt' => max(0, $expiresAt),
            ], ['id' => (int) $existing['id']]);
        } else {
            $db->insert('SecurityGuardWhitelist', [
                'ipRange' => $range,
                'description' => Text::cut($description, 255),
                'auto' => $auto ? 1 : 0,
                'expiresAt' => max(0, $expiresAt),
                'createdAt' => $now,
            ]);
        }
        $this->state->rebuild();
    }

    public function remove(int $id): void
    {
        if ($this->db()->delete('SecurityGuardWhitelist', ['id' => $id]) > 0) {
            $this->state->rebuild();
        }
    }

    public function all(): array
    {
        $rows = $this->db()->fetchAllAssociative('SELECT * FROM SecurityGuardWhitelist ORDER BY auto ASC, createdAt DESC');
        $out = [];
        foreach ($rows as $row) {
            $out[] = [
                'id' => (int) $row['id'],
                'ipRange' => (string) $row['ipRange'],
                'description' => $row['description'] === null ? null : (string) $row['description'],
                'auto' => (bool) $row['auto'],
                'expiresAt' => (int) $row['expiresAt'],
                'createdAt' => (int) $row['createdAt'],
            ];
        }

        return $out;
    }

    public static function matches(string $ip, string $range): bool
    {
        return IpRange::matches($ip, $range);
    }

    /**
     * Чи довірена IP за знімком стану: loopback, налаштування whitelist_ranges,
     * записи таблиці (з терміном). Без БД — для гарячого шляху.
     */
    public static function isTrusted(string $ip, array $state, int $now): bool
    {
        if (IpRange::isLoopback($ip)) {
            return true;
        }
        if (IpRange::matchesAny($ip, IpRange::parseList((string) ($state['settings']['whitelist_ranges'] ?? '')))) {
            return true;
        }
        foreach ((array) ($state['whitelist'] ?? []) as $entry) {
            $expires = (int) ($entry['expires'] ?? 0);
            if (($expires === 0 || $expires > $now) && IpRange::matches($ip, (string) ($entry['range'] ?? ''))) {
                return true;
            }
        }

        return false;
    }

    /** Чи є IP у таблиці (будь-який запис, що її покриває і ще діє). */
    public function contains(string $ip): bool
    {
        return self::isTrusted($ip, ['settings' => [], 'whitelist' => array_map(static function (array $r): array {
            return ['range' => $r['ipRange'], 'expires' => $r['expiresAt']];
        }, $this->all())], time()) && !IpRange::isLoopback($ip);
    }

    /** Видаляє прострочені записи (автодовіра). */
    public function purgeExpired(): int
    {
        $n = (int) $this->db()->executeStatement(
            'DELETE FROM SecurityGuardWhitelist WHERE expiresAt > 0 AND expiresAt < ?',
            [time()]
        );
        if ($n > 0) {
            $this->state->rebuild();
        }

        return $n;
    }

    private static function canonical(string $range): string
    {
        $range = strtolower(trim($range));
        if (strpos($range, '/') === false && !in_array(substr($range, -1), ['.', ':'], true)) {
            $ip = IpRange::normalize($range);
            if ($ip !== '') {
                return $ip;
            }
        }

        return $range;
    }

    private function db(): Connection
    {
        return $this->db ?? ($this->db = $this->app->make(Connection::class));
    }
}
