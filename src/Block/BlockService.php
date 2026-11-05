<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Block;

use Concrete\Core\Application\Application;
use Concrete\Core\Database\Connection\Connection;
use PasichDev\SecurityGuard\Contract\BlockServiceInterface;
use PasichDev\SecurityGuard\Contract\StateCacheInterface;
use PasichDev\SecurityGuard\Geo\CountryGuesser;
use PasichDev\SecurityGuard\Ip\IpRange;
use PasichDev\SecurityGuard\State\Counters;
use PasichDev\SecurityGuard\State\FileStateCache;
use PasichDev\SecurityGuard\Waf\Text;

/** Бани IP (таблиця SecurityGuardBlocks): один рядок на IP, з історією ескалації. */
final class BlockService implements BlockServiceInterface
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

    public function block(string $ip, string $reason, string $category, ?int $duration = null, bool $manual = false, array $context = []): array
    {
        $subject = self::subject($ip);
        if ($subject === '') {
            throw new \InvalidArgumentException('Invalid IP address');
        }
        $now = time();
        $settings = $this->state->load()['settings'];
        $db = $this->db();
        $previous = $db->fetchAssociative('SELECT * FROM SecurityGuardBlocks WHERE ip = ?', [$subject]) ?: null;
        $active = $previous !== null && ((int) $previous['permanent'] || (int) $previous['blockedUntil'] > $now);

        // Автоматичний бан поверх чинного — нічого не міняємо (ідемпотентно):
        // паралельні запити атакувальника не подовжують і не ескалюють бан.
        if ($active && !$manual) {
            Counters::store()->set('ban:' . $subject, ['until' => (int) $previous['permanent'] ? 0 : (int) $previous['blockedUntil'], 'reason' => (string) $previous['reason'], 'category' => (string) $previous['category'], 'at' => $now], self::banTtl($previous, $now));

            return $this->cast($previous);
        }

        if ($duration === null) {
            $steps = Escalation::steps((array) ($settings['escalation'] ?? []), (int) ($settings['block_duration'] ?? 3600));
            $next = Escalation::next($steps, $previous, $now);
            $level = $next['level'];
            $duration = $next['duration'];
        } else {
            $level = $previous !== null ? (int) $previous['escalationLevel'] : 0;
        }
        // Ручна дія адміністратора задає термін точно; автоматика не скорочує чинний.
        [$until, $permanent] = $manual
            ? ($duration <= 0 ? [0, true] : [$now + $duration, false])
            : Escalation::until(max(0, $duration), $active ? $previous : null, $now);

        $row = [
            'reason' => Text::cut($reason, 64),
            'category' => Text::cut($category, 32),
            'blockedUntil' => $until,
            'permanent' => $permanent ? 1 : 0,
            'escalationLevel' => $level,
            'manual' => $manual ? 1 : 0,
            'lastUrl' => Text::url((string) ($context['url'] ?? ''), 500),
            'lastUserAgent' => Text::cut((string) ($context['userAgent'] ?? ''), 255),
            'country' => Text::cut((string) ($context['country'] ?? CountryGuesser::guess(strpos($subject, '/') === false ? $subject : $ip)), 2),
            'updatedAt' => $now,
        ];
        if ($previous !== null) {
            $row['attempts'] = (int) $previous['attempts'] + 1;
            $db->update('SecurityGuardBlocks', $row, ['ip' => $subject]);
        } else {
            $row += ['ip' => $subject, 'attempts' => 1, 'createdAt' => $now];
            $db->insert('SecurityGuardBlocks', $row);
        }
        // Гарячий шлях бачить бан одразу через лічильник; файл стану — з дебаунсом.
        Counters::store()->set('ban:' . $subject, ['until' => $permanent ? 0 : $until, 'reason' => $row['reason'], 'category' => $row['category'], 'manual' => $manual, 'at' => $now], $permanent ? 86400 : max(1, $until - $now));
        if ($manual || !$this->state instanceof FileStateCache) {
            $this->state->rebuild();
        } else {
            $this->state->rebuildDebounced();
        }

        return $this->cast($db->fetchAssociative('SELECT * FROM SecurityGuardBlocks WHERE ip = ?', [$subject]) ?: ($row + ['ip' => $subject]));
    }

    public function unblock(string $ip): void
    {
        $subject = self::subject($ip);
        if ($subject === '') {
            return;
        }
        $now = time();
        $keys = array_values(array_unique([$subject, IpRange::normalize($ip) ?: $subject]));
        $affected = 0;
        foreach ($keys as $key) {
            // Рядок лишається як історія (для ескалації та вкладки «Історія»).
            $affected += (int) $this->db()->executeStatement(
                'UPDATE SecurityGuardBlocks SET blockedUntil = ?, permanent = 0, updatedAt = ? WHERE ip = ? AND (permanent = 1 OR blockedUntil > ?)',
                [$now - 1, $now, $key, $now]
            );
            Counters::store()->delete('ban:' . $key);
        }
        $blocks = $this->state->load()['blocks'];
        if ($affected > 0 || isset($blocks[$subject]) || isset($blocks[$keys[1] ?? $subject])) {
            $this->state->rebuild();
        }
    }

    /** Ключ бану: IPv4 як є, IPv6 — мережа /64. Порожній рядок — невалідна адреса. */
    public static function subject(string $ip): string
    {
        return IpRange::subject($ip);
    }

    private static function banTtl(array $row, int $now): int
    {
        return (int) $row['permanent'] ? 86400 : max(1, (int) $row['blockedUntil'] - $now);
    }

    public function find(string $ip): ?array
    {
        $ip = self::subject($ip);
        if ($ip === '') {
            return null;
        }
        $row = $this->db()->fetchAssociative(
            'SELECT * FROM SecurityGuardBlocks WHERE ip = ? AND (permanent = 1 OR blockedUntil > ?)',
            [$ip, time()]
        );

        return $row ? $this->cast($row) : null;
    }

    public function listActive(int $limit = 50, int $offset = 0, string $search = ''): array
    {
        return $this->listWhere('(permanent = 1 OR blockedUntil > ?)', [time()], $limit, $offset, $search);
    }

    public function listHistory(int $limit = 50, int $offset = 0, string $search = ''): array
    {
        return $this->listWhere('(permanent = 0 AND blockedUntil <= ?)', [time()], $limit, $offset, $search);
    }

    public function countActive(): int
    {
        return (int) $this->db()->fetchOne(
            'SELECT COUNT(*) FROM SecurityGuardBlocks WHERE permanent = 1 OR blockedUntil > ?',
            [time()]
        );
    }

    public function purgeExpired(int $olderThanDays = 30): int
    {
        $cutoff = time() - max(0, $olderThanDays) * 86400;

        return (int) $this->db()->executeStatement(
            'DELETE FROM SecurityGuardBlocks WHERE permanent = 0 AND blockedUntil < ?',
            [$cutoff]
        );
    }

    /**
     * Дописує спроби забаненої IP (лічильник накопичується в пам'яті й
     * скидається в базу не частіше разу на хвилину). Поза контрактом.
     */
    public function recordAttempts(string $ip, int $count): void
    {
        if ($count <= 0) {
            return;
        }
        $this->db()->executeStatement(
            'UPDATE SecurityGuardBlocks SET attempts = attempts + ?, updatedAt = ? WHERE ip = ?',
            [$count, time(), self::subject($ip)]
        );
    }

    private function listWhere(string $where, array $params, int $limit, int $offset, string $search): array
    {
        $search = trim($search);
        if ($search !== '') {
            $like = '%' . addcslashes($search, '%_\\') . '%';
            $where .= ' AND (ip LIKE ? OR reason LIKE ? OR category LIKE ? OR lastUrl LIKE ?)';
            array_push($params, $like, $like, $like, $like);
        }
        $db = $this->db();
        $total = (int) $db->fetchOne('SELECT COUNT(*) FROM SecurityGuardBlocks WHERE ' . $where, $params);
        $rows = $db->fetchAllAssociative(
            'SELECT * FROM SecurityGuardBlocks WHERE ' . $where . ' ORDER BY updatedAt DESC, id DESC LIMIT ' . max(1, $limit) . ' OFFSET ' . max(0, $offset),
            $params
        );

        return ['rows' => array_map([$this, 'cast'], $rows), 'total' => $total];
    }

    private function cast(array $row): array
    {
        foreach (['id', 'blockedUntil', 'escalationLevel', 'attempts', 'createdAt', 'updatedAt'] as $k) {
            if (isset($row[$k])) {
                $row[$k] = (int) $row[$k];
            }
        }
        foreach (['permanent', 'manual'] as $k) {
            if (isset($row[$k])) {
                $row[$k] = (bool) $row[$k];
            }
        }

        return $row;
    }

    private function db(): Connection
    {
        return $this->db ?? ($this->db = $this->app->make(Connection::class));
    }
}
