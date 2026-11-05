<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Waf;

use Concrete\Core\Application\Application;
use Concrete\Core\Database\Connection\Connection;
use PasichDev\SecurityGuard\Contract\HoneypotRepositoryInterface;
use PasichDev\SecurityGuard\Contract\StateCacheInterface;
use PasichDev\SecurityGuard\Ip\IpRange;
use PasichDev\SecurityGuard\Rules\HoneypotList;

final class HoneypotRepository implements HoneypotRepositoryInterface
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

    public function record(string $ip, string $url, string $userAgent): void
    {
        $this->db()->insert('SecurityGuardHoneypotHits', [
            'ip' => IpRange::normalize($ip) ?: Text::cut($ip, 45),
            'url' => Text::url($url, 500),
            'userAgent' => Text::cut($userAgent, 255),
            'createdAt' => time(),
        ]);
    }

    public function list(int $limit = 50, int $offset = 0): array
    {
        $db = $this->db();
        $total = (int) $db->fetchOne('SELECT COUNT(*) FROM SecurityGuardHoneypotHits');
        $rows = $db->fetchAllAssociative(
            'SELECT * FROM SecurityGuardHoneypotHits ORDER BY id DESC LIMIT ' . max(1, $limit) . ' OFFSET ' . max(0, $offset)
        );
        foreach ($rows as &$row) {
            $row['id'] = (int) $row['id'];
            $row['createdAt'] = (int) $row['createdAt'];
        }
        unset($row);

        return ['rows' => $rows, 'total' => $total];
    }

    public function trapUrls(): array
    {
        $settings = $this->state->load()['settings'];

        return array_values(array_unique(array_merge(
            HoneypotList::BUILTIN,
            HoneypotList::parseCustom((string) ($settings['honeypot_custom_urls'] ?? ''))
        )));
    }

    public function purgeOlderThan(int $days): int
    {
        return (int) $this->db()->executeStatement(
            'DELETE FROM SecurityGuardHoneypotHits WHERE createdAt < ?',
            [time() - max(1, $days) * 86400]
        );
    }

    private function db(): Connection
    {
        return $this->db ?? ($this->db = $this->app->make(Connection::class));
    }
}
