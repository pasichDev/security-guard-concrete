<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Waf;

use Concrete\Core\Application\Application;
use Concrete\Core\Database\Connection\Connection;
use PasichDev\SecurityGuard\Contract\AlertServiceInterface;
use PasichDev\SecurityGuard\Contract\BlockServiceInterface;
use PasichDev\SecurityGuard\Contract\EventLogInterface;
use PasichDev\SecurityGuard\Contract\HoneypotRepositoryInterface;
use PasichDev\SecurityGuard\Contract\ScoreServiceInterface;
use PasichDev\SecurityGuard\Contract\StateCacheInterface;
use PasichDev\SecurityGuard\Contract\WhitelistInterface;
use PasichDev\SecurityGuard\State\Counters;
use Throwable;

/**
 * Очищення старих даних таблиць WAF. Викликається з CLI-команди і
 * (не частіше разу на годину) після відповіді на звичайний запит.
 */
final class Maintenance
{
    /** Історію банів тримаємо стільки ж, скільки діє ескалація. */
    private const BLOCK_HISTORY_DAYS = 30;
    private const BOT_CACHE_DAYS = 7;

    /** @var Application */
    private $app;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    /** @return array<string, int|string> скільки видалено по кожній частині (або текст помилки) */
    public function run(): array
    {
        $settings = $this->app->make(StateCacheInterface::class)->load()['settings'];
        $retention = max(1, (int) ($settings['event_retention_days'] ?? 90));
        $tasks = [
            'events' => function () use ($retention): int {
                return $this->app->make(EventLogInterface::class)->purgeOlderThan($retention);
            },
            'blocks' => function (): int {
                return $this->app->make(BlockServiceInterface::class)->purgeExpired(self::BLOCK_HISTORY_DAYS);
            },
            'whitelist' => function (): int {
                $wl = $this->app->make(WhitelistInterface::class);

                return method_exists($wl, 'purgeExpired') ? (int) $wl->purgeExpired() : 0;
            },
            'scores' => function (): int {
                $sc = $this->app->make(ScoreServiceInterface::class);

                return method_exists($sc, 'purgeExpired') ? (int) $sc->purgeExpired() : 0;
            },
            'honeypot' => function () use ($retention): int {
                $hp = $this->app->make(HoneypotRepositoryInterface::class);

                return method_exists($hp, 'purgeOlderThan') ? (int) $hp->purgeOlderThan($retention) : 0;
            },
            'alerts' => function () use ($retention): int {
                $al = $this->app->make(AlertServiceInterface::class);

                return method_exists($al, 'purgeOlderThan') ? (int) $al->purgeOlderThan($retention) : 0;
            },
            'botCache' => function (): int {
                return (int) $this->app->make(Connection::class)->executeStatement(
                    'DELETE FROM SecurityGuardBotCache WHERE verifiedAt < ?',
                    [time() - self::BOT_CACHE_DAYS * 86400]
                );
            },
            'counters' => function (): int {
                return Counters::store()->purgeExpired();
            },
        ];
        $out = [];
        foreach ($tasks as $name => $task) {
            try {
                $out[$name] = $task();
            } catch (Throwable $e) {
                $out[$name] = 'error: ' . $e->getMessage();
            }
        }

        return $out;
    }
}
