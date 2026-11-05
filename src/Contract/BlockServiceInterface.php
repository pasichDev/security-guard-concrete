<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace PasichDev\SecurityGuard\Contract;

/** Бани IP з ескалацією. Будь-яка зміна викликає StateCacheInterface::rebuild(). */
interface BlockServiceInterface
{
    /**
     * Банить IP. $duration = null — за правилами ескалації
     * (Settings 'escalation'); 0 — назавжди. Повертає рядок бану.
     */
    public function block(string $ip, string $reason, string $category, ?int $duration = null, bool $manual = false, array $context = []): array;

    public function unblock(string $ip): void;

    /** Активний бан або null. */
    public function find(string $ip): ?array;

    /** @return array{rows: array, total: int} */
    public function listActive(int $limit = 50, int $offset = 0, string $search = ''): array;

    /** @return array{rows: array, total: int} */
    public function listHistory(int $limit = 50, int $offset = 0, string $search = ''): array;

    public function countActive(): int;

    /** Видаляє прострочені бани старші за $olderThanDays (історію). */
    public function purgeExpired(int $olderThanDays = 30): int;
}
