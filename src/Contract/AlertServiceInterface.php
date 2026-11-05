<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace PasichDev\SecurityGuard\Contract;

/** Сповіщення: запис у SecurityGuardAlerts + лист (з тротлінгом за типом). */
interface AlertServiceInterface
{
    /** $severity: info | warning | critical */
    public function raise(string $type, string $severity, string $message, array $context = []): void;

    /** @return array{rows: array, total: int} */
    public function recent(int $limit = 20, bool $unreadOnly = false): array;

    public function markAllRead(): void;
}
