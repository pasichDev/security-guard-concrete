<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace PasichDev\SecurityGuard\Contract;

/** Поведінкові бали (таблиця SecurityGuardScores). */
interface ScoreServiceInterface
{
    /** Додає бали й повертає новий бал (з урахуванням TTL). */
    public function add(string $ip, int $points, array $events): int;

    public function reset(string $ip): void;

    /** Видаляє бали, старші за TTL (Settings 'behavior_ttl'). Повертає кількість. */
    public function purgeExpired(): int;

    /** @return array{rows: array, total: int} */
    public function list(int $limit = 50, int $offset = 0): array;
}
