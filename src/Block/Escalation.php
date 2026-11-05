<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Block;

/**
 * Ескалація банів: перший бан — block_duration, далі кроки з налаштування
 * escalation (1 год → 24 год → 7 днів → 30 днів), не далі останнього кроку.
 * «Повторне» порушення — якщо попередній бан ще діє або закінчився не
 * раніше ніж DECAY секунд тому; інакше рахунок починається спочатку.
 */
final class Escalation
{
    public const DECAY = 2592000; // 30 днів

    /** @return int[] кроки в секундах, перший = $firstDuration (якщо > 0) */
    public static function steps(array $escalation, int $firstDuration): array
    {
        $steps = array_values(array_filter(array_map('intval', $escalation), static function (int $s): bool {
            return $s > 0;
        }));
        if ($firstDuration > 0) {
            if ($steps === []) {
                $steps = [$firstDuration];
            } else {
                $steps[0] = $firstDuration;
            }
        }

        return $steps === [] ? [3600] : $steps;
    }

    /**
     * Наступний рівень і тривалість.
     *
     * @param array|null $previous рядок SecurityGuardBlocks (escalationLevel, blockedUntil, permanent) або null
     * @return array{level: int, duration: int}
     */
    public static function next(array $steps, ?array $previous, int $now, int $decay = self::DECAY): array
    {
        $level = 0;
        if ($previous !== null) {
            $prevUntil = (int) ($previous['blockedUntil'] ?? 0);
            $recent = !empty($previous['permanent']) || $prevUntil >= $now - $decay;
            if ($recent) {
                $level = (int) ($previous['escalationLevel'] ?? 0) + 1;
            }
        }
        $level = min(max(0, $level), count($steps) - 1);

        return ['level' => $level, 'duration' => $steps[$level]];
    }

    /**
     * Кінцевий час бану: ніколи не скорочуємо чинний довший бан.
     * Повертає [until, permanent]. $duration 0 — назавжди.
     */
    public static function until(int $duration, ?array $previous, int $now): array
    {
        if ($duration === 0) {
            return [0, true];
        }
        $until = $now + $duration;
        if ($previous !== null) {
            if (!empty($previous['permanent'])) {
                return [0, true];
            }
            $until = max($until, (int) ($previous['blockedUntil'] ?? 0));
        }

        return [$until, false];
    }
}
