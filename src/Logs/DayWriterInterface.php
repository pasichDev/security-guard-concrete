<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/** Запис агрегату дня (повністю перезаписує рядок дня). */
interface DayWriterInterface
{
    /** @param array $row колонки SecurityGuardDailyStats + 'breakdown' масивом */
    public function saveDay(string $day, array $row): void;
}
