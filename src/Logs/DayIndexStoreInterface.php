<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/**
 * Покажчик «день → діапазон байтів» для кожного файлу логу, щоб перерахунок дня
 * читав лише потрібну частину файлу, а не весь місячний архів.
 * Формат: path => ['from0' => bool (покажчик будувався з початку файлу), 'days' => [день => [початок, кінець]]],
 * зсуви — у розпакованому потоці для .gz.
 */
interface DayIndexStoreInterface
{
    public function getDayIndex(): array;

    public function setDayIndex(array $index): void;
}
