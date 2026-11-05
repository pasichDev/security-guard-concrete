<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace PasichDev\SecurityGuard\Contract;

/** Агрегати з логів хостингу (таблиця SecurityGuardDailyStats). */
interface StatsRepositoryInterface
{
    /**
     * Дні в діапазоні включно, відсортовані за датою. Кожен рядок — колонки
     * таблиці + 'breakdown' уже розкодований у масив.
     * @return array<int, array>
     */
    public function getDays(string $fromDay, string $toDay): array;

    /** Підсумок діапазону: суми колонок + унікальні attackIps/uniqueIps за діапазон + злиті breakdown. */
    public function summarize(string $fromDay, string $toDay): array;

    public function lastIngestAt(): int;
}
