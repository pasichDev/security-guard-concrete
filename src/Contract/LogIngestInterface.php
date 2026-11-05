<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace PasichDev\SecurityGuard\Contract;

/** Читання логів хостингу й оновлення SecurityGuardDailyStats. */
interface LogIngestInterface
{
    /**
     * Дочитує нові рядки з усіх джерел (не довше $timeBudget секунд, 0 = без ліміту)
     * і перераховує торкнуті дні.
     * @return array{files: int, lines: int, days: string[], finished: bool, errors: string[]}
     */
    public function ingest(int $timeBudget = 0): array;

    /** Знайдені файли логів (для сторінки налаштувань/трафіку): шлях => розмір. */
    public function discoverSources(): array;
}
