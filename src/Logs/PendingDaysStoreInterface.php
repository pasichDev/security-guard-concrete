<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/**
 * Черга днів, які треба перерахувати. Зберігається між запусками, щоб запуск,
 * обірваний лімітом часу, не загубив днів, нові рядки яких уже прочитано.
 */
interface PendingDaysStoreInterface
{
    /** @return string[] YYYY-MM-DD */
    public function get(): array;

    /** @param string[] $days */
    public function set(array $days): void;
}
