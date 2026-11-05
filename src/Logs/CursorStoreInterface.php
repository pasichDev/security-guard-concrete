<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/** Курсори файлів логів (таблиця SecurityGuardLogCursors). */
interface CursorStoreInterface
{
    /** @return array<string, array{path:string, fingerprint:string, size:int, position:int, completed:bool, updatedAt:int}> */
    public function load(): array;

    /** @param array<string, array> $cursors path => рядок */
    public function save(array $cursors): void;
}
