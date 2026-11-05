<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace PasichDev\SecurityGuard\Contract;

/**
 * Знімок стану для гарячого шляху: один PHP-файл (return [...]) у
 * DIR_FILES_UPLOADED_STANDARD . '/security_guard/state.php' (або іншому
 * каталозі з правом запису поза веб-доступом, якщо такий є). Читання —
 * include без запитів до БД. Перебудова — атомарно (tmp + rename) після
 * будь-якої зміни банів, білого списку чи налаштувань.
 *
 * Формат масиву:
 *  'settings'  => Settings::all(),
 *  'blocks'    => [ip => ['until' => int (0 = назавжди), 'reason' => string, 'category' => string]],
 *  'whitelist' => [['range' => string, 'expires' => int]],
 *  'builtAt'   => int
 */
interface StateCacheInterface
{
    public function load(): array;

    public function rebuild(): void;

    public function clear(): void;
}
