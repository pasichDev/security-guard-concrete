<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\State;

/** Вибір сховища лічильників: APCu, якщо доступний, інакше файли в теці стану. */
final class Counters
{
    /** @var CounterStore|null */
    private static $store;

    public static function store(): CounterStore
    {
        if (self::$store === null) {
            if (ApcuCounterStore::available()) {
                self::$store = new ApcuCounterStore(substr(md5(StateDir::path()), 0, 8) . ':');
            } else {
                $dir = StateDir::path();
                self::$store = new FileCounterStore($dir . '/counters', StateDir::salt($dir));
            }
        }

        return self::$store;
    }

    /** Для тестів. */
    public static function use(?CounterStore $store): void
    {
        self::$store = $store;
    }
}
