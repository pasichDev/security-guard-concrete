<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\State;

/**
 * Короткоживучі лічильники й прапорці гарячого шляху (ліміт частоти,
 * сплески, тротлінг записів). Вікно фіксоване: TTL задається при першому
 * записі ключа й не продовжується наступними increment().
 */
interface CounterStore
{
    /** Додає $by і повертає нове значення. Новий/прострочений ключ стартує з 0 і живе $ttl секунд. */
    public function increment(string $key, int $by, int $ttl): int;

    /** @return mixed|null null — немає або прострочено */
    public function get(string $key);

    /** @param mixed $value */
    public function set(string $key, $value, int $ttl): void;

    /** Записує, лише якщо ключа ще немає. true — записали (подія «вперше за $ttl»). */
    public function add(string $key, $value, int $ttl): bool;

    public function delete(string $key): void;

    /** Видаляє прострочене (для файлового сховища). Повертає кількість. */
    public function purgeExpired(int $limit = 5000): int;

    public function name(): string;
}
