<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\State;

/** Лічильники в спільній пам'яті APCu (найдешевший варіант). */
final class ApcuCounterStore implements CounterStore
{
    private const PREFIX = 'security_guard:';

    /** @var string */
    private $prefix;

    public function __construct(string $namespace = '')
    {
        $this->prefix = self::PREFIX . $namespace;
    }

    public static function available(): bool
    {
        return extension_loaded('apcu') && function_exists('apcu_enabled') && apcu_enabled();
    }

    public function increment(string $key, int $by, int $ttl): int
    {
        $k = $this->prefix . $key;
        apcu_add($k, 0, max(1, $ttl));
        $value = apcu_inc($k, $by, $success);
        if ($success && is_int($value)) {
            return $value;
        }
        // Ключ витіснили між add та inc — починаємо заново.
        apcu_store($k, $by, max(1, $ttl));

        return $by;
    }

    public function get(string $key)
    {
        $value = apcu_fetch($this->prefix . $key, $success);

        return $success ? $value : null;
    }

    public function set(string $key, $value, int $ttl): void
    {
        apcu_store($this->prefix . $key, $value, max(1, $ttl));
    }

    public function add(string $key, $value, int $ttl): bool
    {
        return (bool) apcu_add($this->prefix . $key, $value, max(1, $ttl));
    }

    public function delete(string $key): void
    {
        apcu_delete($this->prefix . $key);
    }

    public function purgeExpired(int $limit = 5000): int
    {
        return 0; // APCu сам прибирає прострочене
    }

    public function name(): string
    {
        return 'apcu';
    }
}
