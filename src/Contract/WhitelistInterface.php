<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace PasichDev\SecurityGuard\Contract;

/**
 * Білий список: точний IP, префікс із крапкою ("203.0.113.") або CIDR (IPv4/IPv6).
 * Плюс діапазони з налаштування whitelist_ranges. Loopback довірений завжди.
 */
interface WhitelistInterface
{
    public function add(string $range, string $description = '', int $expiresAt = 0, bool $auto = false): void;

    public function remove(int $id): void;

    /** @return array<int, array{id:int, ipRange:string, description:?string, auto:bool, expiresAt:int, createdAt:int}> */
    public function all(): array;

    /** Чисто обчислювальна перевірка за переданим списком (для гарячого шляху, без БД). */
    public static function matches(string $ip, string $range): bool;
}
