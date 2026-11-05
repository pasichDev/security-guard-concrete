<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Update;

/** Збережені діапазони ботів (таблиця SecurityGuardBotRanges). */
interface BotRangeStoreInterface
{
    /** @return array<string, string[]> бот => CIDR */
    public function rangesByBot(): array;

    /** @return array<string, array{count:int, source:string, fetchedAt:int}> */
    public function meta(): array;

    /** @param string[] $ranges */
    public function save(string $bot, array $ranges, string $source, int $fetchedAt): void;
}
