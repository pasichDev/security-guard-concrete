<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/** Класифікація рядка логу як атаки. */
interface AttackClassifierInterface
{
    /** @return array{rule:string, category:string}|null */
    public function classify(string $method, string $uri, string $userAgent): ?array;
}
