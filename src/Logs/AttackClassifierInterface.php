<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/** Класифікація рядка логу як атаки. */
interface AttackClassifierInterface
{
    /**
     * strength: 'strong' — атака; 'weak' — лише схоже на неї (звичайний текст); відсутній ключ = strong.
     * @return array{rule:string, category:string, strength?:string}|null
     */
    public function classify(string $method, string $uri, string $userAgent): ?array;
}
