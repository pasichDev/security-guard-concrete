<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Waf;

/** Підготовка рядків від відвідувача до запису в базу. */
final class Text
{
    /** Валідний UTF-8 без керівних символів, обрізаний до $max символів. */
    public static function cut(string $value, int $max): string
    {
        if ($value === '') {
            return '';
        }
        if (!mb_check_encoding($value, 'UTF-8')) {
            $value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        }
        $value = (string) preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value);

        return mb_substr($value, 0, $max, 'UTF-8');
    }
}
