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

    /**
     * Адреса без секретів: прибирає параметр sg_pass (аварійний обхід) з
     * будь-яким значенням і в будь-якому написанні, яке PHP зведе до sg_pass
     * (регістр, %-кодування, «.», пробіл, «[»). Токен ніде не зберігаємо.
     */
    public static function cleanUrl(string $url): string
    {
        $q = strpos($url, '?');
        if ($q === false) {
            return $url;
        }
        $hash = strpos($url, '#', $q);
        $fragment = $hash === false ? '' : substr($url, $hash);
        $query = $hash === false ? substr($url, $q + 1) : substr($url, $q + 1, $hash - $q - 1);
        $kept = [];
        foreach (explode('&', $query) as $part) {
            $eq = strpos($part, '=');
            $name = strtolower(trim(rawurldecode(str_replace('+', ' ', $eq === false ? $part : substr($part, 0, $eq)))));
            $bracket = strpos($name, '[');
            if ($bracket !== false) {
                $name = substr($name, 0, $bracket); // sg_pass[]=… → масив sg_pass
            }
            $name = strtr($name, ['.' => '_', ' ' => '_']);
            if ($name === 'sg_pass') {
                continue;
            }
            $kept[] = $part;
        }
        $base = substr($url, 0, $q);

        return ($kept === [] ? $base : $base . '?' . implode('&', $kept)) . $fragment;
    }

    /** cleanUrl + cut — для всього, що пишеться в базу чи лист. */
    public static function url(string $url, int $max): string
    {
        return self::cut(self::cleanUrl($url), $max);
    }
}
