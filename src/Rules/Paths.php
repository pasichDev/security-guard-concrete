<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Rules;

/**
 * Розбір і нормалізація шляху запиту. Чистий PHP — спільний для WAF і
 * розбору логів хостингу.
 */
final class Paths
{
    /**
     * Службові шляхи Concrete: дашборд, /ccm/, вхід. Тут редактори постять
     * HTML з <script>, ../ тощо, тому евристики вмісту сюди не застосовуються.
     */
    public static function isTrusted(string $path): bool
    {
        return (bool) preg_match('#^/(?:index\.php/)?(?:dashboard|ccm|login)(?:/|$)#i', $path);
    }

    /** Шлях входу ядра, на який POST-ять форму пароля. */
    public static function isLoginAuthenticate(string $path): bool
    {
        return (bool) preg_match('#^/(?:index\.php/)?login/authenticate/concrete/?$#i', $path);
    }

    /** [шлях, query] із рядка запиту (шлях без схеми/хоста). */
    public static function split(string $uri): array
    {
        // Повний URL (рядок логу з абсолютною адресою) → лише шлях.
        if (preg_match('#^[a-z][a-z0-9+.-]*://[^/]*(/.*)?$#i', $uri, $m)) {
            $uri = $m[1] ?? '/';
        }
        $pos = strpos($uri, '?');
        if ($pos === false) {
            return [$uri === '' ? '/' : $uri, ''];
        }
        $path = substr($uri, 0, $pos);

        return [$path === '' ? '/' : $path, (string) substr($uri, $pos + 1)];
    }

    /** Декодує %XX до двох разів (подвійне кодування — типовий обхід фільтрів). */
    public static function decode(string $value, bool $plusIsSpace = false): string
    {
        for ($i = 0; $i < 2; $i++) {
            if (strpos($value, '%') === false && (!$plusIsSpace || strpos($value, '+') === false)) {
                break;
            }
            $decoded = $plusIsSpace ? urldecode($value) : rawurldecode($value);
            if ($decoded === $value) {
                break;
            }
            $value = $decoded;
            $plusIsSpace = false; // «+» після першого проходу — уже літерал
        }

        return $value;
    }

    /** Нормалізований шлях для порівняння: декодований, у нижньому регістрі, без повторних слешів. */
    public static function normalize(string $path): string
    {
        $path = strtolower(self::decode($path));
        $path = str_replace('\\', '/', $path);
        $path = (string) preg_replace('#/{2,}#', '/', $path);

        return $path === '' ? '/' : $path;
    }
}
