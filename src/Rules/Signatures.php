<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Rules;

/**
 * Сигнатури, спільні для query/тіла і значень cookie: PHP object injection
 * (unserialize), XXE, SSRF на внутрішні адреси й небезпечні схеми.
 */
final class Signatures
{
    /** O:8:"stdClass":1:{ / C:11:"ArrayObject":… — серіалізований об'єкт PHP. */
    public const PHP_OBJECT = '#(?:^|[^a-z0-9_])[oc]:\+?\d+:"[^"]{1,255}":\d+:\{#i';

    public const XXE = '#<!doctype[^>]*\[|<!entity\b#i';

    /** Схема + внутрішній/службовий хост (метадані хмар, loopback, приватні мережі) або небезпечна схема. */
    public const SSRF = '~(?:(?:https?|ftp|ldap|tftp)://(?:[^/@\s&"\']*@)?\[?(?:169\.254\.\d{1,3}\.\d{1,3}|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200|localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|0x7f[0-9a-f.]*|2130706433|017700000001|::1\]?|::ffff:127\.|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?=[:/?\]#&\s"\']|$)|\b(?:gopher|dict|file|jar|netdoc)://)~i';

    /** Перевіряє рядок cookie («name=value» по рядку) лише цими сигнатурами. */
    public static function classifyCookies(string $cookies): ?array
    {
        if ($cookies === '') {
            return null;
        }
        $value = Paths::decode($cookies, true);
        if (preg_match(self::PHP_OBJECT, $value)) {
            return ['rule' => 'PHP_OBJECT_INJECTION', 'category' => 'injection'];
        }
        if (preg_match(self::XXE, $value)) {
            return ['rule' => 'XXE', 'category' => 'injection'];
        }
        if (preg_match(self::SSRF, $value)) {
            return ['rule' => 'SSRF_TARGET', 'category' => 'injection'];
        }

        return null;
    }
}
