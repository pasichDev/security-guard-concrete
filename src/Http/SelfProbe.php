<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Http;

use PasichDev\SecurityGuard\State\StateDir;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

/**
 * Підпис запитів «Перевірки безпеки» до власного сайту, щоб WAF не банив за
 * них IP самого сервера. Заголовок: "<unix-час>:<HMAC-SHA256(сіль, час)>",
 * дійсний 120 секунд. Сіль лежить у каталозі стану, ззовні недоступна.
 */
final class SelfProbe
{
    public const HEADER = 'X-Security-Guard-Probe';
    private const TTL = 120;

    public static function headerValue(?int $now = null): string
    {
        $ts = (string) ($now ?? time());

        return $ts . ':' . hash_hmac('sha256', 'probe|' . $ts, self::salt());
    }

    public static function isValid(Request $request, ?int $now = null): bool
    {
        try {
            $value = (string) $request->headers->get(self::HEADER, '');
            if (!preg_match('/^(\d{9,12}):([a-f0-9]{64})$/', $value, $m)) {
                return false;
            }
            if (abs(($now ?? time()) - (int) $m[1]) > self::TTL) {
                return false;
            }

            return hash_equals(hash_hmac('sha256', 'probe|' . $m[1], self::salt()), $m[2]);
        } catch (Throwable $e) {
            return false;
        }
    }

    private static function salt(): string
    {
        return StateDir::salt(StateDir::path());
    }
}
