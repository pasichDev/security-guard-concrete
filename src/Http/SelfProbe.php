<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Http;

use PasichDev\SecurityGuard\State\CounterStore;
use PasichDev\SecurityGuard\State\StateDir;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

/**
 * Підпис запитів «Перевірки безпеки» до власного сайту, щоб WAF не банив за
 * них IP самого сервера. Заголовок: "<unix-час>:<nonce>:<HMAC>", де HMAC =
 * HMAC-SHA256(сіль, "probe|МЕТОД|шлях|час|nonce"). Дійсний 30 секунд і лише
 * один раз (nonce запам'ятовується). Шлях «*» — підпис без прив'язки до
 * адреси (для сумісності); краще передавати адресу в headerValue().
 */
final class SelfProbe
{
    public const HEADER = 'X-Security-Guard-Probe';
    private const TTL = 30;

    public static function headerValue(?int $now = null, string $method = 'GET', string $url = ''): string
    {
        $ts = (string) ($now ?? time());
        $nonce = bin2hex(random_bytes(8));
        $path = $url === '' ? '*' : self::pathOf($url);

        return $ts . ':' . $nonce . ':' . self::sign(strtoupper($method), $path, $ts, $nonce);
    }

    /** Підпис, прив'язаний до методу й адреси. */
    public static function headerFor(string $method, string $url, ?int $now = null): string
    {
        return self::headerValue($now, $method, $url);
    }

    public static function isValid(Request $request, ?int $now = null, ?CounterStore $nonces = null): bool
    {
        try {
            $value = (string) $request->headers->get(self::HEADER, '');
            if (!preg_match('/^(\d{9,12}):([a-f0-9]{16}):([a-f0-9]{64})$/', $value, $m)) {
                return false;
            }
            if (abs(($now ?? time()) - (int) $m[1]) > self::TTL) {
                return false;
            }
            $method = strtoupper($request->getMethod());
            $path = self::pathOf((string) $request->getRequestUri());
            $ok = hash_equals(self::sign($method, $path, $m[1], $m[2]), $m[3])
                || hash_equals(self::sign($method, '*', $m[1], $m[2]), $m[3]);
            if (!$ok) {
                return false;
            }
            // Одноразовий: повтор того самого заголовка не пропускається.
            return $nonces === null || $nonces->add('probe:' . $m[2], 1, self::TTL * 2);
        } catch (Throwable $e) {
            return false;
        }
    }

    private static function sign(string $method, string $path, string $ts, string $nonce): string
    {
        return hash_hmac('sha256', 'probe|' . $method . '|' . $path . '|' . $ts . '|' . $nonce, StateDir::salt(StateDir::path()));
    }

    private static function pathOf(string $url): string
    {
        $path = parse_url($url, PHP_URL_PATH);

        return is_string($path) && $path !== '' ? $path : '/';
    }
}
