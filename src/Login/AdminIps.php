<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Login;

use PasichDev\SecurityGuard\State\StateDir;

/**
 * Хто з адміністраторів входив із якої IP (для автодовіри). Маленький файл
 * у теці стану; читається лише на POST форми входу з автодовіреної IP —
 * щоб невдалі спроби з ЧУЖИМИ логінами з тієї самої мережі (NAT) рахувались.
 */
final class AdminIps
{
    private const FILE = 'admin_ips.php';
    private const SEPARATOR = "__halt_compiler();\n";
    private const MAX_IPS = 200;

    /** @var string|null */
    private static $dir;

    public static function useDir(?string $dir): void
    {
        self::$dir = $dir;
    }

    /** @return string[] логіни (нижній регістр), що входили з цієї IP і ще не прострочені */
    public static function usersFor(string $ip, ?int $now = null): array
    {
        $now = $now ?? time();
        $out = [];
        foreach ((array) (self::read()[$ip] ?? []) as $user => $until) {
            if ((int) $until > $now) {
                $out[] = (string) $user;
            }
        }

        return $out;
    }

    public static function remember(string $ip, string $user, int $until): void
    {
        $data = self::read();
        $now = time();
        foreach ($data as $k => $users) {
            $data[$k] = array_filter((array) $users, static function ($u) use ($now): bool {
                return (int) $u > $now;
            });
            if ($data[$k] === []) {
                unset($data[$k]);
            }
        }
        $data[$ip][strtolower($user)] = $until;
        if (count($data) > self::MAX_IPS) {
            $data = array_slice($data, -self::MAX_IPS, null, true);
        }
        $dir = self::dir();
        StateDir::prepare($dir);
        $file = $dir . '/' . self::FILE;
        $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
        $php = "<?php\ndefined('C5_EXECUTE') or die('Access Denied.');\n" . self::SEPARATOR . json_encode($data) . "\n";
        if (@file_put_contents($tmp, $php, LOCK_EX) !== false && !@rename($tmp, $file)) {
            @unlink($tmp);
        }
    }

    private static function read(): array
    {
        $raw = @file_get_contents(self::dir() . '/' . self::FILE);
        if (!is_string($raw) || ($pos = strpos($raw, self::SEPARATOR)) === false) {
            return [];
        }
        $data = json_decode(substr($raw, $pos + strlen(self::SEPARATOR)), true);

        return is_array($data) ? $data : [];
    }

    private static function dir(): string
    {
        return self::$dir ?? StateDir::path();
    }
}
