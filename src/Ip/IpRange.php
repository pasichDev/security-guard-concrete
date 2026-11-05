<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Ip;

/**
 * Порівняння IP з діапазонами без залежностей. Формати діапазону:
 *  - точний IP: 203.0.113.7, 2001:db8::1;
 *  - префікс, що закінчується на «.» або «:»: 203.0.113. / 2001:db8:;
 *  - CIDR: 203.0.113.0/24, 2001:db8::/32.
 * Будь-що інше — точний збіг, тож 1.2.3.1 не збігається з 1.2.3.10.
 */
final class IpRange
{
    /** Канонічний запис IP або '' для невалідного. ::ffff:1.2.3.4 → 1.2.3.4. */
    public static function normalize(string $ip): string
    {
        $ip = trim($ip);
        if ($ip === '') {
            return '';
        }
        // [::1]:8080 / 1.2.3.4:80 / fe80::1%eth0
        if ($ip[0] === '[' && ($end = strpos($ip, ']')) !== false) {
            $ip = substr($ip, 1, $end - 1);
        } elseif (substr_count($ip, ':') === 1 && strpos($ip, '.') !== false) {
            $ip = substr($ip, 0, (int) strpos($ip, ':'));
        }
        if (($pct = strpos($ip, '%')) !== false) {
            $ip = substr($ip, 0, $pct);
        }
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return '';
        }
        if (strlen($bin) === 16 && strncmp($bin, str_repeat("\0", 10) . "\xff\xff", 12) === 0) {
            $bin = substr($bin, 12);
        }
        $out = inet_ntop($bin);

        return $out === false ? '' : strtolower($out);
    }

    /**
     * Ключ «суб'єкта» для лічильників, балів і банів: IPv4 — сама адреса,
     * IPv6 — мережа /64 («2001:db8:1:2::/64»), бо один клієнт IPv6 зазвичай
     * має цілу /64 і міняє адреси всередині неї. Вже готовий /64 повертається як є.
     */
    public static function subject(string $ip): string
    {
        $ip = trim($ip);
        if (substr($ip, -3) === '/64' && strpos($ip, ':') !== false) {
            $net = self::normalize(substr($ip, 0, -3));

            return $net === '' ? '' : self::subject($net);
        }
        $ip = self::normalize($ip);
        if ($ip === '' || strpos($ip, ':') === false) {
            return $ip;
        }
        $bin = (string) inet_pton($ip);

        return strtolower((string) inet_ntop(substr($bin, 0, 8) . str_repeat("\0", 8))) . '/64';
    }

    public static function isLoopback(string $ip): bool
    {
        $ip = self::normalize($ip);

        return $ip === '::1' || strncmp($ip, '127.', 4) === 0;
    }

    public static function matches(string $ip, string $range): bool
    {
        $range = strtolower(trim($range));
        if ($range === '') {
            return false;
        }
        $ip = self::normalize($ip);
        if ($ip === '') {
            return false;
        }
        if (strpos($range, '/') !== false) {
            return self::inCidr($ip, $range);
        }
        $last = substr($range, -1);
        if ($last === '.' || ($last === ':' && substr($range, -2) !== '::')) {
            return strncmp($ip, $range, strlen($range)) === 0;
        }

        return $ip === self::normalize($range);
    }

    /** @param iterable<string> $ranges */
    public static function matchesAny(string $ip, iterable $ranges): bool
    {
        foreach ($ranges as $range) {
            if (is_string($range) && self::matches($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    public static function inCidr(string $ip, string $cidr): bool
    {
        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2 || !ctype_digit($parts[1])) {
            return false;
        }
        $net = @inet_pton(self::normalize($parts[0]));
        $addr = @inet_pton(self::normalize($ip));
        if ($net === false || $addr === false || strlen($net) !== strlen($addr)) {
            return false;
        }
        $bits = (int) $parts[1];
        if ($bits > strlen($net) * 8) {
            return false;
        }
        $bytes = intdiv($bits, 8);
        if ($bytes > 0 && strncmp($net, $addr, $bytes) !== 0) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xff << (8 - $rest)) & 0xff;

        return (ord($net[$bytes]) & $mask) === (ord($addr[$bytes]) & $mask);
    }

    /** Чи коректний запис діапазону (для форм білого списку). */
    public static function isValidRange(string $range): bool
    {
        $range = strtolower(trim($range));
        if ($range === '') {
            return false;
        }
        if (strpos($range, '/') !== false) {
            [$net, $bits] = explode('/', $range, 2);
            $bin = @inet_pton($net);

            return $bin !== false && ctype_digit($bits) && (int) $bits <= strlen($bin) * 8;
        }
        $last = substr($range, -1);
        if ($last === '.') {
            return (bool) preg_match('/^(\d{1,3}\.){1,3}$/', $range);
        }
        if ($last === ':' && substr($range, -2) !== '::') {
            return (bool) preg_match('/^([0-9a-f]{1,4}:){1,7}$/', $range);
        }

        return self::normalize($range) !== '';
    }

    /** Розбирає текстове налаштування: рядки або через кому; «#» — коментар. */
    public static function parseList(string $value): array
    {
        $out = [];
        foreach (preg_split('/[\r\n,]+/', $value) ?: [] as $line) {
            $hash = strpos($line, '#');
            if ($hash !== false) {
                $line = substr($line, 0, $hash);
            }
            $line = trim($line);
            if ($line !== '') {
                $out[] = $line;
            }
        }

        return $out;
    }
}
