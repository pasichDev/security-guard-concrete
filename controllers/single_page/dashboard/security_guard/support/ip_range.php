<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support;

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * Перевірка записів білого списку: точний IP, префікс із крапкою в кінці
 * ("203.0.113.") або CIDR. Занадто широкі діапазони відкидаються — інакше
 * білий список вимикає захист для половини інтернету.
 */
final class IpRange
{
    /** Найширші дозволені мережі. */
    public const MIN_PREFIX_V4 = 8;
    public const MIN_PREFIX_V6 = 16;

    /** Повертає null, якщо запис коректний, або текст помилки. */
    public static function validate(string $range): ?string
    {
        $range = trim($range);
        if ($range === '' || strlen($range) > 64) {
            return t('Enter an IP address, a prefix such as 203.0.113. or a CIDR range such as 203.0.113.0/24.');
        }
        if (filter_var($range, FILTER_VALIDATE_IP)) {
            return null;
        }
        // Префікс: 1–3 октети з крапкою в кінці.
        if (preg_match('/^(\d{1,3}\.){1,3}$/', $range)) {
            $octets = explode('.', rtrim($range, '.'));
            foreach ($octets as $o) {
                if ((int) $o > 255 || ($o !== '0' && $o[0] === '0')) {
                    return t('"%s" is not a valid prefix.', $range);
                }
            }
            if (count($octets) < 1 || (count($octets) * 8) < self::MIN_PREFIX_V4) {
                return t('"%s" is too broad.', $range);
            }

            return null;
        }
        if (preg_match('#^([^/]+)/(\d{1,3})$#', $range, $m)) {
            $ip = $m[1];
            $bits = (int) $m[2];
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                if ($bits > 32) {
                    return t('"%s" is not a valid CIDR range.', $range);
                }
                if ($bits < self::MIN_PREFIX_V4) {
                    return t('"%s" is too broad: the smallest allowed mask is /%s.', $range, self::MIN_PREFIX_V4);
                }

                return null;
            }
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                if ($bits > 128) {
                    return t('"%s" is not a valid CIDR range.', $range);
                }
                if ($bits < self::MIN_PREFIX_V6) {
                    return t('"%s" is too broad: the smallest allowed mask is /%s.', $range, self::MIN_PREFIX_V6);
                }

                return null;
            }
        }

        return t('"%s" is not an IP address, prefix or CIDR range.', $range);
    }

    /**
     * Розбирає багаторядковий список (рядки або коми; # — коментар).
     *
     * @return array{valid: string[], errors: string[]}
     */
    public static function parseList(string $text): array
    {
        $valid = [];
        $errors = [];
        foreach (preg_split('/\r\n|\r|\n/', $text) ?: [] as $line) {
            $line = trim(preg_replace('/#.*$/', '', $line) ?? '');
            if ($line === '') {
                continue;
            }
            foreach (preg_split('/[\s,;]+/', $line) ?: [] as $item) {
                if ($item === '') {
                    continue;
                }
                $err = self::validate($item);
                if ($err === null) {
                    if (!in_array($item, $valid, true)) {
                        $valid[] = $item;
                    }
                } else {
                    $errors[] = $err;
                }
            }
        }

        return ['valid' => $valid, 'errors' => $errors];
    }
}
