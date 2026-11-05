<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Update;

use InvalidArgumentException;

/**
 * Суворий розбір офіційного списку діапазонів краулера у форматі
 * {"creationTime": "...", "prefixes": [{"ipv4Prefix": "a.b.c.d/n"} | {"ipv6Prefix": "x::/n"}, ...]}
 * (Google, Bing, Apple, DuckDuckGo). Будь-яка неочікувана структура — виняток,
 * а не часткове прийняття: краще лишити старі діапазони, ніж записати сміття.
 */
final class RangeListParser
{
    public const MAX_PREFIXES = 20000;
    /** Найширші допустимі мережі: захист від підміненого списку з /0 чи /8. */
    public const MIN_V4_BITS = 16;
    public const MIN_V6_BITS = 32;

    /** @return array{prefixes: string[], creationTime: string} */
    public static function parse(string $json): array
    {
        $data = json_decode($json, true, 8);
        if (!is_array($data) || !isset($data['prefixes']) || !is_array($data['prefixes'])) {
            throw new InvalidArgumentException('Not a crawler range list (no "prefixes" array)');
        }
        if (count($data['prefixes']) > self::MAX_PREFIXES) {
            throw new InvalidArgumentException('Too many prefixes: ' . count($data['prefixes']));
        }
        $out = [];
        foreach ($data['prefixes'] as $i => $item) {
            if (!is_array($item)) {
                throw new InvalidArgumentException("Prefix #$i is not an object");
            }
            $keys = array_values(array_intersect(array_keys($item), ['ipv4Prefix', 'ipv6Prefix']));
            if (count($keys) !== 1 || !is_string($item[$keys[0]])) {
                throw new InvalidArgumentException("Prefix #$i must have exactly one of ipv4Prefix/ipv6Prefix");
            }
            $out[self::normalizeCidr($item[$keys[0]], $keys[0] === 'ipv6Prefix')] = true;
        }
        if (!$out) {
            throw new InvalidArgumentException('Empty prefix list');
        }
        $creation = isset($data['creationTime']) && is_string($data['creationTime']) ? substr($data['creationTime'], 0, 40) : '';

        return ['prefixes' => array_keys($out), 'creationTime' => $creation];
    }

    /**
     * Перевіряє CIDR і повертає його в канонічному вигляді (IPv4 /32 — просто IP,
     * як у вбудованому списку). Адреса мусить бути адресою мережі (без «хвоста» хоста).
     */
    public static function normalizeCidr(string $cidr, bool $v6): string
    {
        if (!preg_match('#^([0-9A-Fa-f:.]+)/(\d{1,3})$#', $cidr, $m)) {
            throw new InvalidArgumentException('Invalid CIDR: ' . $cidr);
        }
        $bin = @inet_pton($m[1]);
        $bits = (int) $m[2];
        if ($bin === false || strlen($bin) !== ($v6 ? 16 : 4)) {
            throw new InvalidArgumentException('Invalid address in CIDR: ' . $cidr);
        }
        $max = $v6 ? 128 : 32;
        $min = $v6 ? self::MIN_V6_BITS : self::MIN_V4_BITS;
        if ($bits < $min || $bits > $max) {
            throw new InvalidArgumentException('Prefix length out of range: ' . $cidr);
        }
        for ($b = $bits; $b < $max; ++$b) {
            if (ord($bin[intdiv($b, 8)]) & (0x80 >> ($b % 8))) {
                throw new InvalidArgumentException('Host bits set in CIDR: ' . $cidr);
            }
        }
        $addr = (string) inet_ntop($bin);

        return !$v6 && $bits === 32 ? $addr : $addr . '/' . $bits;
    }
}
