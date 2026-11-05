<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/**
 * Список IP для виключення зі статистики: точна IP, префікс ("203.0.113.") або CIDR (IPv4/IPv6).
 * Окремий від білого списку WAF, щоб розбір логів не залежав від Concrete.
 */
final class IpMatcher
{
    /** @var array<string, true> */
    private $exact = [];
    /** @var string[] */
    private $prefixes = [];
    /** @var array<int, array{0:string, 1:int}> */
    private $cidrs = [];
    /** @var array<string, bool> */
    private $memo = [];
    /** @var string[] */
    private $items = [];

    /** @param string|string[] $list рядки або один рядок, розділений комами/пробілами/новими рядками */
    public function __construct($list)
    {
        $items = is_array($list) ? $list : preg_split('/[\s,;]+/', (string) $list);
        foreach ($items as $item) {
            $item = trim((string) $item);
            if ($item === '') {
                continue;
            }
            $this->items[] = $item;
            if (strpos($item, '/') !== false) {
                [$net, $bits] = explode('/', $item, 2);
                $bin = @inet_pton($net);
                if ($bin !== false && ctype_digit($bits)) {
                    $this->cidrs[] = [$bin, (int) $bits];
                }
            } elseif (substr($item, -1) === '.' || substr($item, -1) === ':') {
                $this->prefixes[] = $item;
            } else {
                $this->exact[$item] = true;
            }
        }
    }

    /** @return string[] вихідні записи списку */
    public function items(): array
    {
        return $this->items;
    }

    public function isEmpty(): bool
    {
        return !$this->exact && !$this->prefixes && !$this->cidrs;
    }

    public function matches(string $ip): bool
    {
        if (isset($this->exact[$ip])) {
            return true;
        }
        if (!$this->prefixes && !$this->cidrs) {
            return false;
        }
        if (isset($this->memo[$ip])) {
            return $this->memo[$ip];
        }
        $hit = false;
        foreach ($this->prefixes as $p) {
            if (strncmp($ip, $p, strlen($p)) === 0) {
                $hit = true;
                break;
            }
        }
        if (!$hit && $this->cidrs) {
            $bin = @inet_pton($ip);
            if ($bin !== false) {
                foreach ($this->cidrs as [$net, $bits]) {
                    if (strlen($net) === strlen($bin) && self::inCidr($bin, $net, $bits)) {
                        $hit = true;
                        break;
                    }
                }
            }
        }
        if (count($this->memo) > 20000) {
            $this->memo = [];
        }

        return $this->memo[$ip] = $hit;
    }

    private static function inCidr(string $ip, string $net, int $bits): bool
    {
        $bytes = intdiv($bits, 8);
        if ($bytes > strlen($ip)) {
            return false;
        }
        if (strncmp($ip, $net, $bytes) !== 0) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rest)) & 0xFF;

        return (ord($ip[$bytes]) & $mask) === (ord($net[$bytes]) & $mask);
    }
}
