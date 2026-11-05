<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/**
 * HyperLogLog на 1024 регістри (похибка ~3 %): дає кількість унікальних IP
 * за довільний діапазон днів без зберігання списку всіх IP (той не вліз би в TEXT).
 * Серіалізація — 1024 символи 'A'..'X'.
 */
final class CardinalitySketch
{
    private const P = 10;
    private const M = 1024;

    /** @var string */
    private $reg;

    public function __construct(string $serialized = '')
    {
        $this->reg = strlen($serialized) === self::M ? $serialized : str_repeat('A', self::M);
    }

    public function add(string $value): void
    {
        $h = (int) hexdec(substr(md5($value), 0, 8));
        $idx = $h >> (32 - self::P);
        $w = $h & ((1 << (32 - self::P)) - 1);
        $rank = 1;
        for ($bit = 31 - self::P; $bit >= 0 && !($w & (1 << $bit)); --$bit) {
            ++$rank;
        }
        if ($rank > ord($this->reg[$idx]) - 65) {
            $this->reg[$idx] = chr(65 + $rank);
        }
    }

    public function merge(self $other): void
    {
        $o = $other->reg;
        for ($i = 0; $i < self::M; ++$i) {
            if ($o[$i] > $this->reg[$i]) {
                $this->reg[$i] = $o[$i];
            }
        }
    }

    public function count(): int
    {
        $sum = 0.0;
        $zeros = 0;
        for ($i = 0; $i < self::M; ++$i) {
            $r = ord($this->reg[$i]) - 65;
            $sum += 2 ** -$r;
            if ($r === 0) {
                ++$zeros;
            }
        }
        $alpha = 0.7213 / (1 + 1.079 / self::M);
        $e = $alpha * self::M * self::M / $sum;
        if ($e <= 2.5 * self::M && $zeros > 0) {
            $e = self::M * log(self::M / $zeros);
        }

        return (int) round($e);
    }

    public function serialize(): string
    {
        return $this->reg;
    }
}
