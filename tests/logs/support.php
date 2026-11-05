<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Tests\Logs;

use PasichDev\SecurityGuard\Logs\AttackClassifierInterface;
use PasichDev\SecurityGuard\Logs\CursorStoreInterface;
use PasichDev\SecurityGuard\Logs\DayWriterInterface;
use PasichDev\SecurityGuard\Logs\PendingDaysStoreInterface;

final class MemoryCursors implements CursorStoreInterface
{
    public $rows = [];

    public function load(): array
    {
        return $this->rows;
    }

    public function save(array $cursors): void
    {
        foreach ($cursors as $path => $row) {
            $this->rows[$path] = $row;
        }
    }
}

final class MemoryPending implements PendingDaysStoreInterface
{
    public $days = [];

    public function get(): array
    {
        return $this->days;
    }

    public function set(array $days): void
    {
        $this->days = array_values($days);
    }
}

final class MemoryDays implements DayWriterInterface
{
    public $rows = [];
    public $writes = 0;

    public function saveDay(string $day, array $row): void
    {
        // Як у БД: breakdown проходить через JSON.
        $row['breakdown'] = json_decode((string) json_encode($row['breakdown'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), true);
        $row['day'] = $day;
        $this->rows[$day] = $row;
        ++$this->writes;
        ksort($this->rows);
    }
}

/** Тестовий класифікатор: атака — шлях містить "/evil". */
final class FakeClassifier implements AttackClassifierInterface
{
    public function classify(string $method, string $uri, string $userAgent): ?array
    {
        return stripos($uri, '/evil') !== false ? ['rule' => 'FAKE_EVIL', 'category' => 'injection'] : null;
    }
}

final class T
{
    public static $fail = 0;
    public static $pass = 0;

    public static function eq($expected, $actual, string $msg): void
    {
        if ($expected === $actual) {
            ++self::$pass;

            return;
        }
        ++self::$fail;
        fwrite(STDERR, "FAIL: $msg\n  expected: " . var_export($expected, true) . "\n  actual:   " . var_export($actual, true) . "\n");
    }

    public static function ok(bool $cond, string $msg): void
    {
        self::eq(true, $cond, $msg);
    }

    public static function done(): int
    {
        echo sprintf("%d passed, %d failed\n", self::$pass, self::$fail);

        return self::$fail ? 1 : 0;
    }
}
