<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\State;

/**
 * Лічильники у файлах (коли APCu немає). Один ключ — один маленький файл
 * з flock. Ім'я файла — HMAC ключа з сіллю, тож за IP його не вгадати
 * (тека може віддаватися nginx напряму). Час життя зберігається в mtime
 * файла: прибирання дивиться лише на stat, не читаючи вміст.
 */
final class FileCounterStore implements CounterStore
{
    /** @var string */
    private $dir;

    /** @var string */
    private $salt;

    /** @var callable|null */
    private $clock;

    public function __construct(string $dir, string $salt, ?callable $clock = null)
    {
        $this->dir = rtrim($dir, '/');
        $this->salt = $salt;
        $this->clock = $clock;
    }

    public function increment(string $key, int $by, int $ttl): int
    {
        $value = $by;
        $this->locked($key, function (?array $entry, int $now) use ($by, $ttl, &$value): ?array {
            if ($entry !== null && is_int($entry['v'])) {
                $value = $entry['v'] + $by;

                return ['v' => $value, 'e' => $entry['e']];
            }
            $value = $by;

            return ['v' => $value, 'e' => $now + max(1, $ttl)];
        });

        return $value;
    }

    public function get(string $key)
    {
        $file = $this->file($key);
        $raw = @file_get_contents($file);
        if ($raw === false || $raw === '') {
            return null;
        }
        $entry = $this->decode($raw);

        return $entry !== null && $entry['e'] > $this->now() ? $entry['v'] : null;
    }

    public function set(string $key, $value, int $ttl): void
    {
        $this->locked($key, function (?array $entry, int $now) use ($value, $ttl): ?array {
            return ['v' => $value, 'e' => $now + max(1, $ttl)];
        });
    }

    public function add(string $key, $value, int $ttl): bool
    {
        $added = false;
        $this->locked($key, function (?array $entry, int $now) use ($value, $ttl, &$added): ?array {
            if ($entry !== null) {
                return $entry;
            }
            $added = true;

            return ['v' => $value, 'e' => $now + max(1, $ttl)];
        });

        return $added;
    }

    public function delete(string $key): void
    {
        @unlink($this->file($key));
    }

    public function purgeExpired(int $limit = 5000): int
    {
        $now = $this->now();
        $removed = 0;
        $seen = 0;
        $handle = @opendir($this->dir);
        if ($handle === false) {
            return 0;
        }
        while (($name = readdir($handle)) !== false) {
            if (substr($name, -4) !== '.cnt') {
                continue;
            }
            if (++$seen > $limit) {
                break;
            }
            $path = $this->dir . '/' . $name;
            $mtime = @filemtime($path);
            if ($mtime !== false && $mtime <= $now && @unlink($path)) {
                $removed++;
            }
        }
        closedir($handle);

        return $removed;
    }

    public function name(): string
    {
        return 'file';
    }

    private function now(): int
    {
        return $this->clock ? (int) ($this->clock)() : time();
    }

    private function file(string $key): string
    {
        return $this->dir . '/' . substr(hash_hmac('sha256', $key, $this->salt), 0, 40) . '.cnt';
    }

    /** Читання-зміна-запис під ексклюзивним flock. $fn отримує чинний запис або null. */
    private function locked(string $key, callable $fn): void
    {
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0775, true);
        }
        $file = $this->file($key);
        $fp = @fopen($file, 'c+');
        if ($fp === false) {
            throw new \RuntimeException('Cannot open counter file');
        }
        try {
            if (!flock($fp, LOCK_EX)) {
                throw new \RuntimeException('Cannot lock counter file');
            }
            $now = $this->now();
            $raw = stream_get_contents($fp);
            $entry = ($raw === false || $raw === '') ? null : $this->decode($raw);
            if ($entry !== null && $entry['e'] <= $now) {
                $entry = null;
            }
            $next = $fn($entry, $now);
            if ($next !== null && $next !== $entry) {
                ftruncate($fp, 0);
                rewind($fp);
                fwrite($fp, json_encode($next, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
                fflush($fp);
            }
            flock($fp, LOCK_UN);
        } finally {
            fclose($fp);
        }
        if (isset($next) && $next !== null && $next !== $entry) {
            @touch($file, (int) $next['e']);
        }
    }

    private function decode(string $raw): ?array
    {
        $data = json_decode($raw, true);
        if (!is_array($data) || !array_key_exists('v', $data) || !isset($data['e'])) {
            return null;
        }

        return ['v' => $data['v'], 'e' => (int) $data['e']];
    }
}
