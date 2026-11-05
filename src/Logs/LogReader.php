<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

use RuntimeException;

/**
 * Послідовне читання звичайного або gzip-файлу логу (gzopen/gzgets — без exec).
 * Позиція для gzip — зсув у розпакованому потоці (gztell); zlib прозоро читає
 * склеєні gzip-члени, які cPanel дописує в місячний архів щодня.
 */
final class LogReader
{
    private const MAX_LINE = 65536;

    /** @var resource|null */
    private $h;
    /** @var bool */
    private $gz;
    /** @var string */
    private $path;

    public function __construct(string $path)
    {
        $this->path = $path;
        $this->gz = self::isGzip($path);
        $h = $this->gz ? @gzopen($path, 'rb') : @fopen($path, 'rb');
        if (!$h) {
            throw new RuntimeException('Cannot open log file: ' . $path);
        }
        $this->h = $h;
    }

    public function __destruct()
    {
        $this->close();
    }

    public static function isGzip(string $path): bool
    {
        $f = @fopen($path, 'rb');
        if (!$f) {
            return substr($path, -3) === '.gz';
        }
        $magic = (string) fread($f, 2);
        fclose($f);

        return $magic === "\x1f\x8b";
    }

    public function isGz(): bool
    {
        return $this->gz;
    }

    /** Перший рядок файлу (для відбитка). Позицію не змінює для наступного seek(0). */
    public static function firstLine(string $path): string
    {
        try {
            $r = new self($path);
            $line = $r->next();
            $r->close();
        } catch (\Throwable $e) {
            return '';
        }

        return $line === null ? '' : rtrim($line, "\r\n");
    }

    public function seek(int $pos): bool
    {
        if ($pos <= 0) {
            return $this->gz ? gzrewind($this->h) : rewind($this->h);
        }

        return $this->gz ? gzseek($this->h, $pos) === 0 : fseek($this->h, $pos) === 0;
    }

    public function tell(): int
    {
        $p = $this->gz ? gztell($this->h) : ftell($this->h);

        return $p === false ? 0 : (int) $p;
    }

    /**
     * Наступний повний рядок або null у кінці. Недописаний останній рядок
     * (без "\n") у звичайному файлі не повертається — його дочитаємо наступного разу.
     */
    public function next(): ?string
    {
        if ($this->h === null) {
            return null;
        }
        $before = $this->gz ? null : ftell($this->h);
        $line = $this->gz ? gzgets($this->h, self::MAX_LINE) : fgets($this->h, self::MAX_LINE);
        if ($line === false) {
            return null;
        }
        if (substr($line, -1) !== "\n") {
            $eof = $this->gz ? gzeof($this->h) : feof($this->h);
            if ($eof && !$this->gz && $before !== false) {
                fseek($this->h, $before);

                return null;
            }
            if (!$eof) {
                // Надто довгий рядок: пропускаємо решту.
                do {
                    $more = $this->gz ? gzgets($this->h, self::MAX_LINE) : fgets($this->h, self::MAX_LINE);
                } while ($more !== false && substr($more, -1) !== "\n");
            }
        }

        return $line;
    }

    public function close(): void
    {
        if ($this->h !== null) {
            $this->gz ? @gzclose($this->h) : @fclose($this->h);
            $this->h = null;
        }
    }

    public function path(): string
    {
        return $this->path;
    }
}
