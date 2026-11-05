<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/**
 * Пошук файлів логів хостингу cPanel.
 *
 * За замовчуванням (для домену example.com і домашнього каталогу ~):
 *   ~/access-logs/example.com            — живий лог http
 *   ~/access-logs/example.com-ssl_log    — живий лог https
 *   ~/logs/example.com-*.gz              — місячні архіви (…-Oct-2026.gz, …-ssl_log-Oct-2026_NGINX.gz)
 * Або явний список шляхів/глобів (по одному в рядку; "~/" — від домашнього каталогу).
 */
final class SourceLocator
{
    /** @var string|null */
    private $home;
    /** @var string */
    private $domain;
    /** @var string[] */
    private $explicit;

    /** @param string|string[] $explicit */
    public function __construct(?string $home, string $domain, $explicit = [])
    {
        $this->home = $home === null || $home === '' ? null : rtrim($home, '/');
        $this->domain = self::normalizeDomain($domain);
        $lines = is_array($explicit) ? $explicit : preg_split('/[\r\n]+/', (string) $explicit);
        $this->explicit = array_values(array_filter(array_map('trim', $lines), 'strlen'));
    }

    public static function normalizeDomain(string $domain): string
    {
        $domain = strtolower(trim($domain));
        if (strpos($domain, '://') !== false) {
            $domain = (string) parse_url($domain, PHP_URL_HOST);
        }
        $domain = rtrim($domain, '/.');
        if (strpos($domain, 'www.') === 0) {
            $domain = substr($domain, 4);
        }

        return preg_match('/^[a-z0-9.-]+$/', $domain) ? $domain : '';
    }

    /**
     * Домашній каталог акаунта. HOME для PHP на хостингу буває недоступний —
     * тоді йдемо вгору від кореня сайту (/home/user/public_html → /home/user).
     * Спершу шукаємо каталог з access-logs/; каталог лише з logs/ приймаємо, тільки
     * якщо в ньому є архіви домену (у корені сайту буває стара тека logs/ від Joomla).
     */
    public static function detectHome(?string $siteRoot = null, string $domain = ''): ?string
    {
        $candidates = [];
        if ($siteRoot) {
            $dir = rtrim($siteRoot, '/');
            for ($i = 0; $i < 4 && $dir !== '' && $dir !== '/'; ++$i) {
                $candidates[] = $dir;
                $dir = dirname($dir);
            }
        }
        foreach ([getenv('HOME'), $_SERVER['HOME'] ?? null, $_ENV['HOME'] ?? null] as $h) {
            if (is_string($h) && $h !== '') {
                $candidates[] = rtrim($h, '/');
            }
        }
        foreach ($candidates as $dir) {
            if (@is_dir($dir . '/access-logs')) {
                return $dir;
            }
        }
        $domain = self::normalizeDomain($domain);
        if ($domain !== '') {
            foreach ($candidates as $dir) {
                if (@is_dir($dir . '/logs') && glob($dir . '/logs/' . $domain . '-*.gz', GLOB_NOSORT)) {
                    return $dir;
                }
            }
        }
        if ($siteRoot && preg_match('#^(/home\d*/[^/]+)/#', rtrim($siteRoot, '/') . '/', $m)) {
            return $m[1];
        }

        return null;
    }

    public function home(): ?string
    {
        return $this->home;
    }

    public function domain(): string
    {
        return $this->domain;
    }

    /** @return string[] шаблони, за якими шукаємо */
    public function patterns(): array
    {
        $out = [];
        if ($this->explicit) {
            foreach ($this->explicit as $p) {
                if (strpos($p, '~/') === 0) {
                    if ($this->home === null) {
                        continue;
                    }
                    $p = $this->home . substr($p, 1);
                }
                $out[] = $p;
            }

            return $out;
        }
        if ($this->home === null || $this->domain === '') {
            return [];
        }
        $d = $this->domain;

        return [
            $this->home . '/logs/' . $d . '-*.gz',
            $this->home . '/access-logs/' . $d,
            $this->home . '/access-logs/' . $d . '-ssl_log',
        ];
    }

    /**
     * Знайдені файли: path => ['size' => int, 'mtime' => int, 'stream' => string].
     * Спершу архіви (за часом зміни), потім живі логи.
     * @return array<string, array{size:int, mtime:int, stream:string}>
     */
    public function discover(): array
    {
        $found = [];
        foreach ($this->patterns() as $pattern) {
            $paths = strpbrk($pattern, '*?[') === false ? [$pattern] : (glob($pattern, GLOB_NOSORT) ?: []);
            foreach ($paths as $path) {
                if (!@is_file($path) || !@is_readable($path)) {
                    continue;
                }
                $real = realpath($path) ?: $path;
                if (isset($found[$real])) {
                    continue;
                }
                $found[$real] = [
                    'size' => (int) @filesize($path),
                    'mtime' => (int) @filemtime($path),
                    'stream' => self::streamOf($real),
                ];
            }
        }
        uksort($found, static function (string $a, string $b) use ($found): int {
            $ga = LogReader::isGzip($a) ? 0 : 1;
            $gb = LogReader::isGzip($b) ? 0 : 1;

            return [$ga, $found[$a]['mtime'], $a] <=> [$gb, $found[$b]['mtime'], $b];
        });

        return $found;
    }

    /**
     * Потік, до якого належить файл: архіви й живий лог того самого потоку
     * можуть перекриватися при ротації; різні потоки (http і https) — ніколи.
     * example.com-ssl_log-Oct-2026_NGINX.gz → example.com-ssl_log
     */
    public static function streamOf(string $path): string
    {
        $base = basename($path);
        $base = (string) preg_replace('/\.gz$/i', '', $base);
        $base = (string) preg_replace('/-[A-Z][a-z]{2}-\d{4}(?:_[A-Za-z]+)?$/', '', $base);
        $base = (string) preg_replace('/[.-](?:\d+|\d{8}|\d{4}-\d{2}-\d{2})$/', '', $base);

        return $base;
    }
}
