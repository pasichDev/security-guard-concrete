<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support;

use Throwable;

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * Межі для шляхів до логів хостингу: усе має лежати всередині домашнього
 * каталогу акаунта (визначається автоматично, не з налаштувань — інакше
 * налаштування саме розширювало б собі межі). Перевірка через realpath,
 * тож символьні посилання назовні не проходять. Шаблони (* ? [ ]) — лише
 * в імені файлу.
 */
final class LogPaths
{
    public const MAX_SOURCES = 50;
    private const CACHE_KEY = 'ui.log_sources_cache';

    /** @var string|null|false false — ще не визначали */
    private static $root = false;

    /** Дозволений корінь (realpath) або null, якщо його не вдалося визначити. */
    public static function root(string $domain = ''): ?string
    {
        if (self::$root !== false) {
            return self::$root;
        }
        $base = defined('DIR_BASE') ? (string) DIR_BASE : '';
        $home = null;
        try {
            if (class_exists('PasichDev\SecurityGuard\Logs\SourceLocator')) {
                $home = \PasichDev\SecurityGuard\Logs\SourceLocator::detectHome($base !== '' ? $base : null, $domain);
            }
        } catch (Throwable $e) {
        }
        if (!$home && $base !== '') {
            // Без access-logs/ поруч: каталог над коренем сайту (на cPanel — домашній).
            $home = dirname(rtrim($base, '/'));
        }
        $real = $home ? realpath($home) : false;
        // Корінь файлової системи — не межа.
        self::$root = ($real && $real !== '/') ? rtrim($real, '/') : null;

        return self::$root;
    }

    /** Для тестів. */
    public static function setRoot(?string $root): void
    {
        self::$root = $root;
    }

    public static function inside(string $path, ?string $root): bool
    {
        if ($root === null) {
            return false;
        }
        $real = realpath($path);

        return $real !== false && ($real === $root || strpos($real, $root . '/') === 0);
    }

    /** Розгортає "~/" у корінь акаунта. */
    public static function expand(string $path, ?string $root): string
    {
        if ($root !== null && ($path === '~' || strpos($path, '~/') === 0)) {
            return $root . substr($path, 1);
        }

        return $path;
    }

    /** null — шлях до каталогу (log_root) допустимий, інакше текст помилки. */
    public static function validateRoot(string $path, ?string $root): ?string
    {
        if ($path === '') {
            return null;
        }
        if ($root === null) {
            return t('The hosting account home directory could not be detected, so custom log paths are not allowed. Leave the field empty.');
        }
        $path = self::expand($path, $root);
        if ($path[0] !== '/' || preg_match('/[*?\[\]\r\n\0]/', $path) || preg_match('#(^|/)\.\.(/|$)#', $path)) {
            return t('"%s" must be an absolute path without wildcards or "..".', mb_substr($path, 0, 80));
        }
        if (!is_dir($path) || !self::inside($path, $root)) {
            return t('"%s" is not a directory inside the hosting account (%s).', mb_substr($path, 0, 80), $root);
        }

        return null;
    }

    /** null — рядок log_sources допустимий, інакше текст помилки. */
    public static function validateSource(string $line, ?string $root): ?string
    {
        if ($root === null) {
            return t('The hosting account home directory could not be detected, so custom log paths are not allowed. Leave the field empty.');
        }
        $line = self::expand($line, $root);
        if (strlen($line) > 255 || $line[0] !== '/' || preg_match('#(^|/)\.\.(/|$)#', $line) || preg_match('/[\r\n\0]/', $line)) {
            return t('"%s" must be an absolute path (or start with ~/) without "..".', mb_substr($line, 0, 80));
        }
        $dir = dirname($line);
        if (preg_match('/[*?\[\]{}]/', $dir)) {
            return t('"%s": wildcards are allowed only in the file name.', mb_substr($line, 0, 80));
        }
        if (!is_dir($dir) || !self::inside($dir, $root)) {
            return t('"%s" is not inside the hosting account (%s).', mb_substr($line, 0, 80), $root);
        }

        return null;
    }

    /**
     * Лишає лише файли всередині кореня (після realpath), не більше MAX_SOURCES.
     *
     * @return array<string, int> шлях => розмір
     */
    public static function filter(array $sources, ?string $root): array
    {
        $out = [];
        foreach ($sources as $path => $size) {
            if (!is_string($path) || !self::inside($path, $root)) {
                continue;
            }
            $out[$path] = (int) $size;
            if (count($out) >= self::MAX_SOURCES) {
                break;
            }
        }

        return $out;
    }

    /**
     * Збережений результат пошуку джерел: ['at' => int, 'sources' => [...]] або null.
     * Сторінки читають кеш і не обходять файлову систему на кожному відкритті.
     */
    public static function cached($config): ?array
    {
        try {
            $raw = $config->get(self::CACHE_KEY);
            $data = is_string($raw) ? json_decode($raw, true) : null;

            return is_array($data) && isset($data['sources']) ? $data : null;
        } catch (Throwable $e) {
            return null;
        }
    }

    public static function store($config, array $sources): array
    {
        $data = ['at' => time(), 'sources' => $sources];
        try {
            $config->save(self::CACHE_KEY, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        } catch (Throwable $e) {
        }

        return $data;
    }
}
