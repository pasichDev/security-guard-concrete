<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\State;

/**
 * Тека стану пакета. Перевага — каталог ПОЗА веб-коренем (поруч із
 * public_html, на shared-хостингу це домашня тека), якщо він уже є або
 * його можна створити. Інакше — application/files/security_guard із
 * забороною доступу (.htaccess, index.html), а файли там нешкідливі:
 * state.php має захист C5_EXECUTE, лічильники названі HMAC-ом.
 */
final class StateDir
{
    public const OUTSIDE_NAME = '.security_guard';

    /** @var string|null */
    private static $resolved;

    public static function path(): string
    {
        if (self::$resolved !== null) {
            return self::$resolved;
        }
        $candidates = [];
        if (defined('DIR_BASE')) {
            $candidates[] = dirname((string) DIR_BASE) . '/' . self::OUTSIDE_NAME;
        }
        $fallback = (defined('DIR_FILES_UPLOADED_STANDARD') ? (string) DIR_FILES_UPLOADED_STANDARD : sys_get_temp_dir()) . '/security_guard';

        foreach ($candidates as $dir) {
            if (is_dir($dir) && is_writable($dir)) {
                return self::$resolved = $dir;
            }
        }
        if (is_dir($fallback)) {
            return self::$resolved = $fallback;
        }
        foreach ($candidates as $dir) {
            $parent = dirname($dir);
            if (!is_dir($dir) && @is_writable($parent) && @mkdir($dir, 0770) && is_writable($dir)) {
                return self::$resolved = $dir;
            }
        }
        self::prepare($fallback);

        return self::$resolved = $fallback;
    }

    /** Для тестів і CLI: явно задати теку. */
    public static function override(?string $dir): void
    {
        self::$resolved = $dir;
    }

    /** Створює теку з файлами-запобіжниками від веб-доступу. */
    public static function prepare(string $dir): void
    {
        if (!is_dir($dir)) {
            @mkdir($dir, 0775, true);
        }
        if (!is_file($dir . '/.htaccess')) {
            @file_put_contents($dir . '/.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
        }
        if (!is_file($dir . '/index.html')) {
            @file_put_contents($dir . '/index.html', '');
        }
    }

    /** Секрет для імен файлів лічильників; створюється один раз. */
    public static function salt(string $dir): string
    {
        $file = $dir . '/salt.php';
        $raw = @file_get_contents($file);
        if (is_string($raw) && preg_match('/\'([a-f0-9]{64})\'/', $raw, $m)) {
            return $m[1];
        }
        self::prepare($dir);
        $salt = bin2hex(random_bytes(32));
        $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, "<?php\ndefined('C5_EXECUTE') or die('Access Denied.');\nreturn '" . $salt . "';\n", LOCK_EX) !== false) {
            if (!@rename($tmp, $file)) {
                @unlink($tmp);
            }
        }
        // Якщо інший процес встиг першим — беремо його сіль.
        $raw = @file_get_contents($file);
        if (is_string($raw) && preg_match('/\'([a-f0-9]{64})\'/', $raw, $m)) {
            return $m[1];
        }

        return $salt;
    }

    /** Видаляє теку стану з усім вмістом (лише нашу теку). */
    public static function remove(string $dir): void
    {
        if ($dir === '' || !is_dir($dir) || basename($dir) === '' || !in_array(basename($dir), [self::OUTSIDE_NAME, 'security_guard'], true)) {
            return;
        }
        $items = @scandir($dir) ?: [];
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            if (is_dir($path) && !is_link($path)) {
                foreach (@scandir($path) ?: [] as $sub) {
                    if ($sub !== '.' && $sub !== '..') {
                        @unlink($path . '/' . $sub);
                    }
                }
                @rmdir($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
        if (self::$resolved === $dir) {
            self::$resolved = null;
        }
    }
}
