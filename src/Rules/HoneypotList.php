<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Rules;

/**
 * Вбудовані URL-пастки. На сайті на Concrete жодної з цих адрес немає, тож
 * звернення до них робить лише сканер. Запис, що закінчується на «/», — тека
 * (збігається сама тека і все всередині), інакше — файл (точний збіг або
 * останні сегменти шляху).
 */
final class HoneypotList
{
    public const BUILTIN = [
        '/c99.php', '/c100.php', '/r57.php', '/wso.php', '/alfa.php',
        '/shell.php', '/webshell.php', '/cmd.php', '/exec.php',
        '/backdoor.php', '/adminer.php',
        '/wp-admin.php', '/wp-login.php', '/wp-config.php',
        '/wp-admin/admin-ajax.php', '/wp-admin/setup-config.php',
        '/admin.php', '/login.php', '/phpmyadmin/',
        '/pma/', '/dbadmin/', '/myadmin/',
        '/.env', '/.git/config', '/.htpasswd',
        '/config.php.bak', '/configuration.php.bak',
        '/install.php', '/setup.php', '/installation/',
        '/up.php', '/up_admin.php', '/upload.php',
    ];

    /** Розбирає налаштування honeypot_custom_urls (по рядку або через кому). */
    public static function parseCustom(string $value): array
    {
        $out = [];
        foreach (preg_split('/[\r\n,]+/', $value) ?: [] as $line) {
            $line = trim($line);
            if ($line !== '' && $line[0] === '/') {
                $out[] = $line;
            }
        }

        return $out;
    }

    public static function matches(string $path, string $trap): bool
    {
        $trap = strtolower(trim($trap));
        if ($trap === '' || $trap === '/') {
            return false;
        }
        if (substr($trap, -1) === '/') {
            $dir = rtrim($trap, '/');

            return $path === $dir || strncmp($path, $dir . '/', strlen($dir) + 1) === 0;
        }
        $path = rtrim($path, '/');
        if ($path === $trap) {
            return true;
        }
        // Межа сегмента: /blog/wp-login.php збігається з /wp-login.php, а /xwp-login.php — ні.
        $len = strlen($trap);

        return strlen($path) > $len && substr($path, -$len) === $trap;
    }
}
