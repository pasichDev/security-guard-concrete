<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

// Автономний запуск без Concrete: php tests/engine/<назва>_test.php
declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '1');

spl_autoload_register(static function (string $class): void {
    $prefix = 'PasichDev\\SecurityGuard\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $file = dirname(__DIR__, 2) . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

if (!function_exists('t')) {
    // Замінник функції перекладу Concrete для автономних тестів.
    function t($text, ...$args)
    {
        return $args ? vsprintf((string) $text, $args) : (string) $text;
    }
}
if (!defined('C5_EXECUTE')) {
    define('C5_EXECUTE', true);
}

/** Тимчасова тека для тестів (видаляється в кінці). */
function sg_temp_dir(string $name): string
{
    $dir = sys_get_temp_dir() . '/sg-test-' . $name . '-' . bin2hex(random_bytes(4));
    mkdir($dir, 0777, true);
    $owner = getmypid();
    register_shutdown_function(static function () use ($dir, $owner): void {
        // Дочірні процеси (тест гонки) теку не прибирають.
        if (getmypid() !== $owner || !is_dir($dir)) {
            return;
        }
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
        }
        @rmdir($dir);
    });

    return $dir;
}

final class T
{
    public static $pass = 0;
    public static $fail = 0;

    public static function ok(bool $cond, string $label): void
    {
        if ($cond) {
            self::$pass++;
        } else {
            self::$fail++;
            fwrite(STDERR, "FAIL: {$label}\n");
        }
    }

    public static function eq($expected, $actual, string $label): void
    {
        self::ok($expected === $actual, $label . ' (очікувано ' . var_export($expected, true) . ', отримано ' . var_export($actual, true) . ')');
    }

    public static function done(string $name): void
    {
        echo $name . ': ' . self::$pass . ' ok, ' . self::$fail . " fail\n";
        exit(self::$fail > 0 ? 1 : 0);
    }
}
