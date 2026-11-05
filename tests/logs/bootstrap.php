<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

// Автономний запуск без Concrete: автозавантаження класів пакета з src/.
declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '1');

spl_autoload_register(static function (string $class): void {
    $prefix = 'PasichDev\\SecurityGuard\\';
    if (strpos($class, $prefix) !== 0) {
        return;
    }
    $file = dirname(__DIR__, 2) . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

require __DIR__ . '/support.php';
