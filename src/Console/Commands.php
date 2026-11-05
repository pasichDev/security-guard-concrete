<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Console;

use Concrete\Core\Application\Application;
use Throwable;

/**
 * CLI-команди пакета. CLIRunner кладе консоль у контейнер ('console') до
 * setupPackages(), тож з on_start() пакета її вже можна отримати й додати команди.
 * Виклик відбувається на КОЖНІЙ CLI-команді сайту — нічого важкого тут не робимо,
 * а збій не має ламати інші команди.
 */
final class Commands
{
    public const COMMANDS = [
        IngestCommand::class,
        CleanupCommand::class,
        StatsCommand::class,
        UpdateRangesCommand::class,
    ];

    public static function register(Application $app): void
    {
        try {
            if (!$app->isRunThroughCommandLineInterface() || !$app->bound('console')) {
                return;
            }
            $console = $app->make('console');
            if (!is_object($console) || !method_exists($console, 'add')) {
                return;
            }
            foreach (self::COMMANDS as $class) {
                $console->add(new $class());
            }
        } catch (Throwable $e) {
            try {
                $app->make('log')->error('Security Guard: cannot register console commands: ' . $e->getMessage());
            } catch (Throwable $ignored) {
            }
        }
    }
}
