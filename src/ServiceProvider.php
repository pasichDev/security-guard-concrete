<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace PasichDev\SecurityGuard;

use Concrete\Core\Application\Application;
use Concrete\Core\Http\ServerInterface;
use PasichDev\SecurityGuard\Block\BlockService;
use PasichDev\SecurityGuard\Config\Settings;
use PasichDev\SecurityGuard\Console\Commands;
use PasichDev\SecurityGuard\Contract\AlertServiceInterface;
use PasichDev\SecurityGuard\Contract\BlockServiceInterface;
use PasichDev\SecurityGuard\Contract\EventLogInterface;
use PasichDev\SecurityGuard\Contract\HoneypotRepositoryInterface;
use PasichDev\SecurityGuard\Contract\LogIngestInterface;
use PasichDev\SecurityGuard\Contract\ScoreServiceInterface;
use PasichDev\SecurityGuard\Contract\StateCacheInterface;
use PasichDev\SecurityGuard\Contract\StatsRepositoryInterface;
use PasichDev\SecurityGuard\Contract\WhitelistInterface;
use PasichDev\SecurityGuard\Http\GuardMiddleware;
use PasichDev\SecurityGuard\Login\LoginGuard;
use PasichDev\SecurityGuard\Logs\LogIngest;
use PasichDev\SecurityGuard\Notify\AlertService;
use PasichDev\SecurityGuard\State\FileStateCache;
use PasichDev\SecurityGuard\Stats\StatsRepository;
use PasichDev\SecurityGuard\Waf\EventLog;
use PasichDev\SecurityGuard\Waf\HoneypotRepository;
use PasichDev\SecurityGuard\Waf\ScoreService;
use PasichDev\SecurityGuard\Waf\Whitelist;

/**
 * Зв'язує контракти з реалізаціями і підключає пакет до життєвого циклу
 * Concrete. Це файл-контракт між частинами пакета: імена класів реалізацій
 * тут фіксовані.
 */
final class ServiceProvider
{
    public const BINDINGS = [
        StateCacheInterface::class => FileStateCache::class,
        BlockServiceInterface::class => BlockService::class,
        EventLogInterface::class => EventLog::class,
        WhitelistInterface::class => Whitelist::class,
        ScoreServiceInterface::class => ScoreService::class,
        HoneypotRepositoryInterface::class => HoneypotRepository::class,
        AlertServiceInterface::class => AlertService::class,
        StatsRepositoryInterface::class => StatsRepository::class,
        LogIngestInterface::class => LogIngest::class,
    ];

    private $app;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    public function registerBindings(): void
    {
        $this->app->singleton(Settings::class);
        foreach (self::BINDINGS as $abstract => $concrete) {
            $this->app->singleton($abstract, $concrete);
        }
    }

    /** Викликається з Controller::on_start() на кожному запиті. Має бути дешевим. */
    public function boot($pkgController): void
    {
        $this->registerBindings();

        if ($this->app->isRunThroughCommandLineInterface()) {
            Commands::register($this->app);

            return;
        }

        // WAF — middleware: бачить запит до диспетчеризації і відповідь після неї
        // (потрібно, щоб помітити невдалий вхід). Пріоритет високий — раніше за інші.
        $this->app->make(ServerInterface::class)->addMiddleware($this->app->make(GuardMiddleware::class), 1);

        // Події входу/виходу (автодовіра IP адміна, сповіщення про вхід з нової IP).
        $this->app->make(LoginGuard::class)->subscribe();
    }

    public function onInstallOrUpgrade($pkg): void
    {
        $this->registerBindings();
        $this->app->make(StateCacheInterface::class)->rebuild();
    }

    public function onUninstall(): void
    {
        $this->registerBindings();
        $this->app->make(StateCacheInterface::class)->clear();
        try {
            $this->app->make(\Concrete\Core\Package\PackageService::class)->getClass('security_guard')->getConfig()->clear('log_ingest');
        } catch (\Throwable $e) {
        }
        // Concrete не видаляє таблиці з db.xml при видаленні пакета — прибираємо самі.
        $db = $this->app->make(\Concrete\Core\Database\Connection\Connection::class);
        $xml = @simplexml_load_file(dirname(__DIR__) . '/db.xml');
        if ($xml !== false) {
            foreach ($xml->table as $table) {
                $name = (string) $table['name'];
                if (preg_match('/^SecurityGuard[A-Za-z]+$/', $name)) {
                    $db->executeStatement('DROP TABLE IF EXISTS `' . $name . '`');
                }
            }
        }
    }
}
