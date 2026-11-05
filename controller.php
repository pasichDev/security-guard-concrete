<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard;

use Concrete\Core\Package\Package;
use Concrete\Core\Page\Page;
use Concrete\Core\Page\Single;
use PasichDev\SecurityGuard\ServiceProvider;
use Throwable;

defined('C5_EXECUTE') or die('Access Denied.');

final class Controller extends Package
{
    protected $pkgHandle = 'security_guard';
    protected $pkgVersion = '1.0.0';
    protected $appVersionRequired = '9.5.2';
    protected $pkgAutoloaderRegistries = [
        'src' => 'PasichDev\\SecurityGuard',
    ];

    /**
     * Сторінки дашборду пакета: шлях => [назва, опис].
     * Перша — батьківська; решта — її дочірні.
     */
    public const SINGLE_PAGES = [
        '/dashboard/security_guard' => ['Security Guard', 'Web application firewall and security dashboard'],
        '/dashboard/security_guard/overview' => ['Overview', 'Protection status, attacks and traffic at a glance'],
        '/dashboard/security_guard/events' => ['Event Log', 'Detected attacks and actions taken'],
        '/dashboard/security_guard/blocks' => ['Blocked IPs', 'Active and past IP blocks'],
        '/dashboard/security_guard/whitelist' => ['Whitelist', 'Trusted IP addresses and ranges'],
        '/dashboard/security_guard/honeypot' => ['Honeypot', 'Trap URLs and hits'],
        '/dashboard/security_guard/scores' => ['Behaviour Scores', 'Visitors with suspicious behaviour'],
        '/dashboard/security_guard/traffic' => ['Traffic', 'Traffic analytics from the hosting access logs'],
        '/dashboard/security_guard/checklist' => ['Security Check', 'Environment and configuration audit'],
        '/dashboard/security_guard/settings' => ['Settings', 'Firewall modules and thresholds'],
    ];

    public function getPackageName(): string
    {
        return t('Security Guard');
    }

    public function getPackageDescription(): string
    {
        return t('Web application firewall, login protection and security dashboard.');
    }

    public function install()
    {
        $pkg = parent::install();
        $this->installSinglePages($pkg);
        $this->app->make(ServiceProvider::class)->onInstallOrUpgrade($pkg);

        return $pkg;
    }

    public function upgrade()
    {
        parent::upgrade();
        $pkg = $this->getPackageEntity();
        $this->installSinglePages($pkg);
        $this->app->make(ServiceProvider::class)->onInstallOrUpgrade($pkg);
    }

    public function uninstall()
    {
        try {
            $this->app->make(ServiceProvider::class)->onUninstall();
        } catch (Throwable $e) {
            // Видалення пакета не має падати через наш кеш/файли.
        }
        parent::uninstall();
    }

    /**
     * Виконується на кожному запиті. Жодної важкої роботи: лише реєстрація
     * middleware, слухачів подій і CLI-команд. Будь-яка помилка тут
     * ковтається — пакет не має права покласти сайт (fail-open).
     */
    public function on_start()
    {
        try {
            $this->app->make(ServiceProvider::class)->boot($this);
        } catch (Throwable $e) {
            try {
                \Core::make('log')->error('Security Guard boot failed: ' . $e->getMessage());
            } catch (Throwable $ignored) {
            }
        }
    }

    private function installSinglePages($pkg): void
    {
        foreach (self::SINGLE_PAGES as $path => [$name, $description]) {
            $page = Page::getByPath($path);
            if (!is_object($page) || $page->isError()) {
                $page = Single::add($path, $pkg);
            }
            if (is_object($page) && !$page->isError()) {
                $page->update(['cName' => $name, 'cDescription' => $description]);
            }
        }
    }
}
