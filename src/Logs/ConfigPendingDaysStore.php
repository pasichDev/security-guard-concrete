<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

use Concrete\Core\Package\PackageService;

/**
 * Черга днів до перерахунку — у БД-конфігу пакета (ключ log_ingest.pending_days),
 * поза групою settings: це службовий стан, а не налаштування.
 */
final class ConfigPendingDaysStore implements PendingDaysStoreInterface
{
    public const KEY = 'log_ingest.pending_days';

    private $config;

    public function __construct(PackageService $packages)
    {
        $this->config = $packages->getClass('security_guard')->getConfig();
    }

    public function get(): array
    {
        $v = $this->config->get(self::KEY);
        if (!is_array($v)) {
            return [];
        }

        return array_values(array_filter(array_map('strval', $v), static function (string $d): bool {
            return (bool) preg_match('/^\d{4}-\d{2}-\d{2}$/', $d);
        }));
    }

    public function set(array $days): void
    {
        $days = array_values(array_map('strval', $days));
        if ($days === $this->get()) {
            return;
        }
        $this->config->save(self::KEY, $days);
    }
}
