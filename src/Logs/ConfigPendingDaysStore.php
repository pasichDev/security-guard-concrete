<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

use Concrete\Core\Package\PackageService;

/**
 * Службовий стан імпорту в БД-конфігу пакета, поза групою settings:
 * черга днів до перерахунку (log_ingest.pending_days) і ознаки сторінки 403
 * хостингу (log_ingest.host_waf), покажчик днів у файлах (log_ingest.day_index).
 */
final class ConfigPendingDaysStore implements PendingDaysStoreInterface, HostWafStateStoreInterface, DayIndexStoreInterface
{
    public const DAY_INDEX_KEY = 'log_ingest.day_index';
    public const EXCLUDE_KEY = 'log_ingest.exclude_fingerprint';
    public const KEY = 'log_ingest.pending_days';
    public const HOST_WAF_KEY = 'log_ingest.host_waf';

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

    /** Стан детектора 403 хостингу (інтерфейс HostWafStateStoreInterface). */
    public function getHostWafState(): array
    {
        $v = $this->config->get(self::HOST_WAF_KEY);

        return is_array($v) ? $v : [];
    }

    public function setHostWafState(array $state): void
    {
        if ($state !== $this->getHostWafState()) {
            $this->config->save(self::HOST_WAF_KEY, $state);
        }
    }

    public function getDayIndex(): array
    {
        $v = $this->config->get(self::DAY_INDEX_KEY);

        return is_array($v) ? $v : [];
    }

    public function setDayIndex(array $index): void
    {
        if ($index !== $this->getDayIndex()) {
            $this->config->save(self::DAY_INDEX_KEY, $index);
        }
    }

    /** Відбиток списку виключених IP, з яким пораховані збережені дні. */
    public function getExcludeFingerprint(): string
    {
        return (string) $this->config->get(self::EXCLUDE_KEY, '');
    }

    public function setExcludeFingerprint(string $fp): void
    {
        if ($fp !== $this->getExcludeFingerprint()) {
            $this->config->save(self::EXCLUDE_KEY, $fp);
        }
    }
}
