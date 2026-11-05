<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard;

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\BaseController;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Period;
use PasichDev\SecurityGuard\Contract\LogIngestInterface;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;
use PasichDev\SecurityGuard\Contract\StatsRepositoryInterface;
use PasichDev\SecurityGuard\Geo\CountryGuesser;

defined('C5_EXECUTE') or die('Access Denied.');

class Traffic extends BaseController
{
    /** Колонки SecurityGuardDailyStats, для яких малюються графіки по днях. */
    private const DAY_SERIES = ['totalRequests', 'attackRequests', 'uniqueIps', 'errors404', 'errors5xx', 'overload508', 'botRequests', 'bytes'];

    public function view()
    {
        $period = Period::fromInput($this->queryString('period', 10), $this->queryString('from', 10), $this->queryString('to', 10));
        $stats = $this->lazy(StatsRepositoryInterface::class);
        $days = (array) $this->safe(function () use ($stats, $period) {
            return $stats->getDays($period->fromDay, $period->toDay);
        }, [], t('Hosting log statistics'));
        $sum = (array) $this->safe(function () use ($stats, $period) {
            return $stats->summarize($period->fromDay, $period->toDay);
        }, [], '');

        $byDay = [];
        foreach ($days as $row) {
            if (isset($row['day'])) {
                $byDay[(string) $row['day']] = $row;
            }
        }
        $series = array_fill_keys(self::DAY_SERIES, []);
        foreach ($period->days() as $d) {
            $label = substr($d, 8, 2) . '.' . substr($d, 5, 2);
            $title = $label . '.' . substr($d, 0, 4);
            foreach (self::DAY_SERIES as $col) {
                $series[$col][] = ['label' => $label, 'title' => $title, 'value' => (int) ($byDay[$d][$col] ?? 0)];
            }
        }

        $breakdown = (array) ($sum['breakdown'] ?? []);
        // Країн у логах немає — оцінюємо за топом IP офлайн-визначником.
        if (empty($breakdown['countries']) && class_exists(CountryGuesser::class)) {
            $countries = [];
            foreach (Format::pairs($breakdown['topIps'] ?? [], 50) as [$ip, $n]) {
                $cc = (string) $this->safe(function () use ($ip) {
                    return CountryGuesser::guess($ip);
                }, '', '');
                if ($cc !== '') {
                    $countries[$cc] = ($countries[$cc] ?? 0) + $n;
                }
            }
            $breakdown['countries'] = $countries;
            $this->set('countriesEstimated', true);
        }
        $hours = [];
        $rawHours = (array) ($breakdown['hours'] ?? []);
        for ($h = 0; $h < 24; ++$h) {
            $hours[] = ['label' => sprintf('%02d', $h), 'title' => sprintf('%02d:00–%02d:59', $h, $h), 'value' => (int) ($rawHours[$h] ?? $rawHours[(string) $h] ?? $rawHours[sprintf('%02d', $h)] ?? 0)];
        }

        $this->set('period', $period);
        $this->set('hasData', !empty($byDay));
        $this->set('sum', $sum);
        $this->set('series', $series);
        $this->set('hours', $hours);
        $this->set('breakdown', $breakdown);
        $this->set('lastIngestAt', (int) $this->safe(function () use ($stats) {
            return $stats->lastIngestAt();
        }, 0, ''));
        $this->set('sources', (array) $this->safe(function () {
            return $this->service(LogIngestInterface::class)->discoverSources();
        }, [], t('Hosting log sources')));
        $this->set('excludedIps', (string) $this->safe(function () {
            return $this->settings()->get('log_exclude_ips');
        }, '', ''));
    }

    public function ingest()
    {
        if (!$this->isValidPost('sg_ingest')) {
            return $this->back();
        }
        $this->runIngest();

        return $this->back($this->postedPeriod());
    }
}
