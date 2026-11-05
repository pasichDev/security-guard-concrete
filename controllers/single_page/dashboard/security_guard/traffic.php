<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard;

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\BaseController;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Period;
use PasichDev\SecurityGuard\Contract\LogIngestInterface;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;
use PasichDev\SecurityGuard\Contract\StatsRepositoryInterface;
use Concrete\Core\Database\Connection\Connection;
use PasichDev\SecurityGuard\Geo\CountryGuesser;
use PasichDev\SecurityGuard\Update\BotRangeStore;
use PasichDev\SecurityGuard\Update\BotRangeUpdater;
use PasichDev\SecurityGuard\Update\HttpFetcher;

defined('C5_EXECUTE') or die('Access Denied.');

class Traffic extends BaseController
{
    /** Колонки SecurityGuardDailyStats, для яких малюються графіки по днях. */
    private const DAY_SERIES = ['totalRequests', 'attackRequests', 'uniqueIps', 'errors404', 'errors5xx', 'overload508', 'botRequests', 'bytes', 'hostWafBlocked'];

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
        $cache = $this->logSourcesCache();
        $this->set('sources', (array) $cache['sources']);
        $this->set('sourcesAt', (int) ($cache['at'] ?? 0));
        $this->set('botRanges', $this->botRanges());
        $this->set('canUpdateRanges', $this->rangeUpdater() !== null);
        $this->set('excludedIps', (string) $this->safe(function () {
            return $this->settings()->get('log_exclude_ips');
        }, '', ''));
    }

    /** «Оновити діапазони ботів зараз» — лише якщо сервіс оновлення є в пакеті. */
    public function update_ranges()
    {
        if (!$this->isValidPost('sg_update_ranges')) {
            return $this->back();
        }
        $updater = $this->rangeUpdater();
        if ($updater === null) {
            $this->notify('error', t('The bot range update service is not available in this version.'));

            return $this->back();
        }
        if (function_exists('set_time_limit')) {
            @set_time_limit(90);
        }
        $result = $this->safe(function () use ($updater) {
            return $updater[0]->{$updater[1]}();
        }, false, t('Bot range update'));
        if (is_array($result) && empty($result['updated']) && empty($result['unchanged'])) {
            $this->describeUpdate($result);
            $this->notify('error', t('Could not update the bot ranges.'));
        } elseif ($result === false) {
            $this->notify('error', t('Could not update the bot ranges.') . ($this->serviceErrors ? ' ' . implode(' ', $this->serviceErrors) : ''));
        } else {
            $this->rebuildState();
            $this->notify('success', t('Bot ranges updated.') . $this->describeUpdate($result));
        }

        return $this->back($this->postedPeriod());
    }

    /** Повторний пошук файлів логів (результат зберігається, сторінки його лише читають). */
    public function refresh_sources()
    {
        if (!$this->isValidPost('sg_refresh_sources')) {
            return $this->back();
        }
        $r = $this->refreshLogSources();
        $this->notify('success', t('Log sources found: %s.', count((array) ($r['sources'] ?? []))));

        return $this->back($this->postedPeriod());
    }

    public function ingest()
    {
        if (!$this->isValidPost('sg_ingest')) {
            return $this->back();
        }
        $this->runIngest();

        return $this->back($this->postedPeriod());
    }

    /**
     * Стан діапазонів ботів (SecurityGuardBotRanges): [['bot','source','fetchedAt','count'], ...].
     * null — таблиці чи рядків немає: працюють вбудовані діапазони.
     */
    protected function botRanges(): ?array
    {
        $meta = $this->safe(function () {
            if (!class_exists(BotRangeStore::class)) {
                return [];
            }

            return (new BotRangeStore($this->app->make(Connection::class)))->meta();
        }, [], '');
        if (!$meta) {
            return null;
        }
        $out = [];
        foreach ($meta as $bot => $m) {
            $out[] = [
                'bot' => (string) $bot,
                'source' => (string) ($m['source'] ?? ''),
                'fetchedAt' => (int) ($m['fetchedAt'] ?? 0),
                'count' => (int) ($m['count'] ?? 0),
            ];
        }

        return $out;
    }

    /** Сервіс оновлення (так само, як у команді security-guard:update-ranges) або null. */
    protected function rangeUpdater(): ?array
    {
        if (!class_exists(BotRangeUpdater::class) || !class_exists(HttpFetcher::class) || !class_exists(BotRangeStore::class)) {
            return null;
        }
        $updater = $this->safe(function () {
            return new BotRangeUpdater(new HttpFetcher($this->app), new BotRangeStore($this->app->make(Connection::class)));
        }, null, '');

        return $updater ? [$updater, 'update'] : null;
    }

    /** Підсумок результату BotRangeUpdater::update(): updated / unchanged / errors. */
    protected function describeUpdate($result): string
    {
        if (!is_array($result)) {
            return '';
        }
        $parts = [];
        foreach ((array) ($result['updated'] ?? []) as $bot => $n) {
            $parts[] = t('%s: %s ranges updated', (string) $bot, (int) $n);
        }
        foreach ((array) ($result['unchanged'] ?? []) as $bot => $n) {
            $parts[] = t('%s: unchanged', (string) $bot);
        }
        $msg = $parts ? ' ' . implode('; ', $parts) . '.' : '';
        $errors = (array) ($result['errors'] ?? []);
        if ($errors) {
            $e = [];
            foreach ($errors as $bot => $err) {
                $e[] = $bot . ': ' . mb_substr((string) $err, 0, 120);
            }
            $this->notify('error', t('Some sources could not be downloaded:') . ' ' . implode('; ', $e));
        }

        return $msg;
    }
}
