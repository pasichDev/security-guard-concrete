<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

use Concrete\Core\Application\Application;
use Concrete\Core\Database\Connection\Connection;
use Concrete\Core\Package\PackageService;
use DateTimeZone;
use PasichDev\SecurityGuard\Config\Settings;
use PasichDev\SecurityGuard\Contract\LogIngestInterface;
use PasichDev\SecurityGuard\Rules\RuleSet;
use PasichDev\SecurityGuard\Stats\StatsRepository;
use PasichDev\SecurityGuard\Update\BotRangeStore;
use Throwable;

/**
 * Читання логів хостингу в SecurityGuardDailyStats (CLI-команда і кнопка на панелі).
 * Уся логіка — в IngestEngine; тут лише складання залежностей Concrete.
 */
final class LogIngest implements LogIngestInterface
{
    /** @var Application */
    private $app;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    public function ingest(int $timeBudget = 0): array
    {
        return $this->run(['timeBudget' => $timeBudget]);
    }

    /**
     * Розширений запуск (CLI).
     * @param array{timeBudget?:int, days?:int, rebuild?:bool, logRoot?:string, domain?:string, excludeIps?:string} $options
     * @return array{files:int, lines:int, days:string[], finished:bool, errors:string[], pending?:int, deduplicated?:int, malformed?:int}
     */
    public function run(array $options = []): array
    {
        $empty = ['files' => 0, 'lines' => 0, 'days' => [], 'finished' => false, 'errors' => []];
        $lock = null;
        try {
            $lock = $this->acquireLock();
            if ($lock === false) {
                return ['errors' => [t('Another log import is already running.')]] + $empty;
            }
            $settings = $this->app->make(Settings::class)->all();
            $locator = $this->locator($options, $settings);
            $sources = $locator->discover();
            if (!$sources) {
                return ['errors' => [$this->noSourcesMessage($locator)]] + $empty;
            }
            if (!$this->app->isRunThroughCommandLineInterface()) {
                // Запас понад бюджет: одна група днів може трохи перевищити його.
                @set_time_limit(max(60, (int) ($options['timeBudget'] ?? 0) * 3));
            }
            $db = $this->app->make(Connection::class);
            $pendingStore = $this->pendingStore();
            $engine = new IngestEngine(
                $this->timezone(),
                static function () use ($settings): AttackClassifierInterface {
                    return new RuleSetClassifier(new RuleSet($settings));
                },
                new IpMatcher(trim((string) $settings['log_exclude_ips'] . "\n" . (string) ($options['excludeIps'] ?? ''))),
                new DbCursorStore($db),
                $pendingStore,
                new StatsRepository($db),
                new CrawlerVerifier($this->verifiedBotIps($db), (new BotRangeStore($db))->rangesByBot()),
                $pendingStore instanceof HostWafStateStoreInterface ? $pendingStore : null
            );

            return $engine->run($sources, [
                'timeBudget' => (int) ($options['timeBudget'] ?? 0),
                'days' => (int) ($options['days'] ?? 0),
                'rebuild' => !empty($options['rebuild']),
                'hostWafDetect' => !empty($settings['host_waf_detect']),
                'hostWafSizes' => (string) ($settings['host_waf_sizes'] ?? ''),
            ]);
        } catch (Throwable $e) {
            $this->logError($e);

            return ['errors' => [$e->getMessage()]] + $empty;
        } finally {
            if (is_resource($lock)) {
                @flock($lock, LOCK_UN);
                @fclose($lock);
            }
        }
    }

    public function discoverSources(): array
    {
        try {
            $settings = $this->app->make(Settings::class)->all();
            $out = [];
            foreach ($this->locator([], $settings)->discover() as $path => $meta) {
                $out[$path] = $meta['size'];
            }

            return $out;
        } catch (Throwable $e) {
            $this->logError($e);

            return [];
        }
    }

    /** @param array{logRoot?:string, domain?:string} $options */
    public function locator(array $options = [], ?array $settings = null): SourceLocator
    {
        $settings = $settings ?? $this->app->make(Settings::class)->all();
        $domain = (string) ($options['domain'] ?? '');
        if ($domain === '') {
            $domain = $this->siteDomain();
        }
        $home = (string) ($options['logRoot'] ?? '');
        if ($home === '') {
            $home = (string) ($settings['log_root'] ?? '');
        }
        if ($home === '') {
            $home = (string) SourceLocator::detectHome(defined('DIR_BASE') ? DIR_BASE : null, $domain);
        }

        return new SourceLocator($home === '' ? null : $home, $domain, (string) ($settings['log_sources'] ?? ''));
    }

    /**
     * IP, які WAF уже підтвердив rDNS як пошукові боти (SecurityGuardBotCache).
     * @return array<string, string> ip => назва
     */
    private function verifiedBotIps(Connection $db): array
    {
        $out = [];
        try {
            foreach ($db->fetchAllAssociative('SELECT ip, botName FROM SecurityGuardBotCache WHERE isBot = 1') as $r) {
                if ((string) $r['botName'] !== '') {
                    $out[(string) $r['ip']] = (string) $r['botName'];
                }
            }
        } catch (Throwable $e) {
            // Таблиці може ще не бути — обходимось опублікованими діапазонами.
        }

        return $out;
    }

    /** Черга днів: БД-конфіг пакета; у тестах можна підмінити прив'язкою інтерфейсу. */
    private function pendingStore(): PendingDaysStoreInterface
    {
        if ($this->app->bound(PendingDaysStoreInterface::class)) {
            return $this->app->make(PendingDaysStoreInterface::class);
        }

        return new ConfigPendingDaysStore($this->app->make(PackageService::class));
    }

    public function timezone(): DateTimeZone
    {
        try {
            $tz = (string) $this->app->make('site')->getSite()->getTimezone();
            if ($tz !== '') {
                return new DateTimeZone($tz);
            }
        } catch (Throwable $e) {
        }

        return new DateTimeZone(date_default_timezone_get() ?: 'UTC');
    }

    private function siteDomain(): string
    {
        try {
            $site = $this->app->make('site')->getSite();
            $url = $site ? (string) $site->getSiteCanonicalURL() : '';
            if ($url !== '') {
                return SourceLocator::normalizeDomain($url);
            }
        } catch (Throwable $e) {
        }
        if (!$this->app->isRunThroughCommandLineInterface()) {
            try {
                return SourceLocator::normalizeDomain((string) $this->app->make('request')->getHost());
            } catch (Throwable $e) {
            }
        }

        return '';
    }

    private function noSourcesMessage(SourceLocator $locator): string
    {
        if ($locator->home() === null) {
            return t('Hosting log directory not found. Set the log file paths in the settings.');
        }
        if ($locator->domain() === '' && !$locator->patterns()) {
            return t('The site domain is unknown (no canonical URL). Set the log file paths in the settings.');
        }

        return t('No readable log files found: %s', implode(', ', $locator->patterns()));
    }

    /**
     * Блокування від одночасних запусків (cron + кнопка на панелі). Файл — у
     * тимчасовому каталозі, щоб CLI від іншого користувача не створив каталог
     * пакета в application/files з чужим власником.
     * @return resource|false|null null — блокування недоступне (працюємо без нього)
     */
    private function acquireLock()
    {
        $key = defined('DIR_BASE') ? DIR_BASE : __DIR__;
        $h = @fopen(rtrim(sys_get_temp_dir(), '/') . '/security_guard_ingest_' . substr(md5($key), 0, 12) . '.lock', 'c');
        if (!$h) {
            return null;
        }
        if (!flock($h, LOCK_EX | LOCK_NB)) {
            fclose($h);

            return false;
        }

        return $h;
    }

    private function logError(Throwable $e): void
    {
        try {
            $this->app->make('log')->error('Security Guard log import: ' . $e->getMessage());
        } catch (Throwable $ignored) {
        }
    }
}
