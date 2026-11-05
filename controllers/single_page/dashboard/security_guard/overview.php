<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard;

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\BaseController;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Period;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;
use PasichDev\SecurityGuard\Audit\Checklist;
use PasichDev\SecurityGuard\Config\Settings;
use PasichDev\SecurityGuard\Contract\AlertServiceInterface;
use PasichDev\SecurityGuard\Contract\BlockServiceInterface;
use PasichDev\SecurityGuard\Contract\EventLogInterface;
use PasichDev\SecurityGuard\Contract\StatsRepositoryInterface;
use PasichDev\SecurityGuard\Geo\CountryGuesser;

defined('C5_EXECUTE') or die('Access Denied.');

class Overview extends BaseController
{
    /** Тривалості ручного бану для швидкої кнопки (секунди; null — за ескалацією; 0 — назавжди). */
    public const QUICK_DURATIONS = ['escalation', '3600', '86400', '604800', '2592000', '0'];

    public function view()
    {
        $period = Period::fromInput($this->queryString('period', 10), $this->queryString('from', 10), $this->queryString('to', 10));
        $this->set('period', $period);

        $settings = $this->safe(function () {
            return $this->settings()->all();
        }, Settings::DEFAULTS, t('Settings'));
        $this->set('settings', $settings);
        $this->set('modules', $this->modules($settings));

        // Плитки: сьогодні / 7 / 30 днів — з одного підсумку за 30 днів.
        $last30 = Period::lastDays(30);
        $events = $this->lazy(EventLogInterface::class);
        $sum30 = $this->safe(function () use ($events, $last30) {
            return $events->summary($last30->fromTs, $last30->toTs);
        }, [], t('Event log'));
        $byDay30 = (array) ($sum30['byDay'] ?? []);
        $days30 = $last30->days();
        $today = end($days30);
        $last7 = array_slice($days30, -7);
        $tiles = [
            'today' => (int) ($byDay30[$today] ?? 0),
            'd7' => array_sum(array_map(static function ($d) use ($byDay30) {
                return (int) ($byDay30[$d] ?? 0);
            }, $last7)),
            'd30' => (int) ($sum30['total'] ?? array_sum(array_map('intval', $byDay30))),
            'ips30' => (int) ($sum30['uniqueIps'] ?? 0),
        ];

        $sum = ($period->key === '30') ? $sum30 : $this->safe(function () use ($events, $period) {
            return $events->summary($period->fromTs, $period->toTs);
        }, [], t('Event log'));
        $this->set('summary', $sum);

        $tiles['activeBans'] = (int) $this->safe(function () {
            return $this->service(BlockServiceInterface::class)->countActive();
        }, 0, t('Blocks'));

        // Дані логів хостингу за період.
        $stats = $this->lazy(StatsRepositoryInterface::class);
        $statDays = $this->safe(function () use ($stats, $period) {
            return $stats->getDays($period->fromDay, $period->toDay);
        }, [], t('Hosting log statistics'));
        $statSum = $this->safe(function () use ($stats, $period) {
            return $stats->summarize($period->fromDay, $period->toDay);
        }, [], '');
        $this->set('statSum', $statSum);
        $this->set('lastIngestAt', (int) $this->safe(function () use ($stats) {
            return $stats->lastIngestAt();
        }, 0, ''));

        $tiles['loginFailed'] = (int) ($statSum['loginFailed'] ?? 0);
        $tiles['bruteforce'] = (int) ($sum['byCategory']['bruteforce'] ?? 0);
        $tiles['overload'] = (int) ($statSum['overload508'] ?? 0);
        // Фаєрвол хостингу (ModSecurity/Imunify): 403 до PHP, видно лише з логів. У старих рядках полів немає.
        $tiles['hostWaf'] = (int) ($statSum['hostWafBlocked'] ?? 0);
        $tiles['hostWafIps'] = (int) ($statSum['hostWafIps'] ?? 0);
        $tiles['hostWafIpsApprox'] = !empty($statSum['hostWafIpsApprox']);
        $this->set('tiles', $tiles);

        // Ряди для графіків по днях періоду.
        $byStatDay = [];
        foreach ((array) $statDays as $row) {
            if (isset($row['day'])) {
                $byStatDay[(string) $row['day']] = $row;
            }
        }
        $wafByDay = (array) ($sum['byDay'] ?? []);
        $series = ['waf' => [], 'logAttacks' => [], 'total' => [], 'overload' => [], 'wafVsHost' => []];
        $hasHostWaf = false;
        foreach ($period->days() as $d) {
            $label = substr($d, 8, 2) . '.' . substr($d, 5, 2);
            $title = substr($d, 8, 2) . '.' . substr($d, 5, 2) . '.' . substr($d, 0, 4);
            $series['waf'][] = ['label' => $label, 'title' => $title, 'value' => (int) ($wafByDay[$d] ?? 0)];
            $series['logAttacks'][] = ['label' => $label, 'title' => $title, 'value' => (int) ($byStatDay[$d]['attackRequests'] ?? 0)];
            $series['total'][] = ['label' => $label, 'title' => $title, 'value' => (int) ($byStatDay[$d]['totalRequests'] ?? 0)];
            $series['overload'][] = ['label' => $label, 'title' => $title, 'value' => (int) ($byStatDay[$d]['overload508'] ?? 0)];
            $host = (int) ($byStatDay[$d]['hostWafBlocked'] ?? 0);
            $hasHostWaf = $hasHostWaf || $host > 0;
            $series['wafVsHost'][] = ['label' => $label, 'title' => $title, 'values' => [(int) ($wafByDay[$d] ?? 0), $host]];
        }
        $this->set('series', $series);
        $this->set('hasHostWaf', $hasHostWaf || $tiles['hostWaf'] > 0);
        $this->set('hasStats', !empty($byStatDay));

        // Обидва джерела: журнал фаєрвола (живі події) і логи хостингу (усі запити,
        // зокрема ті, що не дійшли до PHP). Огляд не має бути порожнім, коли логи мають дані.
        $logBreakdown = (array) ($statSum['breakdown'] ?? []);
        $hostBreakdown = (array) ($logBreakdown['hostWaf'] ?? []);
        $this->set('categorySources', [
            'waf' => (array) ($sum['byCategory'] ?? []),
            'hostWaf' => (array) ($hostBreakdown['categories'] ?? []),
            'logs' => (array) ($logBreakdown['categories'] ?? []),
        ]);

        $ips = [];
        foreach ((array) ($sum['topIps'] ?? []) as $row) {
            $ip = (string) ($row['ip'] ?? '');
            if ($ip === '') {
                continue;
            }
            $ips[$ip] = ['ip' => $ip, 'waf' => (int) ($row['count'] ?? 0), 'host' => 0, 'logs' => 0, 'country' => strtoupper((string) ($row['country'] ?? '')), 'bot' => ''];
        }
        foreach (Format::pairs($logBreakdown['topAttackIps'] ?? [], 20) as [$ip, $n, $raw]) {
            if ($ip === '') {
                continue;
            }
            $ips[$ip] = ($ips[$ip] ?? ['ip' => $ip, 'waf' => 0, 'host' => 0, 'logs' => 0, 'country' => '', 'bot' => '']);
            $ips[$ip]['logs'] = $n;
            // Поле bot може бути відсутнім у старих рядках.
            if (!empty($raw['bot']) && is_string($raw['bot'])) {
                $ips[$ip]['bot'] = $raw['bot'];
            }
        }
        foreach (Format::pairs($hostBreakdown['topIps'] ?? [], 20) as [$ip, $n, $raw]) {
            if ($ip === '') {
                continue;
            }
            $ips[$ip] = ($ips[$ip] ?? ['ip' => $ip, 'waf' => 0, 'host' => 0, 'logs' => 0, 'country' => '', 'bot' => '']);
            $ips[$ip]['host'] = $n;
            if (!empty($raw['bot']) && is_string($raw['bot'])) {
                $ips[$ip]['bot'] = $raw['bot'];
            }
        }
        uasort($ips, static function ($a, $b) {
            return max($b['waf'], $b['host'], $b['logs']) <=> max($a['waf'], $a['host'], $a['logs']);
        });
        $ips = array_slice(array_values($ips), 0, 10);
        $blocks = $this->lazy(BlockServiceInterface::class);
        foreach ($ips as $i => $row) {
            if ($row['country'] === '') {
                $ips[$i]['country'] = $this->guessCountry($row['ip']);
            }
            $ip = $row['ip'];
            $ips[$i]['banned'] = $this->safe(function () use ($blocks, $ip) {
                return $blocks->find($ip) !== null;
            }, false, '');
        }
        $this->set('topIps', $ips);

        // Країни: з журналу фаєрвола і (оцінка) з топу атакуючих IP логів.
        $wafCountries = [];
        foreach ((array) ($sum['topIps'] ?? []) as $row) {
            $cc = strtoupper((string) ($row['country'] ?? ''));
            if ($cc !== '') {
                $wafCountries[$cc] = ($wafCountries[$cc] ?? 0) + (int) ($row['count'] ?? 0);
            }
        }
        $logCountries = (array) ($logBreakdown['countries'] ?? []);
        if (!$logCountries) {
            foreach (Format::pairs($logBreakdown['topAttackIps'] ?? [], 50) as [$ip, $n]) {
                $cc = $this->guessCountry($ip);
                if ($cc !== '') {
                    $logCountries[$cc] = ($logCountries[$cc] ?? 0) + $n;
                }
            }
        }
        $this->set('countrySources', ['waf' => $wafCountries, 'logs' => $logCountries]);

        $this->set('recentEvents', (array) ($this->safe(function () use ($events) {
            return $events->query([], 10, 0);
        }, ['rows' => []], '')['rows'] ?? []));
        $this->set('alerts', $this->safe(function () {
            return $this->service(AlertServiceInterface::class)->recent(8);
        }, ['rows' => [], 'total' => 0], t('Alerts')));

        $this->set('audit', Checklist::lastResult($this->app));
        $this->set('clientIps', $this->clientIps());
        $this->set('quickDurations', self::QUICK_DURATIONS);
        $this->set('pageTitle', t('Security Guard'));
    }

    protected function guessCountry(string $ip): string
    {
        return (string) $this->safe(function () use ($ip) {
            return class_exists(CountryGuesser::class) ? CountryGuesser::guess($ip) : '';
        }, '', '');
    }

    /** Перемикання monitor → enforce (і назад) з явним підтвердженням. */
    public function switch_mode()
    {
        if (!$this->isValidPost('sg_switch_mode')) {
            return $this->back();
        }
        $target = $this->postString('mode', 16) === Settings::MODE_ENFORCE ? Settings::MODE_ENFORCE : Settings::MODE_MONITOR;
        if ($target === Settings::MODE_ENFORCE && !$this->request->request->get('confirm')) {
            $this->notify('error', t('Please confirm that you have reviewed the event log before switching to enforce mode.'));

            return $this->back();
        }
        $ok = $this->safe(function () use ($target) {
            $this->settings()->set('mode', $target);
            if ($target === Settings::MODE_ENFORCE) {
                $this->settings()->set('enabled', true);
            }

            return true;
        }, false, t('Settings'));
        if ($ok) {
            $this->rebuildState();
            $this->notify('success', $target === Settings::MODE_ENFORCE
                ? t('Enforce mode is on: attacks are now blocked.')
                : t('Monitor mode is on: attacks are only logged.'));
        } else {
            $this->notify('error', t('Could not change the mode.'));
        }

        return $this->back();
    }

    /** «Оновити з логів хостингу» — обмежене за часом дочитування. */
    public function ingest()
    {
        if (!$this->isValidPost('sg_ingest')) {
            return $this->back();
        }
        $this->runIngest();

        return $this->back($this->postedPeriod());
    }

    /** Швидкий бан IP з топу атакуючих. */
    public function ban_ip()
    {
        if (!$this->isValidPost('sg_ban_ip')) {
            return $this->back();
        }
        $this->doBan($this->postString('ip', 45), $this->postString('duration', 16), 'MANUAL', 'manual');

        return $this->afterBan($this->back($this->postedPeriod()));
    }

    public function mark_alerts_read()
    {
        if (!$this->isValidPost('sg_alerts_read')) {
            return $this->back();
        }
        $ok = $this->safe(function () {
            $this->service(AlertServiceInterface::class)->markAllRead();

            return true;
        }, false, t('Alerts'));
        if ($ok) {
            $this->notify('success', t('All alerts are marked as read.'));
        }

        return $this->back();
    }

    /**
     * Стан модулів захисту для «балу захисту».
     *
     * @return array<int, array{label: string, on: bool, weight: int}>
     */
    protected function modules(array $s): array
    {
        $rulesOn = 0;
        $rulesAll = ['rules_sql_injection', 'rules_xss', 'rules_path_traversal', 'rules_code_exec', 'rules_joomla_exploits', 'rules_wordpress_probes', 'rules_webshells', 'rules_sensitive_files', 'rules_bad_user_agents'];
        foreach ($rulesAll as $k) {
            $rulesOn += !empty($s[$k]) ? 1 : 0;
        }

        return [
            ['label' => t('Firewall enabled'), 'on' => !empty($s['enabled']), 'weight' => 3],
            ['label' => t('Enforce mode (attacks are blocked)'), 'on' => ($s['mode'] ?? '') === Settings::MODE_ENFORCE, 'weight' => 3],
            ['label' => t('Attack signatures (%s of %s groups)', $rulesOn, count($rulesAll)), 'on' => $rulesOn === count($rulesAll), 'weight' => 2],
            ['label' => t('Password guessing protection'), 'on' => !empty($s['bruteforce_enabled']), 'weight' => 2],
            ['label' => t('Honeypot traps'), 'on' => !empty($s['honeypot_enabled']), 'weight' => 1],
            ['label' => t('Rate limiting'), 'on' => !empty($s['rate_limit_enabled']), 'weight' => 1],
            ['label' => t('PHP probe burst detection'), 'on' => !empty($s['php_probe_enabled']), 'weight' => 1],
            ['label' => t('Behaviour scoring'), 'on' => !empty($s['behavior_scoring']), 'weight' => 1],
            ['label' => t('Search bot verification'), 'on' => !empty($s['verify_search_bots']), 'weight' => 1],
            ['label' => t('Traffic spike detection'), 'on' => !empty($s['ddos_enabled']), 'weight' => 1],
            ['label' => t('E-mail alerts'), 'on' => trim((string) ($s['notify_emails'] ?? '')) !== '', 'weight' => 1],
            ['label' => t('Emergency bypass token set'), 'on' => trim((string) ($s['bypass_token'] ?? '')) !== '', 'weight' => 1],
        ];
    }
}
