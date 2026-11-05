<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;

/**
 * @var Concrete\Core\Page\View\PageView $view
 * @var Concrete\Core\Validation\CSRF\Token $token
 * @var Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Period $period
 * @var array $settings
 * @var array $modules
 * @var array $tiles
 * @var array $summary
 * @var array $statSum
 * @var array $series
 * @var bool $hasStats
 * @var bool $hasHostWaf
 * @var array $topIps
 * @var array $categorySources
 * @var array $countrySources
 * @var array $recentEvents
 * @var array $alerts
 * @var array|null $audit
 * @var array $clientIps
 * @var int $lastIngestAt
 */

$pageUrl = (string) ($sgPageUrl ?? $view->action('view'));
$mode = (string) ($settings['mode'] ?? 'monitor');
$enabled = !empty($settings['enabled']);
$periodQuery = $period->query();

$scoreTotal = 0;
$scoreOn = 0;
foreach ($modules as $m) {
    $scoreTotal += $m['weight'];
    $scoreOn += $m['on'] ? $m['weight'] : 0;
}
$scorePct = $scoreTotal > 0 ? (int) round($scoreOn / $scoreTotal * 100) : 0;
$durationLabels = [
    'escalation' => t('By escalation rules'),
    '3600' => t('1 hour'),
    '86400' => t('24 hours'),
    '604800' => t('7 days'),
    '2592000' => t('30 days'),
    '0' => t('Permanent'),
];
?>
<div class="sg-page sg-overview">
    <?php View::element('nav', ['current' => $sgPagePath ?? '', 'mode' => $sgMode ?? '', 'errors' => $sgServiceErrors ?? []], 'security_guard'); ?>

    <?php if (!$enabled) { ?>
        <div class="alert alert-danger sg-banner">
            <strong><?= h(t('The firewall is disabled.')) ?></strong>
            <?= h(t('Requests are not checked at all. Enable it in the settings.')) ?>
            <a class="alert-link" href="<?= h((string) URL::to('/dashboard/security_guard/settings')) ?>"><?= h(t('Settings')) ?></a>
        </div>
    <?php } elseif ($mode !== 'enforce') { ?>
        <div class="alert alert-warning sg-banner">
            <div class="sg-banner-text">
                <strong><?= h(t('Monitor mode: attacks are logged, but nothing is blocked.')) ?></strong>
                <p class="mb-0"><?= h(t('This is the safe start after installation. Check the event log for a few days: if legitimate visitors or editors do not appear there, switch to enforce mode.')) ?></p>
            </div>
            <form method="post" action="<?= h((string) $view->action('switch_mode')) ?>" class="sg-banner-form d-print-none">
                <?php $token->output('sg_switch_mode'); ?>
                <input type="hidden" name="mode" value="enforce">
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" name="confirm" value="1" id="sg-confirm-enforce" required>
                    <label class="form-check-label" for="sg-confirm-enforce"><?= h(t('I have reviewed the event log and found no false positives')) ?></label>
                </div>
                <button type="submit" class="btn btn-warning btn-sm"><?= h(t('Switch to enforce mode')) ?></button>
            </form>
        </div>
    <?php } ?>

    <div class="sg-toolbar">
        <?php View::element('period_filter', ['period' => $period, 'baseUrl' => $pageUrl], 'security_guard'); ?>
        <div class="sg-toolbar-actions d-print-none">
            <form method="post" action="<?= h((string) $view->action('ingest')) ?>" class="d-inline" data-sg-busy="<?= h(t('Reading logs…')) ?>">
                <?php $token->output('sg_ingest'); ?>
                <?php foreach ($periodQuery as $qk => $qv) { ?><input type="hidden" name="<?= h($qk) ?>" value="<?= h($qv) ?>"><?php } ?>
                <button type="submit" class="btn btn-outline-primary btn-sm"><?= h(t('Update from hosting logs')) ?></button>
            </form>
            <button type="button" class="btn btn-outline-secondary btn-sm" data-sg-print><?= h(t('Print')) ?></button>
        </div>
    </div>
    <p class="sg-muted small sg-period-caption">
        <?= h(t('Period: %s – %s', Format::day($period->fromDay), Format::day($period->toDay))) ?>
        · <?= h($lastIngestAt > 0 ? t('Hosting logs read: %s', Format::dateTime($lastIngestAt)) : t('Hosting logs have not been read yet')) ?>
    </p>

    <div class="sg-tiles">
        <div class="sg-tile">
            <div class="sg-tile-k"><?= h(t('Attacks today')) ?></div>
            <div class="sg-tile-v"><?= h(Format::num($tiles['today'])) ?></div>
            <div class="sg-tile-s"><?= h(t('firewall log')) ?></div>
        </div>
        <div class="sg-tile">
            <div class="sg-tile-k"><?= h(t('Attacks, 7 days')) ?></div>
            <div class="sg-tile-v"><?= h(Format::num($tiles['d7'])) ?></div>
            <div class="sg-tile-s"><?= h(t('firewall log')) ?></div>
        </div>
        <div class="sg-tile">
            <div class="sg-tile-k"><?= h(t('Attacks, 30 days')) ?></div>
            <div class="sg-tile-v"><?= h(Format::num($tiles['d30'])) ?></div>
            <div class="sg-tile-s"><?= h(t('from %s IP addresses', Format::num($tiles['ips30']))) ?></div>
        </div>
        <a class="sg-tile sg-tile-link" href="<?= h((string) URL::to('/dashboard/security_guard/blocks')) ?>">
            <div class="sg-tile-k"><?= h(t('Active bans')) ?></div>
            <div class="sg-tile-v"><?= h(Format::num($tiles['activeBans'])) ?></div>
            <div class="sg-tile-s"><?= h(t('right now')) ?></div>
        </a>
        <div class="sg-tile">
            <div class="sg-tile-k"><?= h(t('Failed logins')) ?></div>
            <div class="sg-tile-v"><?= h(Format::num($tiles['loginFailed'])) ?></div>
            <div class="sg-tile-s"><?= h(t('hosting logs; password guessing events: %s', Format::num($tiles['bruteforce']))) ?></div>
        </div>
        <?php if ($hasHostWaf) { ?>
            <div class="sg-tile">
                <div class="sg-tile-k"><?= h(t('Blocked by the server (before PHP)')) ?></div>
                <div class="sg-tile-v"><?= h(Format::num($tiles['hostWaf'])) ?></div>
                <div class="sg-tile-s"><?= h(t('from %s IP addresses; hosting firewall (ModSecurity/Imunify) and .htaccess rules', (!empty($tiles['hostWafIpsApprox']) ? '≈' : '') . Format::num($tiles['hostWafIps']))) ?></div>
            </div>
        <?php } ?>
        <div class="sg-tile<?= $tiles['overload'] > 0 ? ' sg-tile-critical' : '' ?>">
            <div class="sg-tile-k"><?= h(t('Overload (508)')) ?></div>
            <div class="sg-tile-v"><?= h(Format::num($tiles['overload'])) ?></div>
            <div class="sg-tile-s"><?= h(t('refused by the hosting for the period')) ?></div>
        </div>
    </div>

    <div class="row g-3 sg-row">
        <div class="col-lg-6">
            <section class="sg-card h-100">
                <div class="sg-card-head">
                    <h3><?= h(t('Protection score')) ?></h3>
                    <span class="sg-score <?= $scorePct >= 85 ? 'sg-score-good' : ($scorePct >= 60 ? 'sg-score-mid' : 'sg-score-bad') ?>"><?= (int) $scorePct ?>%</span>
                </div>
                <ul class="sg-checks">
                    <?php foreach ($modules as $m) { ?>
                        <li class="<?= $m['on'] ? 'sg-on' : 'sg-off' ?>"><span class="sg-check-mark" aria-hidden="true"><?= $m['on'] ? '✓' : '✕' ?></span><span class="visually-hidden"><?= h($m['on'] ? t('On') : t('Off')) ?>:</span> <?= h($m['label']) ?></li>
                    <?php } ?>
                </ul>
                <a class="small d-print-none" href="<?= h((string) URL::to('/dashboard/security_guard/settings')) ?>"><?= h(t('Change settings')) ?></a>
            </section>
        </div>
        <div class="col-lg-6">
            <section class="sg-card h-100">
                <div class="sg-card-head">
                    <h3><?= h(t('Security check')) ?></h3>
                    <?php if ($audit) { ?><span class="sg-muted small"><?= h(Format::dateTime($audit['ranAt'] ?? 0)) ?></span><?php } ?>
                </div>
                <?php if (!$audit) { ?>
                    <p class="sg-muted"><?= h(t('The environment check has not been run yet. It inspects file permissions, publicly reachable files, security headers and versions.')) ?></p>
                <?php } else {
                    $auditCounts = (array) ($audit["counts"] ?? []); ?>
                    <div class="sg-audit-counts">
                        <span class="badge text-bg-danger"><?= h(t('Problems: %s', (int) ($auditCounts['fail'] ?? 0))) ?></span>
                        <span class="badge text-bg-warning"><?= h(t('Warnings: %s', (int) ($auditCounts['warn'] ?? 0))) ?></span>
                        <span class="badge text-bg-success"><?= h(t('OK: %s', (int) ($auditCounts['ok'] ?? 0))) ?></span>
                        <?php if (!empty($auditCounts['unknown'])) { ?><span class="badge text-bg-secondary"><?= h(t('Not checked: %s', (int) $auditCounts['unknown'])) ?></span><?php } ?>
                    </div>
                    <ul class="sg-checks mt-2">
                        <?php foreach ((array) ($audit['items'] ?? []) as $it) {
                            if (!in_array($it['status'] ?? '', ['fail', 'warn'], true)) {
                                continue;
                            } ?>
                            <li class="<?= ($it['status'] ?? '') === 'fail' ? 'sg-off' : 'sg-warn' ?>"><span class="sg-check-mark" aria-hidden="true">!</span> <?= h((string) ($it['title'] ?? '')) ?></li>
                        <?php } ?>
                    </ul>
                <?php } ?>
                <a class="small d-print-none" href="<?= h((string) URL::to('/dashboard/security_guard/checklist')) ?>"><?= h($audit ? t('Open the security check') : t('Run the security check')) ?></a>
            </section>
        </div>
    </div>

    <section class="sg-card sg-avoid-break">
        <div class="sg-card-head">
            <h3><?= h(t('Attacks by day — firewall')) ?></h3>
            <span class="sg-muted small"><?= h($hasHostWaf ? t('Security Guard on this site and requests the server rejected before PHP') : t('requests detected by the firewall on this site')) ?></span>
        </div>
        <?php if ($hasHostWaf) {
            View::element('chart_grouped', ['points' => $series['wafVsHost'], 'series' => [t('Security Guard'), t('Server (before PHP)')], 'unit' => '', 'aria' => t('Attacks by day — firewall')], 'security_guard');
        } else {
            View::element('chart_bars', ['points' => $series['waf'], 'unit' => t('attacks'), 'aria' => t('Attacks by day — firewall')], 'security_guard');
        } ?>
    </section>

    <?php if ($hasStats) { ?>
        <section class="sg-card sg-avoid-break">
            <div class="sg-card-head">
                <h3><?= h(t('Attacks by day — hosting logs')) ?></h3>
                <span class="sg-muted small"><?= h(t('including requests that never reached PHP')) ?></span>
            </div>
            <?php View::element('chart_bars', ['points' => $series['logAttacks'], 'unit' => t('attacks'), 'aria' => t('Attacks by day — hosting logs')], 'security_guard'); ?>
        </section>
        <section class="sg-card sg-avoid-break">
            <div class="sg-card-head">
                <h3><?= h(t('All requests by day')) ?></h3>
                <span class="sg-muted small"><?= h(t('visitors, search engines, bots and attacks together')) ?></span>
            </div>
            <?php View::element('chart_bars', ['points' => $series['total'], 'unit' => t('requests'), 'height' => 190, 'labels' => 2, 'aria' => t('All requests by day')], 'security_guard'); ?>
        </section>
        <section class="sg-card sg-avoid-break">
            <div class="sg-card-head">
                <h3><?= h(t('Overload (508) by day')) ?></h3>
                <span class="sg-muted small"><?= h(t('the hosting refused requests because of the resource limit')) ?></span>
            </div>
            <?php View::element('chart_bars', ['points' => $series['overload'], 'unit' => t('refusals (508)'), 'height' => 160, 'labels' => 4, 'critical' => true, 'aria' => t('Overload (508) by day'), 'empty' => t('No overloads in this period.')], 'security_guard'); ?>
        </section>
    <?php } else { ?>
        <div class="alert alert-info"><?= h(t('There is no data from the hosting access logs for this period yet. Press "Update from hosting logs" or set up the cron command security-guard:ingest.')) ?></div>
    <?php } ?>

    <?php
    // Блок «два джерела»: показуємо ті, де є дані; якщо даних немає ніде — одне повідомлення.
    $twoSources = static function (array $sources, callable $toRows, string $empty) {
        $labels = ['waf' => t('Firewall log'), 'hostWaf' => t('Server (before PHP)'), 'logs' => t('Hosting logs')];
        $shown = 0;
        foreach ($sources as $key => $data) {
            $rows = $toRows($data);
            if (!$rows) {
                continue;
            }
            ++$shown; ?>
            <div class="sg-source">
                <div class="sg-source-label"><?= h($labels[$key] ?? $key) ?></div>
                <?php View::element('chart_hbars', ['rows' => $rows], 'security_guard'); ?>
            </div>
        <?php }
        if ($shown === 0) { ?>
            <div class="sg-chart-empty"><?= h($empty) ?></div>
        <?php } elseif ($shown === 1) {
            foreach ($sources as $key => $data) {
                if ($key !== 'hostWaf' && !$toRows($data)) { ?>
                    <p class="small sg-muted mb-0 mt-2"><?= h($key === 'waf' ? t('The firewall log has no events for this period yet.') : t('No hosting log data for this period.')) ?></p>
                <?php }
            }
        }
    };
    $catRows = static function (array $data) {
        $rows = [];
        foreach (Format::pairs($data, 12) as [$cat, $n]) {
            $rows[] = ['label' => Format::categoryLabel($cat), 'value' => $n, 'critical' => $cat === 'ddos'];
        }

        return $rows;
    };
    $countryRows = static function (array $data) {
        $rows = [];
        foreach (Format::pairs($data, 8) as [$cc, $n]) {
            $rows[] = ['label' => trim(Format::flag($cc) . ' ' . strtoupper($cc)), 'value' => $n];
        }

        return $rows;
    };
    ?>
    <div class="row g-3 sg-row">
        <div class="col-lg-7">
            <section class="sg-card h-100 sg-avoid-break">
                <div class="sg-card-head"><h3><?= h(t('What attackers were looking for')) ?></h3></div>
                <?php $twoSources($categorySources, $catRows, t('No attacks in this period.')); ?>
            </section>
        </div>
        <div class="col-lg-5">
            <section class="sg-card h-100 sg-avoid-break">
                <div class="sg-card-head">
                    <h3><?= h(t('Top countries')) ?></h3>
                    <span class="small sg-muted"><?= h(t('for hosting logs: estimated from the top attacking IPs')) ?></span>
                </div>
                <?php $twoSources($countrySources, $countryRows, t('No country data.')); ?>
            </section>
        </div>
    </div>

    <section class="sg-card">
        <div class="sg-card-head">
            <h3><?= h(t('Top attacking IP addresses')) ?></h3>
            <a class="small d-print-none" href="<?= h((string) URL::to('/dashboard/security_guard/events')) ?>"><?= h(t('Event log')) ?></a>
        </div>
        <?php if (!$topIps) { ?>
            <div class="sg-chart-empty"><?= h(t('No attacks in this period.')) ?></div>
        <?php } else { ?>
            <div class="table-responsive">
                <table class="table table-sm align-middle sg-table">
                    <thead><tr>
                        <th><?= h(t('IP address')) ?></th>
                        <th><?= h(t('Country')) ?></th>
                        <th class="text-end"><?= h(t('Firewall log')) ?></th>
                        <?php if ($hasHostWaf) { ?><th class="text-end"><?= h(t('Server (before PHP)')) ?></th><?php } ?>
                        <th class="text-end"><?= h(t('Hosting logs')) ?></th>
                        <th class="d-print-none"><?= h(t('Action')) ?></th>
                    </tr></thead>
                    <tbody>
                    <?php foreach ($topIps as $row) {
                        $ip = (string) ($row['ip'] ?? '');
                        $cc = (string) ($row['country'] ?? ''); ?>
                        <tr>
                            <td><a class="sg-ip" href="<?= h((string) URL::to('/dashboard/security_guard/events') . '?ip=' . rawurlencode($ip)) ?>"><?= h($ip) ?></a></td>
                            <td class="text-nowrap"><?= h(trim(Format::flag($cc) . ' ' . strtoupper($cc))) ?: '—' ?></td>
                            <td class="text-end sg-num"><?= (int) $row['waf'] > 0 ? h(Format::num($row['waf'])) : '—' ?></td>
                            <?php if ($hasHostWaf) { ?><td class="text-end sg-num"><?= (int) ($row['host'] ?? 0) > 0 ? h(Format::num($row['host'])) : '—' ?></td><?php } ?>
                            <td class="text-end sg-num"><?= (int) $row['logs'] > 0 ? h(Format::num($row['logs'])) : '—' ?></td>
                            <td class="d-print-none">
                                <?php if (!empty($row['banned'])) { ?>
                                    <span class="badge text-bg-danger"><?= h(t('Banned')) ?></span>
                                <?php } elseif (in_array($ip, $clientIps['all'], true)) { ?>
                                    <span class="badge text-bg-info"><?= h(t('Your IP')) ?></span>
                                <?php } elseif (!empty($row['bot'])) { ?>
                                    <span class="badge text-bg-secondary" title="<?= h(t('Search engine crawler: one-click ban is disabled')) ?>"><?= h(t('Bot: %s', Format::truncate($row['bot'], 40))) ?></span>
                                <?php } else { ?>
                                    <form method="post" action="<?= h((string) $view->action('ban_ip')) ?>" class="sg-inline-form" data-sg-confirm="<?= h(t('Block %s?', $ip)) ?>">
                                        <?php $token->output('sg_ban_ip'); ?>
                                        <input type="hidden" name="ip" value="<?= h($ip) ?>">
                                        <?php foreach ($periodQuery as $qk => $qv) { ?><input type="hidden" name="<?= h($qk) ?>" value="<?= h($qv) ?>"><?php } ?>
                                        <label class="visually-hidden" for="sg-dur-<?= h(md5($ip)) ?>"><?= h(t('Duration')) ?></label>
                                        <select name="duration" id="sg-dur-<?= h(md5($ip)) ?>" class="form-select form-select-sm">
                                            <?php foreach ($durationLabels as $k => $label) { ?>
                                                <option value="<?= h((string) $k) ?>"><?= h($label) ?></option>
                                            <?php } ?>
                                        </select>
                                        <button type="submit" class="btn btn-sm btn-outline-danger"><?= h(t('Block')) ?></button>
                                    </form>
                                <?php } ?>
                            </td>
                        </tr>
                    <?php } ?>
                    </tbody>
                </table>
            </div>
        <?php } ?>
    </section>

    <div class="row g-3 sg-row">
        <div class="col-xl-7">
            <section class="sg-card h-100">
                <div class="sg-card-head">
                    <h3><?= h(t('Recent events')) ?></h3>
                    <a class="small d-print-none" href="<?= h((string) URL::to('/dashboard/security_guard/events')) ?>"><?= h(t('All events')) ?></a>
                </div>
                <?php if (!$recentEvents) { ?>
                    <p class="sg-muted mb-0"><?= h(t('No events yet.')) ?></p>
                <?php } else { ?>
                    <div class="table-responsive">
                        <table class="table table-sm align-middle sg-table">
                            <thead><tr>
                                <th><?= h(t('Time')) ?></th>
                                <th><?= h(t('IP address')) ?></th>
                                <th><?= h(t('Category')) ?></th>
                                <th><?= h(t('URL')) ?></th>
                            </tr></thead>
                            <tbody>
                            <?php foreach ($recentEvents as $e) { ?>
                                <tr>
                                    <td class="text-nowrap small"><?= h(Format::dateTime($e['createdAt'] ?? 0)) ?></td>
                                    <td class="text-nowrap"><?= h(trim(Format::flag($e['country'] ?? '') . ' ' . (string) ($e['ip'] ?? ''))) ?></td>
                                    <td><span class="badge <?= h(Format::actionBadge($e['action'] ?? '')) ?>" title="<?= h(Format::actionLabel($e['action'] ?? '')) ?>"><?= h(Format::categoryLabel($e['category'] ?? '')) ?></span></td>
                                    <td class="sg-url" title="<?= h(Format::truncate($e['url'] ?? '', 500)) ?>"><?= h(Format::truncate($e['url'] ?? '', 60)) ?></td>
                                </tr>
                            <?php } ?>
                            </tbody>
                        </table>
                    </div>
                <?php } ?>
            </section>
        </div>
        <div class="col-xl-5">
            <section class="sg-card h-100">
                <div class="sg-card-head">
                    <h3><?= h(t('Alerts')) ?></h3>
                    <?php if (!empty($alerts['rows'])) { ?>
                        <form method="post" action="<?= h((string) $view->action('mark_alerts_read')) ?>" class="d-print-none">
                            <?php $token->output('sg_alerts_read'); ?>
                            <button type="submit" class="btn btn-link btn-sm p-0"><?= h(t('Mark all as read')) ?></button>
                        </form>
                    <?php } ?>
                </div>
                <?php if (empty($alerts['rows'])) { ?>
                    <p class="sg-muted mb-0"><?= h(t('No alerts.')) ?></p>
                <?php } else { ?>
                    <ul class="sg-alerts">
                        <?php foreach ((array) $alerts['rows'] as $a) { ?>
                            <li class="<?= empty($a['isRead']) ? 'sg-unread' : '' ?>">
                                <span class="badge <?= h(Format::severityBadge($a['severity'] ?? '')) ?>"><?= h(Format::severityLabel($a['severity'] ?? '')) ?></span>
                                <span class="sg-alert-msg"><?= h(Format::truncate($a['message'] ?? '', 200)) ?></span>
                                <span class="sg-muted small d-block"><?= h(Format::dateTime($a['createdAt'] ?? 0)) ?><?= !empty($a['ip']) ? ' · ' . h((string) $a['ip']) : '' ?></span>
                            </li>
                        <?php } ?>
                    </ul>
                <?php } ?>
            </section>
        </div>
    </div>
</div>
