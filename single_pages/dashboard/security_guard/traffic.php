<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;

/**
 * @var Concrete\Core\Page\View\PageView $view
 * @var Concrete\Core\Validation\CSRF\Token $token
 * @var Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Period $period
 * @var bool $hasData
 * @var array $sum
 * @var array $series
 * @var array $hours
 * @var array $breakdown
 * @var int $lastIngestAt
 * @var array $sources
 * @var string $excludedIps
 * @var array|null $botRanges
 * @var bool $canUpdateRanges
 */
$pageUrl = (string) ($sgPageUrl ?? $view->action('view'));
$v = static function (string $k) use ($sum) {
    return (int) ($sum[$k] ?? 0);
};
$report = (array) (($sum['breakdown'] ?? [])['report'] ?? []);
$tiles = [
    [t('All requests'), Format::num($v('totalRequests')), t('unique IP addresses: %s', Format::num($v('uniqueIps'))), false],
    [t('Attacks'), Format::num($v('attackRequests')), t('from %s IP addresses', Format::num($v('attackIps'))), false],
    [t('Attacks (report method)'), Format::num($report['attackRequests'] ?? 0), t('from %s IP addresses; counted by URL pattern, as in the monthly report', Format::num($report['attackIps'] ?? 0)), false],
    [t('Refused by the server (403)'), Format::num($v('blocked403')), t('by .htaccess or the firewall'), false],
];
$hostWaf = (array) ($breakdown['hostWaf'] ?? []);
$hasHostWaf = $v('hostWafBlocked') > 0 || !empty($hostWaf['categories']);
if ($hasHostWaf) {
    $tiles[] = [t('Blocked by the server (before PHP)'), Format::num($v('hostWafBlocked')), t('from %s IP addresses; hosting firewall (ModSecurity/Imunify) and .htaccess rules', (!empty($sum['hostWafIpsApprox']) ? '≈' : '') . Format::num($v('hostWafIps'))), false];
}
$tiles = [...$tiles,
    [t('Failed logins'), Format::num($v('loginFailed')), t('to the admin login'), false],
    [t('Not found (404)'), Format::num($v('errors404')), t('server errors (5xx): %s', Format::num($v('errors5xx'))), false],
    [t('Overload (508)'), Format::num($v('overload508')), t('refused by the hosting'), $v('overload508') > 0],
    [t('Search and other bots'), Format::num($v('botRequests')), t('requests'), false],
    [t('Traffic'), Format::bytes($v('bytes')), t('sent to visitors'), false],
];
$table = static function (array $pairs, string $keyTitle, bool $isUrl) {
    if (!$pairs) {
        ?><p class="sg-muted mb-0"><?= h(t('No data for this period.')) ?></p><?php
        return;
    } ?>
    <div class="table-responsive">
        <table class="table table-sm align-middle sg-table mb-0">
            <thead><tr><th><?= h($keyTitle) ?></th><th class="text-end"><?= h(t('Requests')) ?></th></tr></thead>
            <tbody>
            <?php foreach ($pairs as [$key, $n, $raw]) { ?>
                <tr>
                    <td class="<?= $isUrl ? 'sg-url' : 'text-nowrap' ?>" title="<?= h(Format::truncate($key, 500)) ?>"><?= h(Format::truncate($key, $isUrl ? 80 : 45)) ?><?php if (!$isUrl && !empty($raw['bot']) && is_string($raw['bot'])) { ?> <span class="badge text-bg-secondary"><?= h(t('Bot: %s', Format::truncate($raw['bot'], 40))) ?></span><?php } ?></td>
                    <td class="text-end sg-num"><?= h(Format::num($n)) ?></td>
                </tr>
            <?php } ?>
            </tbody>
        </table>
    </div>
<?php };
?>
<div class="sg-page sg-traffic">
    <?php View::element('nav', ['current' => $sgPagePath ?? '', 'mode' => $sgMode ?? '', 'errors' => $sgServiceErrors ?? []], 'security_guard'); ?>

    <div class="sg-toolbar">
        <?php View::element('period_filter', ['period' => $period, 'baseUrl' => $pageUrl], 'security_guard'); ?>
        <div class="sg-toolbar-actions d-print-none">
            <form method="post" action="<?= h((string) $view->action('ingest')) ?>" class="d-inline" data-sg-busy="<?= h(t('Reading logs…')) ?>">
                <?php $token->output('sg_ingest'); ?>
                <?php foreach ($period->query() as $qk => $qv) { ?><input type="hidden" name="<?= h($qk) ?>" value="<?= h($qv) ?>"><?php } ?>
                <button type="submit" class="btn btn-outline-primary btn-sm"><?= h(t('Update from hosting logs')) ?></button>
            </form>
            <button type="button" class="btn btn-outline-secondary btn-sm" data-sg-print><?= h(t('Print')) ?></button>
        </div>
    </div>
    <p class="sg-muted small sg-period-caption">
        <?= h(t('Period: %s – %s', Format::day($period->fromDay), Format::day($period->toDay))) ?>
        · <?= h($lastIngestAt > 0 ? t('Hosting logs read: %s', Format::dateTime($lastIngestAt)) : t('Hosting logs have not been read yet')) ?>
        <?php if (trim($excludedIps) !== '') { ?>· <?= h(t('Excluded from statistics: %s', Format::truncate(preg_replace('/\s+/', ' ', $excludedIps), 120))) ?><?php } ?>
    </p>

    <?php if (!$hasData) { ?>
        <div class="alert alert-info"><?= h(t('There is no data from the hosting access logs for this period yet. Press "Update from hosting logs" or set up the cron command security-guard:ingest.')) ?></div>
    <?php } else { ?>
        <div class="sg-tiles sg-tiles-4">
            <?php foreach ($tiles as [$k, $val, $sub, $crit]) { ?>
                <div class="sg-tile<?= $crit ? ' sg-tile-critical' : '' ?>">
                    <div class="sg-tile-k"><?= h($k) ?></div>
                    <div class="sg-tile-v"><?= h($val) ?></div>
                    <div class="sg-tile-s"><?= h($sub) ?></div>
                </div>
            <?php } ?>
        </div>

        <section class="sg-card sg-avoid-break">
            <div class="sg-card-head"><h3><?= h(t('All requests by day')) ?></h3></div>
            <?php View::element('chart_bars', ['points' => $series['totalRequests'], 'unit' => t('requests'), 'aria' => t('All requests by day')], 'security_guard'); ?>
        </section>
        <section class="sg-card sg-avoid-break">
            <div class="sg-card-head"><h3><?= h(t('Attacks by day')) ?></h3></div>
            <?php View::element('chart_bars', ['points' => $series['attackRequests'], 'unit' => t('attacks'), 'aria' => t('Attacks by day')], 'security_guard'); ?>
        </section>
        <?php if ($hasHostWaf) { ?>
            <section class="sg-card sg-avoid-break">
                <div class="sg-card-head">
                    <h3><?= h(t('Blocked by the server (before PHP) by day')) ?></h3>
                    <span class="sg-muted small"><?= h(t('The hosting firewall (ModSecurity/Imunify) or .htaccess rules rejected these requests with 403 before PHP; Security Guard never saw them')) ?></span>
                </div>
                <?php View::element('chart_bars', ['points' => $series['hostWafBlocked'], 'unit' => t('requests'), 'height' => 190, 'labels' => 2, 'aria' => t('Blocked by the server (before PHP) by day')], 'security_guard'); ?>
                <div class="row g-3 mt-1">
                    <div class="col-lg-6">
                        <div class="sg-source-label"><?= h(t('Attack types')) ?></div>
                        <?php
                        $rows = [];
                        foreach (Format::pairs($hostWaf['categories'] ?? [], 12) as [$cat, $n]) {
                            $rows[] = ['label' => Format::categoryLabel($cat), 'value' => $n];
                        }
                        View::element('chart_hbars', ['rows' => $rows], 'security_guard');
                        ?>
                    </div>
                    <div class="col-lg-6">
                        <div class="sg-source-label"><?= h(t('Top rules')) ?></div>
                        <?php $table(Format::pairs($hostWaf['topRules'] ?? [], 10), t('Rule'), false); ?>
                    </div>
                    <div class="col-lg-6">
                        <div class="sg-source-label"><?= h(t('Top IP addresses')) ?></div>
                        <?php $table(Format::pairs($hostWaf['topIps'] ?? [], 10), t('IP address'), false); ?>
                    </div>
                </div>
            </section>
        <?php } ?>

        <div class="row g-3 sg-row">
            <div class="col-lg-6">
                <section class="sg-card h-100 sg-avoid-break">
                    <div class="sg-card-head"><h3><?= h(t('Requests by hour of day')) ?></h3></div>
                    <?php View::element('chart_bars', ['points' => $hours, 'unit' => t('requests'), 'height' => 200, 'width' => 520, 'labels' => 2, 'aria' => t('Requests by hour of day')], 'security_guard'); ?>
                </section>
            </div>
            <div class="col-lg-6">
                <section class="sg-card h-100 sg-avoid-break">
                    <div class="sg-card-head"><h3><?= h(t('Unique IP addresses by day')) ?></h3></div>
                    <?php View::element('chart_bars', ['points' => $series['uniqueIps'], 'unit' => t('IP addresses'), 'height' => 200, 'width' => 520, 'labels' => 2, 'aria' => t('Unique IP addresses by day')], 'security_guard'); ?>
                </section>
            </div>
            <div class="col-lg-6">
                <section class="sg-card h-100 sg-avoid-break">
                    <div class="sg-card-head"><h3><?= h(t('Not found (404) by day')) ?></h3></div>
                    <?php View::element('chart_bars', ['points' => $series['errors404'], 'unit' => t('responses'), 'height' => 180, 'width' => 520, 'labels' => 2, 'aria' => t('Not found (404) by day')], 'security_guard'); ?>
                </section>
            </div>
            <div class="col-lg-6">
                <section class="sg-card h-100 sg-avoid-break">
                    <div class="sg-card-head"><h3><?= h(t('Overload (508) by day')) ?></h3></div>
                    <?php View::element('chart_bars', ['points' => $series['overload508'], 'unit' => t('refusals (508)'), 'height' => 180, 'width' => 520, 'labels' => 4, 'critical' => true, 'aria' => t('Overload (508) by day'), 'empty' => t('No overloads in this period.')], 'security_guard'); ?>
                </section>
            </div>
            <div class="col-lg-6">
                <section class="sg-card h-100 sg-avoid-break">
                    <div class="sg-card-head"><h3><?= h(t('Server errors (5xx) by day')) ?></h3></div>
                    <?php View::element('chart_bars', ['points' => $series['errors5xx'], 'unit' => t('responses'), 'height' => 180, 'width' => 520, 'labels' => 3, 'critical' => true, 'aria' => t('Server errors (5xx) by day'), 'empty' => t('No server errors in this period.')], 'security_guard'); ?>
                </section>
            </div>
            <div class="col-lg-6">
                <section class="sg-card h-100 sg-avoid-break">
                    <div class="sg-card-head"><h3><?= h(t('Traffic by day')) ?></h3></div>
                    <?php View::element('chart_bars', ['points' => $series['bytes'], 'unit' => '', 'height' => 180, 'width' => 520, 'labels' => 2, 'formatter' => 'bytes', 'aria' => t('Traffic by day')], 'security_guard'); ?>
                </section>
            </div>
        </div>

        <div class="row g-3 sg-row">
            <div class="col-lg-6">
                <section class="sg-card h-100 sg-avoid-break">
                    <div class="sg-card-head"><h3><?= h(t('Response statuses')) ?></h3></div>
                    <?php
                    $rows = [];
                    foreach (Format::pairs($breakdown['statuses'] ?? [], 15) as [$code, $n]) {
                        $rows[] = ['label' => (string) $code, 'value' => $n, 'critical' => (int) $code === 508 || (int) $code >= 500];
                    }
                    View::element('chart_hbars', ['rows' => $rows], 'security_guard');
                    ?>
                </section>
            </div>
            <div class="col-lg-6">
                <section class="sg-card h-100 sg-avoid-break">
                    <div class="sg-card-head"><h3><?= h(t('Bots')) ?></h3></div>
                    <?php
                    $rows = [];
                    foreach (Format::pairs($breakdown['bots'] ?? [], 12) as [$bot, $n]) {
                        $rows[] = ['label' => $bot, 'value' => $n];
                    }
                    View::element('chart_hbars', ['rows' => $rows, 'empty' => t('No bot requests in this period.')], 'security_guard');
                    ?>
                </section>
            </div>
            <div class="col-lg-6">
                <section class="sg-card h-100 sg-avoid-break">
                    <div class="sg-card-head"><h3><?= h(t('Attack types')) ?></h3></div>
                    <?php
                    $rows = [];
                    foreach (Format::pairs($breakdown['categories'] ?? [], 15) as [$cat, $n]) {
                        $rows[] = ['label' => Format::categoryLabel($cat), 'value' => $n];
                    }
                    View::element('chart_hbars', ['rows' => $rows, 'empty' => t('No attacks in this period.')], 'security_guard');
                    ?>
                </section>
            </div>
        </div>

        <div class="row g-3 sg-row">
            <div class="col-xl-6">
                <section class="sg-card h-100">
                    <div class="sg-card-head"><h3><?= h(t('Top URLs')) ?></h3></div>
                    <?php $table(Format::pairs($breakdown['topUrls'] ?? [], 15), t('URL'), true); ?>
                </section>
            </div>
            <div class="col-xl-6">
                <section class="sg-card h-100">
                    <div class="sg-card-head"><h3><?= h(t('Top not found (404)')) ?></h3></div>
                    <?php $table(Format::pairs($breakdown['top404'] ?? [], 15), t('URL'), true); ?>
                </section>
            </div>
            <div class="col-xl-6">
                <section class="sg-card h-100">
                    <div class="sg-card-head"><h3><?= h(t('Top IP addresses')) ?></h3></div>
                    <?php $table(Format::pairs($breakdown['topIps'] ?? [], 15), t('IP address'), false); ?>
                </section>
            </div>
            <div class="col-xl-6">
                <section class="sg-card h-100">
                    <div class="sg-card-head">
                        <h3><?= h(t('Top countries')) ?></h3>
                        <?php if (!empty($countriesEstimated)) { ?><span class="small sg-muted"><?= h(t('estimated from the top IP addresses')) ?></span><?php } ?>
                    </div>
                    <?php
                    $rows = [];
                    foreach (Format::pairs($breakdown['countries'] ?? [], 10) as [$cc, $n]) {
                        $rows[] = ['label' => trim(Format::flag($cc) . ' ' . strtoupper($cc)), 'value' => $n];
                    }
                    View::element('chart_hbars', ['rows' => $rows, 'empty' => t('No country data.')], 'security_guard');
                    ?>
                </section>
            </div>
        </div>
    <?php } ?>

    <section class="sg-card">
        <div class="sg-card-head">
            <h3><?= h(t('Search bot IP ranges')) ?></h3>
            <?php if ($canUpdateRanges) { ?>
                <form method="post" action="<?= h((string) $view->action('update_ranges')) ?>" class="d-print-none" data-sg-busy="<?= h(t('Updating…')) ?>">
                    <?php $token->output('sg_update_ranges'); ?>
                    <?php foreach ($period->query() as $qk => $qv) { ?><input type="hidden" name="<?= h($qk) ?>" value="<?= h($qv) ?>"><?php } ?>
                    <button type="submit" class="btn btn-outline-primary btn-sm"><?= h(t('Update bot ranges now')) ?></button>
                </form>
            <?php } ?>
        </div>
        <?php if (!$botRanges) { ?>
            <p class="sg-muted mb-0"><?= h(t('Using the built-in ranges. They are updated with the package; automatic updates run through the cron command security-guard:update-ranges.')) ?></p>
        <?php } else { ?>
            <div class="table-responsive">
                <table class="table table-sm align-middle sg-table mb-0">
                    <thead><tr><th><?= h(t('Bot')) ?></th><th class="text-end"><?= h(t('Ranges')) ?></th><th><?= h(t('Updated')) ?></th><th><?= h(t('Source')) ?></th></tr></thead>
                    <tbody>
                    <?php foreach ($botRanges as $br) { ?>
                        <tr>
                            <td><?= h(Format::truncate($br['bot'], 40)) ?></td>
                            <td class="text-end sg-num"><?= h(Format::num($br['count'])) ?></td>
                            <td class="text-nowrap small"><?= h(Format::dateTime($br['fetchedAt'])) ?><?php if ($br['fetchedAt'] > 0) { ?><div class="sg-muted"><?= h(Format::relative($br['fetchedAt'])) ?></div><?php } ?></td>
                            <td class="sg-url small"><?= h(Format::truncate($br['source'], 120)) ?></td>
                        </tr>
                    <?php } ?>
                    </tbody>
                </table>
            </div>
        <?php } ?>
    </section>

    <section class="sg-card">
        <div class="sg-card-head">
            <h3><?= h(t('Log sources')) ?></h3>
            <a class="small d-print-none" href="<?= h((string) URL::to('/dashboard/security_guard/settings')) ?>#sg-group-hosting-logs"><?= h(t('Configure')) ?></a>
        </div>
        <?php if (!$sources) { ?>
            <p class="sg-muted mb-0"><?= h(t('No access log files were found. Specify the paths in the settings (for example ~/access-logs/example.com-ssl_log).')) ?></p>
        <?php } else { ?>
            <ul class="sg-sources">
                <?php foreach ($sources as $path => $size) { ?>
                    <li><code><?= h(Format::truncate(is_string($path) ? $path : (string) $size, 160)) ?></code><?php if (is_string($path) && is_numeric($size)) { ?> <span class="sg-muted small"><?= h(Format::bytes($size)) ?></span><?php } ?></li>
                <?php } ?>
            </ul>
        <?php } ?>
    </section>
</div>
