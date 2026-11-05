<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;

/**
 * @var Concrete\Core\Page\View\PageView $view
 * @var string[] $traps
 * @var string[] $customTraps
 * @var bool $enabled
 * @var array $rows
 * @var array $pagination
 */
$pageUrl = (string) ($sgPageUrl ?? $view->action('view'));
?>
<div class="sg-page sg-honeypot">
    <?php View::element('nav', ['current' => $sgPagePath ?? '', 'mode' => $sgMode ?? '', 'errors' => $sgServiceErrors ?? []], 'security_guard'); ?>

    <?php if (!$enabled) { ?>
        <div class="alert alert-warning"><?= h(t('Honeypot traps are disabled in the settings.')) ?></div>
    <?php } ?>
    <p class="sg-lead"><?= h(t('Trap URLs do not exist on the site and are never linked. Only scanners request them, so the IP is blocked immediately.')) ?></p>

    <div class="row g-3 sg-row">
        <div class="col-lg-4">
            <section class="sg-card h-100">
                <div class="sg-card-head">
                    <h3><?= h(t('Trap URLs')) ?></h3>
                    <a class="small d-print-none" href="<?= h((string) URL::to('/dashboard/security_guard/settings')) ?>#sg-group-honeypot"><?= h(t('Add your own')) ?></a>
                </div>
                <?php if (!$traps) { ?>
                    <p class="sg-muted mb-0"><?= h(t('No traps are active.')) ?></p>
                <?php } else { ?>
                    <ul class="sg-trap-list">
                        <?php foreach ($traps as $t) { ?>
                            <li><code><?= h(Format::truncate($t, 120)) ?></code><?php if (in_array($t, $customTraps, true)) { ?> <span class="badge text-bg-info"><?= h(t('custom')) ?></span><?php } ?></li>
                        <?php } ?>
                    </ul>
                <?php } ?>
            </section>
        </div>
        <div class="col-lg-8">
            <section class="sg-card h-100 sg-card-flush">
                <div class="sg-card-head px-3 pt-3"><h3><?= h(t('Hits')) ?></h3></div>
                <?php if (!$rows) { ?>
                    <p class="sg-muted p-3 mb-0"><?= h(t('No hits yet.')) ?></p>
                <?php } else { ?>
                    <div class="table-responsive">
                        <table class="table table-sm align-middle sg-table mb-0">
                            <thead><tr><th><?= h(t('Time')) ?></th><th><?= h(t('IP address')) ?></th><th><?= h(t('Request')) ?></th></tr></thead>
                            <tbody>
                            <?php foreach ($rows as $r) {
                                $ip = (string) ($r['ip'] ?? ''); ?>
                                <tr>
                                    <td class="text-nowrap small"><?= h(Format::dateTime($r['createdAt'] ?? 0)) ?></td>
                                    <td class="text-nowrap"><a class="sg-ip" href="<?= h((string) URL::to('/dashboard/security_guard/events') . '?ip=' . rawurlencode($ip)) ?>"><?= h($ip) ?></a></td>
                                    <td class="sg-request">
                                        <div class="sg-url" title="<?= h(Format::truncate($r['url'] ?? '', 500)) ?>"><?= h(Format::truncate($r['url'] ?? '', 80)) ?></div>
                                        <?php if (!empty($r['userAgent'])) { ?><div class="small sg-muted sg-ua" title="<?= h(Format::truncate($r['userAgent'], 255)) ?>"><?= h(Format::truncate($r['userAgent'], 80)) ?></div><?php } ?>
                                    </td>
                                </tr>
                            <?php } ?>
                            </tbody>
                        </table>
                    </div>
                <?php } ?>
            </section>
        </div>
    </div>
    <?php View::element('pagination', ['pagination' => $pagination, 'baseUrl' => $pageUrl], 'security_guard'); ?>
</div>
