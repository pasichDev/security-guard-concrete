<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;

/**
 * @var Concrete\Core\Page\View\PageView $view
 * @var Concrete\Core\Validation\CSRF\Token $token
 * @var string $tab
 * @var string $search
 * @var array $rows
 * @var int $activeCount
 * @var array $clientIps
 * @var array $myBans
 * @var array $durations
 * @var string $prefillIp
 * @var string $prefillBot
 * @var array $pagination
 */
$pageUrl = (string) ($sgPageUrl ?? $view->action('view'));
$now = time();
?>
<div class="sg-page sg-blocks">
    <?php View::element('nav', ['current' => $sgPagePath ?? '', 'mode' => $sgMode ?? '', 'errors' => $sgServiceErrors ?? []], 'security_guard'); ?>

    <div class="row g-3 sg-row">
        <div class="col-lg-5">
            <section class="sg-card h-100 <?= $myBans ? 'sg-card-alert' : '' ?>">
                <div class="sg-card-head"><h3><?= h(t('Your IP address')) ?></h3></div>
                <p class="sg-myip">
                    <?php foreach ($clientIps['all'] as $ip) { ?><code><?= h($ip) ?></code> <?php } ?>
                    <?php if (!$clientIps['all']) { ?><span class="sg-muted"><?= h(t('unknown')) ?></span><?php } ?>
                </p>
                <?php if (count($clientIps['all']) > 1) { ?>
                    <p class="small sg-muted"><?= h(t('The address seen through the proxy (%s) differs from the direct connection address (%s). Both are shown and both will be unblocked.', $clientIps['resolved'], $clientIps['remote'])) ?></p>
                <?php } ?>
                <?php if ($myBans) { ?>
                    <p class="text-danger"><strong><?= h(t('Your IP address is blocked!')) ?></strong></p>
                <?php } else { ?>
                    <p class="small sg-muted"><?= h(t('Your address is not blocked. Logged-in administrators are never blocked by the firewall heuristics.')) ?></p>
                <?php } ?>
                <form method="post" action="<?= h((string) $view->action('unblock_me')) ?>">
                    <?php $token->output('sg_unblock_me'); ?>
                    <button type="submit" class="btn btn-sm <?= $myBans ? 'btn-danger' : 'btn-outline-secondary' ?>"><?= h(t('Unblock my IP')) ?></button>
                </form>
            </section>
        </div>
        <div class="col-lg-7">
            <section class="sg-card h-100">
                <div class="sg-card-head"><h3><?= h(t('Block an IP address')) ?></h3></div>
                <form method="post" action="<?= h((string) $view->action('block')) ?>" class="row g-2 align-items-end">
                    <?php $token->output('sg_block'); ?>
                    <div class="col-sm-6">
                        <label class="form-label" for="sg-b-ip"><?= h(t('IP address')) ?></label>
                        <input class="form-control form-control-sm" id="sg-b-ip" name="ip" required maxlength="45" placeholder="203.0.113.7" autocomplete="off" spellcheck="false" value="<?= h($prefillIp ?? '') ?>">
                    </div>
                    <div class="col-sm-6">
                        <label class="form-label" for="sg-b-duration"><?= h(t('Duration')) ?></label>
                        <select class="form-select form-select-sm" id="sg-b-duration" name="duration">
                            <?php foreach ($durations as $k => $label) { ?>
                                <option value="<?= h((string) $k) ?>"<?= (string) $k === (string) ($prefillDuration ?? '86400') ? ' selected' : '' ?>><?= h($label) ?></option>
                            <?php } ?>
                        </select>
                    </div>
                    <div class="col-sm-8">
                        <label class="form-label" for="sg-b-reason"><?= h(t('Reason (optional, Latin letters)')) ?></label>
                        <input class="form-control form-control-sm" id="sg-b-reason" name="reason" maxlength="40" placeholder="SPAM" pattern="[A-Za-z0-9_ ]*" value="<?= h($prefillReason ?? '') ?>">
                    </div>
                    <div class="col-sm-4">
                        <button type="submit" class="btn btn-danger btn-sm w-100"><?= h(t('Block')) ?></button>
                    </div>
                    <?php if (!empty($prefillBot)) { ?>
                        <div class="col-12">
                            <div class="alert alert-warning mb-0 py-2">
                                <div class="form-check mb-0">
                                    <input class="form-check-input" type="checkbox" name="confirm_bot" value="1" id="sg-b-confirm-bot" required>
                                    <label class="form-check-label" for="sg-b-confirm-bot"><?= h(t('This is a verified search engine crawler (%s) — banning it removes the site from search results', $prefillBot)) ?></label>
                                </div>
                            </div>
                        </div>
                    <?php } ?>
                    <p class="small sg-muted mb-0"><?= h(t('Only single addresses can be blocked. To block a whole network, use the geo block or the hosting firewall.')) ?></p>
                </form>
            </section>
        </div>
    </div>

    <div class="sg-toolbar">
        <ul class="nav nav-tabs">
            <li class="nav-item"><a class="nav-link<?= $tab === 'active' ? ' active' : '' ?>" href="<?= h($pageUrl . '?tab=active') ?>"><?= h(t('Active')) ?> <span class="badge text-bg-secondary"><?= h(Format::num($activeCount)) ?></span></a></li>
            <li class="nav-item"><a class="nav-link<?= $tab === 'history' ? ' active' : '' ?>" href="<?= h($pageUrl . '?tab=history') ?>"><?= h(t('History')) ?></a></li>
        </ul>
        <form method="get" action="<?= h($pageUrl) ?>" class="sg-search d-print-none">
            <input type="hidden" name="tab" value="<?= h($tab) ?>">
            <label class="visually-hidden" for="sg-b-q"><?= h(t('Search')) ?></label>
            <input class="form-control form-control-sm" id="sg-b-q" type="search" name="q" value="<?= h($search) ?>" placeholder="<?= h(t('IP or reason')) ?>" maxlength="64">
            <button class="btn btn-sm btn-outline-secondary" type="submit"><?= h(t('Search')) ?></button>
        </form>
    </div>

    <section class="sg-card sg-card-flush">
        <?php if (!$rows) { ?>
            <p class="sg-muted mb-0 p-3"><?= h($tab === 'active' ? t('No active bans.') : t('No past bans.')) ?></p>
        <?php } else { ?>
            <div class="table-responsive">
                <table class="table table-sm align-middle sg-table mb-0">
                    <thead><tr>
                        <th><?= h(t('IP address')) ?></th>
                        <th><?= h(t('Reason')) ?></th>
                        <th><?= h(t('Until')) ?></th>
                        <th class="text-end"><?= h(t('Attempts')) ?></th>
                        <th><?= h(t('Last request')) ?></th>
                        <th class="d-print-none"></th>
                    </tr></thead>
                    <tbody>
                    <?php foreach ($rows as $b) {
                        $ip = (string) ($b['ip'] ?? '');
                        $permanent = !empty($b['permanent']);
                        $until = (int) ($b['blockedUntil'] ?? 0);
                        $active = $permanent || $until > $now; ?>
                        <tr>
                            <td class="text-nowrap">
                                <a class="sg-ip" href="<?= h((string) URL::to('/dashboard/security_guard/events') . '?ip=' . rawurlencode($ip)) ?>"><?= h($ip) ?></a>
                                <?php if (!empty($b['country'])) { ?><span class="small"> <?= h(Format::flag($b['country']) ?: (string) $b['country']) ?></span><?php } ?>
                            </td>
                            <td>
                                <code class="small"><?= h(Format::truncate($b['reason'] ?? '', 40)) ?></code>
                                <div class="small sg-muted"><?= h(Format::categoryLabel($b['category'] ?? '')) ?><?= !empty($b['manual']) && ($b['category'] ?? '') !== 'manual' ? ' · ' . h(t('manual')) : '' ?><?= (int) ($b['escalationLevel'] ?? 0) > 0 ? ' · ' . h(t('level %s', (int) $b['escalationLevel'] + 1)) : '' ?></div>
                            </td>
                            <td class="text-nowrap small">
                                <?php if ($permanent) { ?>
                                    <span class="badge text-bg-danger"><?= h(t('Permanent')) ?></span>
                                <?php } else { ?>
                                    <?= h(Format::dateTime($until)) ?>
                                    <div class="sg-muted"><?= h(Format::relative($until, $now)) ?></div>
                                <?php } ?>
                            </td>
                            <td class="text-end sg-num"><?= h(Format::num($b['attempts'] ?? 0)) ?></td>
                            <td class="sg-request">
                                <div class="sg-url" title="<?= h(Format::truncate($b['lastUrl'] ?? '', 500)) ?>"><?= h(Format::truncate($b['lastUrl'] ?? '', 70)) ?></div>
                                <?php if (!empty($b['lastUserAgent'])) { ?><div class="small sg-muted sg-ua" title="<?= h(Format::truncate($b['lastUserAgent'], 255)) ?>"><?= h(Format::truncate($b['lastUserAgent'], 70)) ?></div><?php } ?>
                            </td>
                            <td class="d-print-none text-end">
                                <?php if ($active) { ?>
                                    <form method="post" action="<?= h((string) $view->action('unblock')) ?>" class="d-inline">
                                        <?php $token->output('sg_unblock'); ?>
                                        <input type="hidden" name="ip" value="<?= h($ip) ?>">
                                        <input type="hidden" name="tab" value="<?= h($tab) ?>">
                                        <button type="submit" class="btn btn-sm btn-outline-secondary"><?= h(t('Unblock')) ?></button>
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
    <?php View::element('pagination', ['pagination' => $pagination, 'baseUrl' => $pageUrl], 'security_guard'); ?>
</div>
