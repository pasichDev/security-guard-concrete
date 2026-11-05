<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;

/**
 * @var Concrete\Core\Page\View\PageView $view
 * @var array $rows
 * @var int $total
 * @var array $filters
 * @var array $categories
 * @var array $actions
 * @var array $pagination
 * @var string $exportUrl
 */
$pageUrl = (string) ($sgPageUrl ?? $view->action('view'));
?>
<div class="sg-page sg-events">
    <?php View::element('nav', ['current' => $sgPagePath ?? '', 'mode' => $sgMode ?? '', 'errors' => $sgServiceErrors ?? []], 'security_guard'); ?>

    <form method="get" action="<?= h($pageUrl) ?>" class="sg-filters d-print-none">
        <div class="row g-2 align-items-end">
            <div class="col-sm-6 col-lg-2">
                <label class="form-label" for="sg-f-category"><?= h(t('Category')) ?></label>
                <select class="form-select form-select-sm" id="sg-f-category" name="category">
                    <option value=""><?= h(t('All')) ?></option>
                    <?php foreach ($categories as $k => $label) { ?>
                        <option value="<?= h($k) ?>"<?= $filters['category'] === $k ? ' selected' : '' ?>><?= h($label) ?></option>
                    <?php } ?>
                </select>
            </div>
            <div class="col-sm-6 col-lg-2">
                <label class="form-label" for="sg-f-action"><?= h(t('Action')) ?></label>
                <select class="form-select form-select-sm" id="sg-f-action" name="outcome">
                    <option value=""><?= h(t('All')) ?></option>
                    <?php foreach ($actions as $k => $label) { ?>
                        <option value="<?= h($k) ?>"<?= $filters['outcome'] === $k ? ' selected' : '' ?>><?= h($label) ?></option>
                    <?php } ?>
                </select>
            </div>
            <div class="col-sm-6 col-lg-2">
                <label class="form-label" for="sg-f-ip"><?= h(t('IP address')) ?></label>
                <input class="form-control form-control-sm" id="sg-f-ip" name="ip" value="<?= h($filters['ip']) ?>" maxlength="45" inputmode="text" autocomplete="off">
            </div>
            <div class="col-sm-6 col-lg-2">
                <label class="form-label" for="sg-f-from"><?= h(t('From')) ?></label>
                <input type="date" class="form-control form-control-sm" id="sg-f-from" name="from" value="<?= h($filters['from']) ?>">
            </div>
            <div class="col-sm-6 col-lg-2">
                <label class="form-label" for="sg-f-to"><?= h(t('To')) ?></label>
                <input type="date" class="form-control form-control-sm" id="sg-f-to" name="to" value="<?= h($filters['to']) ?>">
            </div>
            <div class="col-sm-6 col-lg-2">
                <label class="form-label" for="sg-f-search"><?= h(t('URL or user agent')) ?></label>
                <input class="form-control form-control-sm" id="sg-f-search" name="search" value="<?= h($filters['search']) ?>" maxlength="200">
            </div>
        </div>
        <div class="d-flex flex-wrap gap-2 mt-2">
            <button type="submit" class="btn btn-primary btn-sm"><?= h(t('Filter')) ?></button>
            <a class="btn btn-outline-secondary btn-sm" href="<?= h($pageUrl) ?>"><?= h(t('Reset')) ?></a>
            <a class="btn btn-outline-secondary btn-sm ms-auto" href="<?= h($exportUrl) ?>"><?= h(t('Export CSV')) ?></a>
        </div>
    </form>

    <section class="sg-card">
        <?php if (!$rows) { ?>
            <p class="sg-muted mb-0"><?= h(t('No events match the filter.')) ?></p>
        <?php } else { ?>
            <div class="table-responsive">
                <table class="table table-sm align-middle sg-table">
                    <thead><tr>
                        <th><?= h(t('Time')) ?></th>
                        <th><?= h(t('IP address')) ?></th>
                        <th><?= h(t('Category')) ?></th>
                        <th><?= h(t('Rule')) ?></th>
                        <th><?= h(t('Action')) ?></th>
                        <th><?= h(t('Request')) ?></th>
                    </tr></thead>
                    <tbody>
                    <?php foreach ($rows as $e) {
                        $ip = (string) ($e['ip'] ?? '');
                        $ua = (string) ($e['userAgent'] ?? ''); ?>
                        <tr>
                            <td class="text-nowrap small"><?= h(Format::dateTime($e['createdAt'] ?? 0)) ?></td>
                            <td class="text-nowrap">
                                <a class="sg-ip" href="<?= h($pageUrl . '?ip=' . rawurlencode($ip)) ?>"><?= h($ip) ?></a>
                                <?php if (!empty($e['country'])) { ?><span class="sg-muted small" title="<?= h((string) $e['country']) ?>"> <?= h(Format::flag($e['country']) ?: (string) $e['country']) ?></span><?php } ?>
                            </td>
                            <td><?= h(Format::categoryLabel($e['category'] ?? '')) ?></td>
                            <td><code class="small"><?= h(Format::truncate($e['rule'] ?? '', 40)) ?></code></td>
                            <td><span class="badge <?= h(Format::actionBadge($e['action'] ?? '')) ?>"><?= h(Format::actionLabel($e['action'] ?? '')) ?></span></td>
                            <td class="sg-request">
                                <div class="sg-url" title="<?= h(Format::truncate($e['url'] ?? '', 500)) ?>"><span class="sg-method"><?= h(Format::truncate($e['method'] ?? '', 10)) ?></span> <?= h(Format::truncate($e['url'] ?? '', 90)) ?></div>
                                <?php if ($ua !== '') { ?><div class="sg-ua small sg-muted" title="<?= h(Format::truncate($ua, 255)) ?>"><?= h(Format::truncate($ua, 90)) ?></div><?php } ?>
                            </td>
                        </tr>
                    <?php } ?>
                    </tbody>
                </table>
            </div>
        <?php } ?>
        <?php View::element('pagination', ['pagination' => $pagination, 'baseUrl' => $pageUrl], 'security_guard'); ?>
    </section>
</div>
