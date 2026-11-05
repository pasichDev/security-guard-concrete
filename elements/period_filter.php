<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

/* Фільтр періоду 7/30/90/довільний (GET). Параметри: $period (Support\Period), $baseUrl. */

if (!isset($period) || !is_object($period)) {
    return;
}
$baseUrl = isset($baseUrl) ? (string) $baseUrl : '';
$presets = ['7' => t('7 days'), '30' => t('30 days'), '90' => t('90 days')];
?>
<form class="sg-period d-print-none" method="get" action="<?= h($baseUrl) ?>" data-sg-period>
    <div class="btn-group btn-group-sm" role="group" aria-label="<?= h(t('Period')) ?>">
        <?php foreach ($presets as $k => $label) { ?>
            <a class="btn <?= $period->key === (string) $k ? 'btn-primary' : 'btn-outline-secondary' ?>" href="<?= h($baseUrl . (strpos($baseUrl, '?') === false ? '?' : '&') . 'period=' . $k) ?>"><?= h($label) ?></a>
        <?php } ?>
    </div>
    <input type="hidden" name="period" value="custom">
    <label class="sg-period-custom">
        <span class="visually-hidden"><?= h(t('From')) ?></span>
        <input type="date" class="form-control form-control-sm" name="from" value="<?= h($period->fromDay) ?>" max="<?= h($period->toDay) ?>">
    </label>
    <span class="sg-muted">—</span>
    <label class="sg-period-custom">
        <span class="visually-hidden"><?= h(t('To')) ?></span>
        <input type="date" class="form-control form-control-sm" name="to" value="<?= h($period->toDay) ?>">
    </label>
    <button type="submit" class="btn btn-sm <?= $period->key === 'custom' ? 'btn-primary' : 'btn-outline-secondary' ?>"><?= h(t('Show')) ?></button>
</form>
<?php if ((string) ($period->notice ?? '') !== '') { ?>
    <div class="alert alert-info py-2 mt-2 mb-0 sg-period-notice"><?= h((string) $period->notice) ?></div>
<?php } ?>
