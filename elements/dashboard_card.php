<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

/*
 * Компактна картка для стартової сторінки дашборду:
 *   View::element('dashboard_card', [], 'security_guard');
 * Показується лише тим, хто може відкрити панель пакета. Будь-яка помилка —
 * картка просто не виводиться (стартова сторінка дашборду не має ламатися).
 */

use Concrete\Core\Page\Page;
use Concrete\Core\Permission\Checker;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Period;
use PasichDev\SecurityGuard\Config\Settings;
use PasichDev\SecurityGuard\Contract\BlockServiceInterface;
use PasichDev\SecurityGuard\Contract\EventLogInterface;

try {
    $sgPage = Page::getByPath('/dashboard/security_guard/overview');
    if (!is_object($sgPage) || $sgPage->isError() || !(new Checker($sgPage))->canViewPage()) {
        return;
    }
    $sgApp = app();
    $sgSettings = $sgApp->make(Settings::class);
    $sgMode = $sgSettings->get('enabled') ? (string) $sgSettings->get('mode') : 'disabled';
    $sgToday = Period::lastDays(1);
    $sgAttacks = null;
    $sgBans = null;
    try {
        $sgSum = $sgApp->make(EventLogInterface::class)->summary($sgToday->fromTs, $sgToday->toTs);
        $sgAttacks = (int) ($sgSum['total'] ?? 0);
    } catch (Throwable $e) {
    }
    try {
        $sgBans = (int) $sgApp->make(BlockServiceInterface::class)->countActive();
    } catch (Throwable $e) {
    }
} catch (Throwable $e) {
    return;
}
$sgModeMeta = [
    'enforce' => [t('Enforce mode'), 'text-bg-success'],
    'monitor' => [t('Monitor mode'), 'text-bg-warning'],
    'disabled' => [t('Disabled'), 'text-bg-danger'],
];
$sgMeta = $sgModeMeta[$sgMode] ?? $sgModeMeta['monitor'];
$sgCss = \Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\BaseController::assetUrl('css/security-guard.css');
?>
<link rel="stylesheet" href="<?= h($sgCss) ?>">
<div class="card sg-dashboard-card">
    <div class="card-body">
        <div class="d-flex justify-content-between align-items-start gap-2 mb-2">
            <h5 class="card-title mb-0"><?= h(t('Security Guard')) ?></h5>
            <span class="badge <?= $sgMeta[1] ?>"><?= h($sgMeta[0]) ?></span>
        </div>
        <div class="sg-card-stats">
            <div><span class="sg-card-num"><?= $sgAttacks === null ? '—' : h(Format::num($sgAttacks)) ?></span><span class="sg-card-lbl"><?= h(t('attacks today')) ?></span></div>
            <div><span class="sg-card-num"><?= $sgBans === null ? '—' : h(Format::num($sgBans)) ?></span><span class="sg-card-lbl"><?= h(t('active bans')) ?></span></div>
        </div>
        <?php if ($sgMode === 'monitor') { ?>
            <p class="small text-body-secondary mb-2"><?= h(t('Attacks are only logged. Switch to enforce mode after checking the log.')) ?></p>
        <?php } ?>
        <a class="btn btn-sm btn-outline-primary" href="<?= h((string) URL::to($sgPage)) ?>"><?= h(t('Open Security Guard')) ?></a>
    </div>
</div>
