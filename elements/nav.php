<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

/*
 * Верхня навігація між сторінками пакета + стан режиму + помилки сервісів.
 * Параметри: $current — шлях поточної сторінки, $mode, $errors.
 */

$current = isset($current) ? (string) $current : '';
$mode = isset($mode) ? (string) $mode : '';
$errors = isset($errors) && is_array($errors) ? $errors : [];
$items = [
    'overview' => t('Overview'),
    'events' => t('Event Log'),
    'blocks' => t('Blocked IPs'),
    'whitelist' => t('Whitelist'),
    'honeypot' => t('Honeypot'),
    'scores' => t('Behaviour Scores'),
    'traffic' => t('Traffic'),
    'checklist' => t('Security Check'),
    'settings' => t('Settings'),
];
$modeLabel = [
    'enforce' => [t('Enforce mode'), 'text-bg-success'],
    'monitor' => [t('Monitor mode'), 'text-bg-warning'],
    'disabled' => [t('Disabled'), 'text-bg-danger'],
];
?>
<div class="sg-nav d-print-none">
    <ul class="nav nav-pills flex-wrap">
        <?php foreach ($items as $handle => $label) {
            $path = '/dashboard/security_guard/' . $handle;
            $active = $current === $path; ?>
            <li class="nav-item"><a class="nav-link<?= $active ? ' active' : '' ?>"<?= $active ? ' aria-current="page"' : '' ?> href="<?= h((string) \URL::to($path)) ?>"><?= h($label) ?></a></li>
        <?php } ?>
    </ul>
    <?php if (isset($modeLabel[$mode])) { ?>
        <a class="badge rounded-pill <?= $modeLabel[$mode][1] ?> sg-mode-pill" href="<?= h((string) \URL::to('/dashboard/security_guard/settings')) ?>"><?= h($modeLabel[$mode][0]) ?></a>
    <?php } ?>
</div>
<?php foreach ($errors as $err) { ?>
    <div class="alert alert-warning sg-service-error"><?= h((string) $err) ?></div>
<?php } ?>
