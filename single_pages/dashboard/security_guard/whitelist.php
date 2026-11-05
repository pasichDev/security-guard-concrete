<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;

/**
 * @var Concrete\Core\Page\View\PageView $view
 * @var Concrete\Core\Validation\CSRF\Token $token
 * @var array $manual
 * @var array $auto
 * @var string[] $fromSettings
 * @var array $clientIps
 * @var bool $trustAdmin
 * @var int $trustDays
 * @var array $expiries
 */
$now = time();
$renderRows = static function (array $rows, bool $isAuto) use ($view, $token, $now) {
    foreach ($rows as $e) {
        $exp = (int) ($e['expiresAt'] ?? 0);
        $expired = $exp > 0 && $exp <= $now; ?>
        <tr class="<?= $expired ? 'sg-expired' : '' ?>">
            <td class="text-nowrap"><code><?= h((string) ($e['ipRange'] ?? '')) ?></code></td>
            <td><?= h(Format::truncate($e['description'] ?? '', 120)) ?></td>
            <td class="text-nowrap small">
                <?php if ($exp === 0) { ?>
                    <?= h(t('Never')) ?>
                <?php } else { ?>
                    <?= h(Format::dateTime($exp)) ?>
                    <div class="sg-muted"><?= h($expired ? t('expired') : Format::relative($exp, $now)) ?></div>
                <?php } ?>
            </td>
            <td class="text-nowrap small sg-muted"><?= h(Format::dateTime($e['createdAt'] ?? 0)) ?></td>
            <td class="text-end d-print-none">
                <form method="post" action="<?= h((string) $view->action('remove')) ?>" class="d-inline" data-sg-confirm="<?= h(t('Remove %s from the whitelist?', (string) ($e['ipRange'] ?? ''))) ?>">
                    <?php $token->output('sg_whitelist_remove'); ?>
                    <input type="hidden" name="id" value="<?= (int) ($e['id'] ?? 0) ?>">
                    <button type="submit" class="btn btn-sm btn-outline-danger"><?= h(t('Remove')) ?></button>
                </form>
            </td>
        </tr>
    <?php }
};
$head = '<thead><tr><th>' . h(t('Address or range')) . '</th><th>' . h(t('Description')) . '</th><th>' . h(t('Expires')) . '</th><th>' . h(t('Added')) . '</th><th class="d-print-none"></th></tr></thead>';
?>
<div class="sg-page sg-whitelist">
    <?php View::element('nav', ['current' => $sgPagePath ?? '', 'mode' => $sgMode ?? '', 'errors' => $sgServiceErrors ?? []], 'security_guard'); ?>

    <p class="sg-lead"><?= h(t('Requests from these addresses skip all firewall checks. Add only addresses you control: your office, your home connection, monitoring services.')) ?></p>

    <section class="sg-card">
        <div class="sg-card-head"><h3><?= h(t('Add an address')) ?></h3></div>
        <form method="post" action="<?= h((string) $view->action('add')) ?>" class="row g-2 align-items-end">
            <?php $token->output('sg_whitelist_add'); ?>
            <div class="col-md-4">
                <label class="form-label" for="sg-w-range"><?= h(t('IP address, prefix or CIDR')) ?></label>
                <input class="form-control form-control-sm" id="sg-w-range" name="range" required maxlength="64" placeholder="203.0.113.0/24" autocomplete="off" spellcheck="false">
            </div>
            <div class="col-md-4">
                <label class="form-label" for="sg-w-desc"><?= h(t('Description')) ?></label>
                <input class="form-control form-control-sm" id="sg-w-desc" name="description" maxlength="255" placeholder="<?= h(t('e.g. office')) ?>">
            </div>
            <div class="col-md-2">
                <label class="form-label" for="sg-w-exp"><?= h(t('Expires')) ?></label>
                <select class="form-select form-select-sm" id="sg-w-exp" name="expires">
                    <?php foreach ($expiries as $k => $label) { ?><option value="<?= h((string) $k) ?>"><?= h($label) ?></option><?php } ?>
                </select>
            </div>
            <div class="col-md-2"><button type="submit" class="btn btn-primary btn-sm w-100"><?= h(t('Add')) ?></button></div>
        </form>
        <?php if ($clientIps['all']) { ?>
            <p class="small mt-2 mb-0">
                <?= h(t('Your IP address:')) ?>
                <?php foreach ($clientIps['all'] as $ip) { ?>
                    <button type="button" class="btn btn-link btn-sm p-0 align-baseline" data-sg-fill="#sg-w-range" data-sg-value="<?= h($ip) ?>"><code><?= h($ip) ?></code></button>
                <?php } ?>
            </p>
        <?php } ?>
    </section>

    <section class="sg-card sg-card-flush">
        <div class="sg-card-head px-3 pt-3"><h3><?= h(t('Whitelist')) ?></h3></div>
        <?php if (!$manual) { ?>
            <p class="sg-muted p-3 mb-0"><?= h(t('No entries yet.')) ?></p>
        <?php } else { ?>
            <div class="table-responsive"><table class="table table-sm align-middle sg-table mb-0"><?= $head ?><tbody><?php $renderRows($manual, false); ?></tbody></table></div>
        <?php } ?>
    </section>

    <section class="sg-card sg-card-flush">
        <div class="sg-card-head px-3 pt-3">
            <h3><?= h(t('Automatically trusted')) ?></h3>
            <span class="small sg-muted"><?= h($trustAdmin ? t('IP addresses of administrators are trusted for %s days after a successful login.', $trustDays) : t('Automatic trust after administrator login is disabled.')) ?></span>
        </div>
        <?php if (!$auto) { ?>
            <p class="sg-muted p-3 mb-0"><?= h(t('No entries yet.')) ?></p>
        <?php } else { ?>
            <div class="table-responsive"><table class="table table-sm align-middle sg-table mb-0"><?= $head ?><tbody><?php $renderRows($auto, true); ?></tbody></table></div>
        <?php } ?>
    </section>

    <?php if ($fromSettings) { ?>
        <section class="sg-card">
            <div class="sg-card-head">
                <h3><?= h(t('From the settings')) ?></h3>
                <a class="small" href="<?= h((string) URL::to('/dashboard/security_guard/settings')) ?>#sg-group-trust"><?= h(t('Edit')) ?></a>
            </div>
            <p class="mb-0"><?php foreach ($fromSettings as $r) { ?><code class="me-2"><?= h($r) ?></code><?php } ?></p>
        </section>
    <?php } ?>
</div>
