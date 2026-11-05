<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;

/**
 * @var Concrete\Core\Page\View\PageView $view
 * @var Concrete\Core\Validation\CSRF\Token $token
 * @var array|null $audit
 * @var bool $enforcing
 * @var string $baseUrl
 */
$statusMeta = [
    'fail' => [t('Problem'), 'text-bg-danger', '✕'],
    'warn' => [t('Warning'), 'text-bg-warning', '!'],
    'ok' => [t('OK'), 'text-bg-success', '✓'],
    'unknown' => [t('Not checked'), 'text-bg-secondary', '?'],
];
$order = ['fail' => 0, 'warn' => 1, 'unknown' => 2, 'ok' => 3];
$items = $audit ? (array) ($audit['items'] ?? []) : [];
usort($items, static function ($a, $b) use ($order) {
    return ($order[$a['status'] ?? 'unknown'] ?? 9) <=> ($order[$b['status'] ?? 'unknown'] ?? 9);
});
?>
<div class="sg-page sg-checklist">
    <?php View::element('nav', ['current' => $sgPagePath ?? '', 'mode' => $sgMode ?? '', 'errors' => $sgServiceErrors ?? []], 'security_guard'); ?>

    <section class="sg-card">
        <div class="sg-card-head">
            <h3><?= h(t('Environment and configuration audit')) ?></h3>
            <?php if ($audit) { ?><span class="small sg-muted"><?= h(t('Last run: %s (%s s)', Format::dateTime($audit['ranAt'] ?? 0), (string) ($audit['duration'] ?? '?'))) ?></span><?php } ?>
        </div>
        <p><?= h(t('Checks file permissions, PHP files among uploads, publicly reachable sensitive files, security headers, versions and Concrete settings. File scans and HTTP requests to %s take up to a minute, so the check runs only on request.', $baseUrl)) ?></p>
        <?php if ($enforcing) { ?>
            <p class="small sg-muted"><?= h(t('The check requests /.env and similar URLs from the server itself. In enforce mode the firewall may log these requests from the server IP.')) ?></p>
        <?php } ?>
        <form method="post" action="<?= h((string) $view->action('run')) ?>" class="d-print-none" data-sg-busy="<?= h(t('Checking…')) ?>">
            <?php $token->output('sg_audit_run'); ?>
            <button type="submit" class="btn btn-primary btn-sm"><?= h($audit ? t('Run the check again') : t('Run the check')) ?></button>
            <button type="button" class="btn btn-outline-secondary btn-sm" data-sg-print><?= h(t('Print')) ?></button>
        </form>
    </section>

    <?php if ($items) { ?>
        <div class="sg-audit">
            <?php foreach ($items as $it) {
                $st = (string) ($it['status'] ?? 'unknown');
                $meta = $statusMeta[$st] ?? $statusMeta['unknown']; ?>
                <article class="sg-audit-item sg-audit-<?= h($st) ?>">
                    <div class="sg-audit-mark" aria-hidden="true"><?= $meta[2] ?></div>
                    <div class="sg-audit-body">
                        <h4><?= h((string) ($it['title'] ?? '')) ?> <span class="badge <?= $meta[1] ?>"><?= h($meta[0]) ?></span></h4>
                        <p class="mb-1"><?= h((string) ($it['finding'] ?? '')) ?></p>
                        <?php if (!empty($it['advice'])) { ?><p class="sg-advice mb-1"><strong><?= h(t('What to do:')) ?></strong> <?= h((string) $it['advice']) ?></p><?php } ?>
                        <?php if (!empty($it['details'])) { ?>
                            <details>
                                <summary class="small"><?= h(t('Details (%s)', count((array) $it['details']))) ?></summary>
                                <ul class="small sg-details"><?php foreach ((array) $it['details'] as $d) { ?><li><code><?= h(Format::truncate($d, 200)) ?></code></li><?php } ?></ul>
                            </details>
                        <?php } ?>
                    </div>
                </article>
            <?php } ?>
        </div>
    <?php } ?>
</div>
