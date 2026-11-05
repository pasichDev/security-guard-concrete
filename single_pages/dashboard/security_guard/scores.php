<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;

/**
 * @var Concrete\Core\Page\View\PageView $view
 * @var Concrete\Core\Validation\CSRF\Token $token
 * @var array $rows
 * @var int $threshold
 * @var int $ttl
 * @var bool $scoringOn
 * @var array $clientIps
 * @var array $pagination
 */
$pageUrl = (string) ($sgPageUrl ?? $view->action('view'));
$now = time();
$curPage = (int) ($pagination['page'] ?? 1);
?>
<div class="sg-page sg-scores">
    <?php View::element('nav', ['current' => $sgPagePath ?? '', 'mode' => $sgMode ?? '', 'errors' => $sgServiceErrors ?? []], 'security_guard'); ?>

    <?php if (!$scoringOn) { ?>
        <div class="alert alert-warning"><?= h(t('Behaviour scoring is disabled in the settings.')) ?></div>
    <?php } ?>
    <p class="sg-lead"><?= h(t('Each suspicious sign (empty user agent, no Accept-Language, POST without Referer, probing paths…) adds points. At %s points the IP is blocked. Points expire after %s.', $threshold, Format::duration($ttl))) ?></p>

    <section class="sg-card sg-card-flush">
        <?php if (!$rows) { ?>
            <p class="sg-muted p-3 mb-0"><?= h(t('No visitors with a behaviour score.')) ?></p>
        <?php } else { ?>
            <div class="table-responsive">
                <table class="table table-sm align-middle sg-table mb-0">
                    <thead><tr>
                        <th><?= h(t('IP address')) ?></th>
                        <th style="min-width: 10rem"><?= h(t('Score')) ?></th>
                        <th><?= h(t('Signs')) ?></th>
                        <th><?= h(t('Last activity')) ?></th>
                        <th class="d-print-none"></th>
                    </tr></thead>
                    <tbody>
                    <?php foreach ($rows as $r) {
                        $ip = (string) ($r['ip'] ?? '');
                        $score = (int) ($r['score'] ?? 0);
                        $pct = min(100, (int) round($score / $threshold * 100));
                        $signs = [];
                        foreach ((array) $r['events'] as $k => $v) {
                            if (is_array($v)) {
                                $signs[] = (string) ($v['type'] ?? $v['rule'] ?? $v['name'] ?? json_encode($v));
                            } elseif (is_string($k)) {
                                $signs[] = $k . (is_scalar($v) ? ' ×' . $v : '');
                            } else {
                                $signs[] = (string) $v;
                            }
                        }
                        $signs = array_slice(array_unique($signs), 0, 8); ?>
                        <tr>
                            <td class="text-nowrap"><a class="sg-ip" href="<?= h((string) URL::to('/dashboard/security_guard/events') . '?ip=' . rawurlencode($ip)) ?>"><?= h($ip) ?></a></td>
                            <td>
                                <div class="sg-meter" role="meter" aria-valuemin="0" aria-valuemax="<?= (int) $threshold ?>" aria-valuenow="<?= $score ?>" aria-label="<?= h(t('Score')) ?>">
                                    <div class="sg-meter-fill<?= $score >= $threshold ? ' sg-meter-critical' : '' ?>" style="width: <?= $pct ?>%"></div>
                                </div>
                                <span class="small sg-num"><?= h(Format::num($score)) ?> / <?= h(Format::num($threshold)) ?></span>
                            </td>
                            <td class="small"><?php foreach ($signs as $s) { ?><code class="me-1"><?= h(Format::truncate($s, 40)) ?></code><?php } ?></td>
                            <td class="text-nowrap small"><?= h(Format::relative($r['updatedAt'] ?? 0, $now)) ?></td>
                            <td class="text-end text-nowrap d-print-none">
                                <form method="post" action="<?= h((string) $view->action('reset')) ?>" class="d-inline">
                                    <?php $token->output('sg_score_reset'); ?>
                                    <input type="hidden" name="ip" value="<?= h($ip) ?>">
                                    <input type="hidden" name="page" value="<?= $curPage ?>">
                                    <button type="submit" class="btn btn-sm btn-outline-secondary"><?= h(t('Reset')) ?></button>
                                </form>
                                <?php if (!empty($r['banned'])) { ?>
                                    <span class="badge text-bg-danger"><?= h(t('Banned')) ?></span>
                                <?php } elseif (!in_array($ip, $clientIps['all'], true)) { ?>
                                    <form method="post" action="<?= h((string) $view->action('ban')) ?>" class="d-inline" data-sg-confirm="<?= h(t('Block %s?', $ip)) ?>">
                                        <?php $token->output('sg_score_ban'); ?>
                                        <input type="hidden" name="ip" value="<?= h($ip) ?>">
                                        <input type="hidden" name="page" value="<?= $curPage ?>">
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
    <?php View::element('pagination', ['pagination' => $pagination, 'baseUrl' => $pageUrl], 'security_guard'); ?>
</div>
