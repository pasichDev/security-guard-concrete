<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;

/**
 * @var Concrete\Core\Page\View\PageView $view
 * @var Concrete\Core\Validation\CSRF\Token $token
 * @var array $values
 * @var array $groups
 * @var array $fields
 * @var array $clientIps
 * @var string $siteUrl
 * @var array $sources
 */
$groupLabels = [
    'General' => t('General'),
    'Trust' => t('Trust'),
    'Blocking' => t('Blocking'),
    'Signatures' => t('Signatures'),
    'Bots' => t('Bots'),
    'Honeypot' => t('Honeypot'),
    'Rate limiting' => t('Rate limiting'),
    'Behaviour' => t('Behaviour'),
    'Login' => t('Login'),
    'DDoS' => t('DDoS'),
    'Geo' => t('Geo'),
    'Hosting logs' => t('Hosting logs'),
    'Updates' => t('Updates'),
];
$slug = static function (string $g): string {
    return 'sg-group-' . trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($g)) ?? '', '-');
};
$compact = static function ($sec): string {
    $sec = (int) $sec;
    foreach ([604800 => 'w', 86400 => 'd', 3600 => 'h', 60 => 'm'] as $unit => $suffix) {
        if ($sec >= $unit && $sec % $unit === 0) {
            $n = intdiv($sec, $unit);
            // 7d читається краще за 1w, а 30d — за 4w2d.
            if ($suffix === 'w') {
                return ($n * 7) . 'd';
            }

            return $n . $suffix;
        }
    }

    return (string) $sec;
};
$token_ = (string) ($values['bypass_token'] ?? '');
?>
<div class="sg-page sg-settings">
    <?php View::element('nav', ['current' => $sgPagePath ?? '', 'mode' => $sgMode ?? '', 'errors' => $sgServiceErrors ?? []], 'security_guard'); ?>

    <div class="row g-4">
        <div class="col-lg-3 d-none d-lg-block d-print-none">
            <nav class="sg-settings-index" aria-label="<?= h(t('Sections')) ?>">
                <?php foreach ($groups as $g => $keys) { ?>
                    <a href="#<?= h($slug($g)) ?>"><?= h($groupLabels[$g] ?? $g) ?></a>
                <?php } ?>
            </nav>
        </div>
        <div class="col-lg-9">
            <form method="post" action="<?= h((string) $view->action('save')) ?>" class="sg-settings-form" novalidate>
                <?php $token->output('sg_settings_save'); ?>
                <?php /* Enter у будь-якому полі має зберігати, а не генерувати новий токен. */ ?>
                <button type="submit" class="visually-hidden" tabindex="-1" aria-hidden="true"><?= h(t('Save')) ?></button>
                <?php foreach ($groups as $g => $keys) { ?>
                    <section class="sg-card" id="<?= h($slug($g)) ?>">
                        <div class="sg-card-head"><h3><?= h($groupLabels[$g] ?? $g) ?></h3></div>
                        <?php foreach ($keys as $key) {
                            if (!isset($fields[$key])) {
                                continue;
                            }
                            $f = $fields[$key];
                            $id = 'sg-s-' . str_replace('_', '-', $key);
                            $name = 's_' . $key;
                            $val = $values[$key] ?? ''; ?>
                            <div class="sg-field sg-field-<?= h($f['type']) ?>">
                                <?php if ($f['type'] === 'bool') { ?>
                                    <div class="form-check form-switch">
                                        <input type="hidden" name="<?= h($name) ?>" value="0">
                                        <input class="form-check-input" type="checkbox" role="switch" id="<?= h($id) ?>" name="<?= h($name) ?>" value="1"<?= $val ? ' checked' : '' ?>>
                                        <label class="form-check-label" for="<?= h($id) ?>"><?= h($f['label']) ?></label>
                                    </div>
                                <?php } else { ?>
                                    <label class="form-label" for="<?= h($id) ?>"><?= h($f['label']) ?></label>
                                    <?php switch ($f['type']) {
                                        case 'int': ?>
                                            <input class="form-control form-control-sm sg-input-num" type="number" id="<?= h($id) ?>" name="<?= h($name) ?>" value="<?= h((string) $val) ?>" step="1"<?= isset($f['min']) ? ' min="' . (int) $f['min'] . '"' : '' ?><?= isset($f['max']) ? ' max="' . (int) $f['max'] . '"' : '' ?> inputmode="numeric">
                                            <?php break;
                                        case 'mode': ?>
                                            <select class="form-select form-select-sm sg-input-short" id="<?= h($id) ?>" name="<?= h($name) ?>">
                                                <option value="monitor"<?= $val !== 'enforce' ? ' selected' : '' ?>><?= h(t('Monitor — only log')) ?></option>
                                                <option value="enforce"<?= $val === 'enforce' ? ' selected' : '' ?>><?= h(t('Enforce — block attacks')) ?></option>
                                            </select>
                                            <?php break;
                                        case 'response_code': ?>
                                            <select class="form-select form-select-sm sg-input-short" id="<?= h($id) ?>" name="<?= h($name) ?>">
                                                <?php foreach ([403 => t('403 Forbidden'), 404 => t('404 Not Found'), 410 => t('410 Gone')] as $code => $label) { ?>
                                                    <option value="<?= $code ?>"<?= (int) $val === $code ? ' selected' : '' ?>><?= h($label) ?></option>
                                                <?php } ?>
                                            </select>
                                            <?php break;
                                        case 'escalation': ?>
                                            <input class="form-control form-control-sm" type="text" id="<?= h($id) ?>" name="<?= h($name) ?>" value="<?= h(is_array($val) ? implode(', ', array_map($compact, $val)) : (string) $val) ?>" spellcheck="false" autocomplete="off">
                                            <?php break;
                                        case 'token': ?>
                                            <div class="input-group input-group-sm">
                                                <input class="form-control font-monospace" type="text" id="<?= h($id) ?>" name="<?= h($name) ?>" value="<?= h((string) $val) ?>" maxlength="128" spellcheck="false" autocomplete="off">
                                                <button type="submit" class="btn btn-outline-secondary" name="generate_token" value="1" formnovalidate><?= h(t('Generate and save')) ?></button>
                                            </div>
                                            <?php if ($token_ !== '') { ?>
                                                <div class="small mt-1"><?= h(t('Emergency link:')) ?> <code class="sg-break"><?= h($siteUrl . '/?sg_pass=' . $token_) ?></code></div>
                                            <?php } ?>
                                            <?php break;
                                        case 'ranges':
                                        case 'paths':
                                        case 'sources': ?>
                                            <textarea class="form-control form-control-sm font-monospace" id="<?= h($id) ?>" name="<?= h($name) ?>" rows="4" spellcheck="false"><?= h((string) $val) ?></textarea>
                                            <?php break;
                                        default: ?>
                                            <input class="form-control form-control-sm" type="text" id="<?= h($id) ?>" name="<?= h($name) ?>" value="<?= h((string) $val) ?>" maxlength="1000"<?= $f['type'] === 'countries' ? ' spellcheck="false"' : '' ?>>
                                    <?php } ?>
                                <?php } ?>
                                <?php if ($f['help'] !== '') { ?><div class="form-text"><?= h($f['help']) ?></div><?php } ?>
                                <?php if ($key === 'whitelist_ranges' && $clientIps['all']) { ?>
                                    <div class="form-text"><?= h(t('Your IP address:')) ?> <?php foreach ($clientIps['all'] as $ip) { ?><code class="me-1"><?= h($ip) ?></code><?php } ?></div>
                                <?php } ?>
                                <?php if ($key === 'log_sources' && $sources) { ?>
                                    <div class="form-text"><?= h(t('Found now:')) ?>
                                        <?php foreach (array_slice($sources, 0, 10, true) as $path => $size) { ?><code class="me-1"><?= h(Format::truncate(is_string($path) ? $path : (string) $size, 100)) ?></code><?php } ?>
                                    </div>
                                <?php } ?>
                            </div>
                        <?php } ?>
                    </section>
                <?php } ?>
                <div class="ccm-dashboard-form-actions-wrapper">
                    <div class="ccm-dashboard-form-actions">
                        <button type="submit" class="btn btn-primary float-end"><?= h(t('Save')) ?></button>
                    </div>
                </div>
            </form>
        </div>
    </div>
</div>
