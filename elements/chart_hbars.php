<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

/*
 * Горизонтальні смуги (розподіл за категоріями, статусами тощо). HTML+CSS,
 * щоб довгі українські підписи переносилися, а не обрізалися.
 * Параметри: $rows — [['label' => string, 'value' => int, 'critical' => bool?], ...],
 * $formatter — 'num' | 'bytes', $empty — текст, коли даних немає.
 */

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;

$rows = isset($rows) && is_array($rows) ? array_values($rows) : [];
$fmt = (isset($formatter) && $formatter === 'bytes') ? 'bytes' : 'num';
$total = 0;
$max = 0;
foreach ($rows as $r) {
    $total += (int) ($r['value'] ?? 0);
    $max = max($max, (int) ($r['value'] ?? 0));
}
if (!$rows || $max === 0) {
    ?><div class="sg-chart-empty"><?= h(isset($empty) ? (string) $empty : t('No data for this period.')) ?></div><?php
    return;
}
?>
<div class="sg-hbars">
    <?php foreach ($rows as $r) {
        $v = (int) ($r['value'] ?? 0);
        $pct = $total > 0 ? $v / $total * 100 : 0;
        $w = max(0.5, $v / $max * 100); ?>
        <div class="sg-hbar-row">
            <div class="sg-hbar-label" title="<?= h((string) ($r['title'] ?? $r['label'] ?? '')) ?>"><?= h(Format::truncate((string) ($r['label'] ?? ''), 90)) ?></div>
            <div class="sg-hbar-track">
                <div class="sg-hbar<?= !empty($r['critical']) ? ' sg-hbar-critical' : '' ?>" style="width: <?= round($w, 2) ?>%"></div>
            </div>
            <div class="sg-hbar-value"><?= h($fmt === 'bytes' ? Format::bytes($v) : Format::num($v)) ?><span class="sg-muted"> · <?= h(number_format($pct, $pct > 0 && $pct < 1 ? 1 : 0, ',', '')) ?>&nbsp;%</span></div>
        </div>
    <?php } ?>
</div>
