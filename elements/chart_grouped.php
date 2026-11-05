<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

/*
 * Згрупований стовпчиковий графік для порівняння двох джерел по днях (одна вісь,
 * стовпчики поруч). Стиль — як у chart_bars: SVG на сервері, підказки data-sg-tip.
 *
 * Параметри: $points — [['label' => 'дд.мм', 'title' => 'дд.мм.рррр', 'values' => [int, int]], ...],
 * $series — [назва1, назва2], $unit, $aria, $height, $width, $empty.
 */

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;

$points = isset($points) && is_array($points) ? array_values($points) : [];
$series = isset($series) && is_array($series) ? array_values($series) : [];
$k = max(1, count($series));
$unit = isset($unit) ? (string) $unit : '';
$aria = isset($aria) ? (string) $aria : '';
$H = isset($height) ? max(120, (int) $height) : 220;
$W = isset($width) ? max(320, min(1200, (int) $width)) : 860;

$n = count($points);
$max = 0;
foreach ($points as $p) {
    foreach ((array) ($p['values'] ?? []) as $v) {
        $max = max($max, (int) $v);
    }
}
if ($n === 0 || $max === 0) {
    ?>
    <div class="sg-chart sg-chart-empty"><?= h(isset($empty) ? (string) $empty : t('No data for this period.')) ?></div>
    <?php
    return;
}

$pow = 10 ** floor(log10($max));
$m = $max / $pow;
$nice = ($m <= 1 ? 1 : ($m <= 2 ? 2 : ($m <= 2.5 ? 2.5 : ($m <= 5 ? 5 : 10))));
$top = $nice * $pow;
$divs = $nice === 2 ? 4 : 5;
if ($top <= 5) {
    $divs = max(1, (int) $top);
}

$L = 48;
$R = 8;
$T = 14;
$B = 28;
$pw = $W - $L - $R;
$ph = $H - $T - $B;
$step = $pw / $n;
$groupW = max(2, min(36, $step - max(1, $step * 0.25)));
$bw = max(1, $groupW / $k);
$y = static function ($v) use ($T, $ph, $top) {
    return $T + $ph - ($v / $top) * $ph;
};
$r2 = static function ($v) {
    return round($v, 1);
};
$every = max(1, (int) ceil($n / max(6, (int) ($W / 54))));
?>
<div class="sg-chart sg-chart-grouped">
    <div class="sg-legend">
        <?php foreach ($series as $i => $name) { ?>
            <span class="sg-legend-item"><span class="sg-swatch sg-series-<?= (int) $i ?>" aria-hidden="true"></span><?= h((string) $name) ?></span>
        <?php } ?>
    </div>
    <svg viewBox="0 0 <?= $W ?> <?= $H ?>" role="img" aria-label="<?= h($aria) ?>" preserveAspectRatio="xMidYMid meet">
        <?php for ($g = 0; $g <= $divs; ++$g) {
            $v = $top * $g / $divs;
            $yy = $r2($y($v)); ?>
            <line class="<?= $g ? 'sg-grid' : 'sg-axis' ?>" x1="<?= $L ?>" x2="<?= $W - $R ?>" y1="<?= $yy ?>" y2="<?= $yy ?>"/>
            <text class="sg-tick" x="<?= $L - 6 ?>" y="<?= $yy + 4 ?>" text-anchor="end"><?= h(Format::num($v)) ?></text>
        <?php } ?>
        <?php foreach ($points as $i => $p) {
            $x0 = $L + $i * $step + ($step - $groupW) / 2;
            $vals = array_values((array) ($p['values'] ?? []));
            $tipParts = [];
            $minY = $T + $ph;
            foreach ($series as $j => $name) {
                $v = (int) ($vals[$j] ?? 0);
                $tipParts[] = $name . ': ' . Format::num($v);
                if ($v <= 0) {
                    continue;
                }
                $x = $x0 + $j * $bw;
                $yy = $y($v);
                $minY = min($minY, $yy);
                $h = $T + $ph - $yy;
                $rr = min(3, $bw / 2, $h);
                $d = sprintf('M%s,%s V%s Q%s,%s %s,%s H%s Q%s,%s %s,%s V%s Z',
                    $r2($x), $r2($T + $ph), $r2($yy + $rr), $r2($x), $r2($yy), $r2($x + $rr), $r2($yy),
                    $r2($x + $bw - $rr), $r2($x + $bw), $r2($yy), $r2($x + $bw), $r2($yy + $rr), $r2($T + $ph)); ?>
                <path class="sg-bar sg-series-<?= (int) $j ?>" d="<?= $d ?>"/>
            <?php }
            $tip = (string) ($p['title'] ?? $p['label'] ?? '') . ' · ' . implode(' · ', $tipParts) . ($unit !== '' ? ' ' . $unit : '');
            if (($i % $every === 0 && $i <= $n - 1 - $every) || $i === $n - 1) { ?>
                <text class="sg-tick" x="<?= $r2($x0 + $groupW / 2) ?>" y="<?= $H - $B + 16 ?>" text-anchor="middle"><?= h((string) ($p['label'] ?? '')) ?></text>
            <?php } ?>
            <rect class="sg-hit" x="<?= $r2($L + $i * $step) ?>" y="<?= $T ?>" width="<?= $r2($step) ?>" height="<?= $ph ?>" data-sg-tip="<?= h($tip) ?>" data-sg-x="<?= $r2($x0 + $groupW / 2) ?>" data-sg-y="<?= $r2($minY) ?>"><title><?= h($tip) ?></title></rect>
        <?php } ?>
    </svg>
</div>
