<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

/*
 * Стовпчиковий графік, намальований на сервері (SVG): працює без JS і
 * друкується. JS лише показує гарні підказки за data-sg-tip; без нього
 * лишаються рідні <title>.
 *
 * Параметри: $points — [['label' => 'дд', 'title' => 'повна дата', 'value' => int], ...],
 * $unit — підпис одиниці в підказці, $aria, $height (px у viewBox),
 * $critical — червоний колір (лише для перевантажень/критичних станів),
 * $labels — скільки найбільших значень підписати над стовпчиком,
 * $formatter — 'num' | 'bytes', $width — ширина viewBox (за замовчуванням 860).
 */

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;

$points = isset($points) && is_array($points) ? array_values($points) : [];
$unit = isset($unit) ? (string) $unit : '';
$aria = isset($aria) ? (string) $aria : '';
$H = isset($height) ? max(120, (int) $height) : 220;
$critical = !empty($critical);
$labelCount = isset($labels) ? (int) $labels : 3;
$fmt = (isset($formatter) && $formatter === 'bytes') ? 'bytes' : 'num';
$f = static function ($v) use ($fmt) {
    return $fmt === 'bytes' ? Format::bytes($v) : Format::num($v);
};

$n = count($points);
$max = 0;
foreach ($points as $p) {
    $max = max($max, (int) ($p['value'] ?? 0));
}
if ($n === 0 || $max === 0) {
    ?>
    <div class="sg-chart sg-chart-empty"><?= h(isset($empty) ? (string) $empty : t('No data for this period.')) ?></div>
    <?php
    return;
}

// «Гарний» верх шкали: 1, 2, 2.5, 5, 10 × 10^n.
$pow = 10 ** floor(log10($max));
$m = $max / $pow;
$nice = ($m <= 1 ? 1 : ($m <= 2 ? 2 : ($m <= 2.5 ? 2.5 : ($m <= 5 ? 5 : 10))));
$top = $nice * $pow;
// Кроки шкали мають бути «круглими»: 1, 2.5, 5, 10 ділимо на 5, 2 — на 4;
// для малих чисел — крок 1, щоб не було дробових поділок на цілих даних.
$divs = $nice === 2 ? 4 : 5;
if ($top <= 5) {
    $divs = max(1, (int) $top);
}

// Вужчий viewBox для графіків у пів ширини, щоб підписи лишалися читабельними.
$W = isset($width) ? max(320, min(1200, (int) $width)) : 860;
$L = $fmt === 'bytes' ? 64 : 48;
$R = 8;
$T = 22;
$B = 28;
$pw = $W - $L - $R;
$ph = $H - $T - $B;
$step = $pw / $n;
$bw = max(2, min(28, $step - max(1, $step * 0.25)));
$y = static function ($v) use ($T, $ph, $top) {
    return $T + $ph - ($v / $top) * $ph;
};

$sorted = [];
foreach ($points as $i => $p) {
    if ((int) ($p['value'] ?? 0) > 0) {
        $sorted[$i] = (int) $p['value'];
    }
}
arsort($sorted);
$labelled = array_slice(array_keys($sorted), 0, max(0, $labelCount));
$every = max(1, (int) ceil($n / max(6, (int) ($W / 54))));
$r2 = static function ($v) {
    return round($v, 1);
};
?>
<div class="sg-chart<?= $critical ? ' sg-chart-critical' : '' ?>">
    <svg viewBox="0 0 <?= $W ?> <?= $H ?>" role="img" aria-label="<?= h($aria) ?>" preserveAspectRatio="xMidYMid meet">
        <?php for ($g = 0; $g <= $divs; ++$g) {
            $v = $top * $g / $divs;
            $yy = $r2($y($v)); ?>
            <line class="<?= $g ? 'sg-grid' : 'sg-axis' ?>" x1="<?= $L ?>" x2="<?= $W - $R ?>" y1="<?= $yy ?>" y2="<?= $yy ?>"/>
            <text class="sg-tick" x="<?= $L - 6 ?>" y="<?= $yy + 4 ?>" text-anchor="end"><?= h($f($v)) ?></text>
        <?php } ?>
        <?php foreach ($points as $i => $p) {
            $v = (int) ($p['value'] ?? 0);
            $x = $L + $i * $step + ($step - $bw) / 2;
            $yy = $y($v);
            $h = $T + $ph - $yy;
            $tip = (string) ($p['title'] ?? $p['label'] ?? '') . ' · ' . $f($v) . ($unit !== '' ? ' ' . $unit : '');
            if ($v > 0) {
                $rr = min(4, $bw / 2, $h);
                $d = sprintf('M%s,%s V%s Q%s,%s %s,%s H%s Q%s,%s %s,%s V%s Z',
                    $r2($x), $r2($T + $ph), $r2($yy + $rr), $r2($x), $r2($yy), $r2($x + $rr), $r2($yy),
                    $r2($x + $bw - $rr), $r2($x + $bw), $r2($yy), $r2($x + $bw), $r2($yy + $rr), $r2($T + $ph)); ?>
                <path class="sg-bar" d="<?= $d ?>"/>
            <?php }
            if (in_array($i, $labelled, true)) { ?>
                <text class="sg-lbl" x="<?= $r2($x + $bw / 2) ?>" y="<?= $r2($yy - 5) ?>" text-anchor="middle"><?= h($f($v)) ?></text>
            <?php }
            if (($i % $every === 0 && $i <= $n - 1 - $every) || $i === $n - 1) { ?>
                <text class="sg-tick" x="<?= $r2($x + $bw / 2) ?>" y="<?= $H - $B + 16 ?>" text-anchor="middle"><?= h((string) ($p['label'] ?? '')) ?></text>
            <?php } ?>
            <rect class="sg-hit" x="<?= $r2($L + $i * $step) ?>" y="<?= $T ?>" width="<?= $r2($step) ?>" height="<?= $ph ?>" data-sg-tip="<?= h($tip) ?>" data-sg-x="<?= $r2($x + $bw / 2) ?>" data-sg-y="<?= $r2(min($yy, $T + $ph)) ?>"><title><?= h($tip) ?></title></rect>
        <?php } ?>
    </svg>
</div>
