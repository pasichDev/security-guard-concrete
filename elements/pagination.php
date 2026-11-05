<?php
/* Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE. */
defined('C5_EXECUTE') or die('Access Denied.');

/* Пагінація Bootstrap 5. Параметри: $pagination = ['total','perPage','page','pages','query'], $baseUrl. */

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;

if (!isset($pagination) || !is_array($pagination)) {
    return;
}
$pages = max(1, (int) ($pagination['pages'] ?? 1));
$page = max(1, min($pages, (int) ($pagination['page'] ?? 1)));
$query = (array) ($pagination['query'] ?? []);
$baseUrl = isset($baseUrl) ? (string) $baseUrl : '';
$link = static function (int $p) use ($query, $baseUrl) {
    $q = array_filter($query + [], static function ($v) {
        return $v !== null && $v !== '';
    });
    $q['page'] = $p;

    return $baseUrl . (strpos($baseUrl, '?') === false ? '?' : '&') . http_build_query($q);
};
$from = ($page - 1) * (int) $pagination['perPage'] + 1;
$to = min((int) $pagination['total'], $page * (int) $pagination['perPage']);
if ($from > $to) {
    $from = $to;
}
?>
<div class="sg-pagination d-flex flex-wrap align-items-center justify-content-between gap-2 mt-3">
    <div class="sg-muted small">
        <?php if ((int) $pagination['total'] > 0) { ?>
            <?= h(t('%s–%s of %s', Format::num($from), Format::num($to), Format::num($pagination['total']))) ?>
        <?php } ?>
    </div>
    <?php if ($pages > 1) { ?>
        <nav aria-label="<?= h(t('Pages')) ?>">
            <ul class="pagination pagination-sm mb-0 flex-wrap">
                <li class="page-item<?= $page <= 1 ? ' disabled' : '' ?>"><a class="page-link" href="<?= h($link(max(1, $page - 1))) ?>">&laquo;</a></li>
                <?php
                $window = array_unique(array_filter([1, $page - 2, $page - 1, $page, $page + 1, $page + 2, $pages], static function ($p) use ($pages) {
                    return $p >= 1 && $p <= $pages;
                }));
                sort($window);
                $prev = 0;
                foreach ($window as $p) {
                    if ($prev && $p > $prev + 1) { ?>
                        <li class="page-item disabled"><span class="page-link">…</span></li>
                    <?php } ?>
                    <li class="page-item<?= $p === $page ? ' active' : '' ?>"><a class="page-link" href="<?= h($link($p)) ?>"><?= (int) $p ?></a></li>
                    <?php $prev = $p;
                } ?>
                <li class="page-item<?= $page >= $pages ? ' disabled' : '' ?>"><a class="page-link" href="<?= h($link(min($pages, $page + 1))) ?>">&raquo;</a></li>
            </ul>
        </nav>
    <?php } ?>
</div>
