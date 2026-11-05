<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

/*
 * Синхронізує всі languages/<локаль>/LC_MESSAGES/messages.po з кодом:
 * додає нові рядки (порожній msgstr), прибирає застарілі, впорядковує,
 * перевіряє плейсхолдери і компілює .mo.
 *
 *   php tests/ui/sync_po.php                       — усі мови з SG_LOCALES (strings_lib.php)
 *   php tests/ui/sync_po.php de_DE                 — одна мова
 *   php tests/ui/sync_po.php de_DE --import=-      — взяти переклади з STDIN (рядки "msgid<TAB>msgstr")
 *
 * Код виходу 1, якщо є неперекладені рядки або розбіжність плейсхолдерів.
 * Нова мова: додайте її в SG_LOCALES, запустіть sync для неї, перекладіть msgstr
 * (у .po або через --import), запустіть ще раз.
 */

declare(strict_types=1);

require __DIR__ . '/strings_lib.php';

$root = realpath(__DIR__ . '/../..');
$args = array_slice($argv, 1);
$import = null;
$locales = [];
foreach ($args as $a) {
    if (strpos($a, '--import=') === 0) {
        $import = substr($a, 9);
    } else {
        $locales[] = $a;
    }
}
if (!$locales) {
    $locales = array_keys(SG_LOCALES);
}
foreach ($locales as $l) {
    if (!isset(SG_LOCALES[$l])) {
        fwrite(STDERR, "Unknown locale {$l}: add it to SG_LOCALES in tests/ui/strings_lib.php\n");
        exit(2);
    }
}

$refs = sg_extract_strings($root);
$bad = 0;
foreach ($locales as $locale) {
    $file = $root . '/languages/' . $locale . '/LC_MESSAGES/messages.po';
    $tr = sg_read_po($file);
    if ($import !== null) {
        $src = $import === '-' ? stream_get_contents(STDIN) : (string) file_get_contents($import);
        foreach (preg_split('/\r\n|\r|\n/', (string) $src) ?: [] as $line) {
            if ($line === '' || strpos($line, "\t") === false) {
                continue;
            }
            [$id, $str] = explode("\t", $line, 2);
            $tr[stripcslashes($id)] = stripcslashes($str);
        }
    }
    $tr = array_intersect_key($tr, $refs);
    sg_write_po($file, $locale, $refs, $tr);

    $missing = 0;
    foreach ($refs as $id => $_) {
        $str = (string) ($tr[$id] ?? '');
        if ($str === '') {
            ++$missing;
            fwrite(STDERR, "{$locale} MISSING: {$id}\n");
        } elseif (sg_placeholders((string) $id) !== sg_placeholders($str)) {
            ++$bad;
            fwrite(STDERR, "{$locale} PLACEHOLDERS: {$id}\n");
        }
    }
    $bad += $missing;
    // Компіляція .mo тим самим процесом (без повторного читання з диска).
    $_SERVER['argv'] = $argv = ['compile_mo.php', $file];
    ob_start();
    include __DIR__ . '/compile_mo.php';
    $msg = trim((string) ob_get_clean());
    echo $locale . ': ' . count($refs) . ' strings, ' . $missing . ' untranslated; ' . $msg . "\n";
}
exit($bad ? 1 : 0);
