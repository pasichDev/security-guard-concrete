<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

/*
 * Компілює .po у .mo (формат GNU gettext, без хеш-таблиці) — без утиліт gettext:
 *   php tests/ui/compile_mo.php languages/uk_UA/LC_MESSAGES/messages.po
 * Підтримує однорядкові й багаторядкові msgid/msgstr; множинні форми — msgid_plural/msgstr[n].
 */

declare(strict_types=1);

$po = $argv[1] ?? '';
if (!is_file($po)) {
    fwrite(STDERR, "Usage: php compile_mo.php file.po\n");
    exit(2);
}
$unq = static function (string $s): string {
    return stripcslashes(substr($s, 1, -1));
};
$entries = [];
$cur = ['id' => null, 'plural' => null, 'str' => [], 'fuzzy' => false];
$field = null;
$flush = static function () use (&$cur, &$entries) {
    if ($cur['id'] !== null && !$cur['fuzzy']) {
        $strs = $cur['str'];
        ksort($strs);
        $key = $cur['plural'] !== null ? $cur['id'] . "\0" . $cur['plural'] : $cur['id'];
        $val = implode("\0", $strs);
        if ($val !== '' || $cur['id'] === '') {
            $entries[$key] = $val;
        }
    }
    $cur = ['id' => null, 'plural' => null, 'str' => [], 'fuzzy' => false];
};
foreach (file($po) as $line) {
    $line = trim($line);
    if ($line === '') {
        continue;
    }
    if ($line[0] === '#') {
        if (strpos($line, '#,') === 0 && strpos($line, 'fuzzy') !== false) {
            $flush();
            $cur['fuzzy'] = true;
        }
        continue;
    }
    if (preg_match('/^msgid\s+(".*")$/', $line, $m)) {
        if ($cur['id'] !== null) {
            $flush();
        }
        $cur['id'] = $unq($m[1]);
        $field = ['id'];
    } elseif (preg_match('/^msgid_plural\s+(".*")$/', $line, $m)) {
        $cur['plural'] = $unq($m[1]);
        $field = ['plural'];
    } elseif (preg_match('/^msgstr(?:\[(\d+)\])?\s+(".*")$/', $line, $m)) {
        $n = $m[1] === '' ? 0 : (int) $m[1];
        $cur['str'][$n] = $unq($m[2]);
        $field = ['str', $n];
    } elseif ($line[0] === '"' && $field !== null) {
        if ($field[0] === 'str') {
            $cur['str'][$field[1]] .= $unq($line);
        } else {
            $cur[$field[0]] .= $unq($line);
        }
    }
}
$flush();
ksort($entries, SORT_STRING);

$n = count($entries);
$origTable = 28;
$transTable = $origTable + $n * 8;
$dataStart = $transTable + $n * 8;
$ids = '';
$strs = '';
$idIdx = [];
$strIdx = [];
foreach ($entries as $id => $str) {
    $idIdx[] = [strlen((string) $id), strlen($ids)];
    $ids .= $id . "\0";
}
foreach ($entries as $str) {
    $strIdx[] = [strlen($str), strlen($strs)];
    $strs .= $str . "\0";
}
$out = pack('V7', 0x950412de, 0, $n, $origTable, $transTable, 0, $dataStart);
foreach ($idIdx as [$len, $off]) {
    $out .= pack('V2', $len, $dataStart + $off);
}
$strStart = $dataStart + strlen($ids);
foreach ($strIdx as [$len, $off]) {
    $out .= pack('V2', $len, $strStart + $off);
}
$out .= $ids . $strs;
$mo = preg_replace('/\.po$/', '.mo', $po);
file_put_contents($mo, $out);
echo "{$n} entries → {$mo}\n";
