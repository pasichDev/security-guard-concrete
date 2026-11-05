<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

/*
 * Збирає всі рядки t('…') пакета (токенізатором PHP) і, якщо передано .po,
 * показує рядки без перекладу і зайві переклади:
 *   php tests/ui/extract_strings.php [languages/uk_UA/LC_MESSAGES/messages.po]
 * Вихід: JSON {"msgid": ["файл:рядок", ...]} у stdout; пропуски — у stderr.
 */

declare(strict_types=1);

$root = realpath(__DIR__ . '/../..');
$found = [];
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
foreach ($it as $file) {
    $path = (string) $file;
    $rel = substr($path, strlen($root) + 1);
    if (substr($path, -4) !== '.php' || strpos($rel, 'tests/') === 0 || strpos($rel, '.git/') === 0) {
        continue;
    }
    $tokens = token_get_all((string) file_get_contents($path));
    $n = count($tokens);
    for ($i = 0; $i < $n; ++$i) {
        $tk = $tokens[$i];
        if (!is_array($tk) || $tk[0] !== T_STRING || !in_array($tk[1], ['t', 't2'], true)) {
            continue;
        }
        // Не метод і не оголошення функції.
        $prev = $i - 1;
        while ($prev >= 0 && is_array($tokens[$prev]) && $tokens[$prev][0] === T_WHITESPACE) {
            --$prev;
        }
        if ($prev >= 0 && is_array($tokens[$prev]) && in_array($tokens[$prev][0], [T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NULLSAFE_OBJECT_OPERATOR], true)) {
            continue;
        }
        $j = $i + 1;
        while ($j < $n && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
            ++$j;
        }
        if (($tokens[$j] ?? null) !== '(') {
            continue;
        }
        ++$j;
        while ($j < $n && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
            ++$j;
        }
        if (!is_array($tokens[$j] ?? null) || $tokens[$j][0] !== T_CONSTANT_ENCAPSED_STRING) {
            continue;
        }
        $lit = $tokens[$j][1];
        $str = $lit[0] === "'" ? str_replace(["\\'", '\\\\'], ["'", '\\'], substr($lit, 1, -1)) : stripcslashes(substr($lit, 1, -1));
        $found[$str][] = $rel . ':' . $tk[2];
    }
}
ksort($found);
echo json_encode($found, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), "\n";

if (isset($argv[1])) {
    require __DIR__ . '/bootstrap.php';
    $po = sg_parse_po($argv[1]);
    $missing = array_diff(array_keys($found), array_keys($po));
    $extra = array_diff(array_keys($po), array_keys($found));
    foreach ($missing as $m) {
        fwrite(STDERR, 'MISSING: ' . $m . "\n");
    }
    foreach ($extra as $e) {
        fwrite(STDERR, 'UNUSED: ' . $e . "\n");
    }
    fwrite(STDERR, count($found) . ' strings, ' . count($missing) . ' missing, ' . count($extra) . " unused\n");
    exit($missing ? 1 : 0);
}
