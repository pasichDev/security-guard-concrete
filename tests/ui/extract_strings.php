<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

/*
 * Збирає всі рядки t('…') пакета і, якщо передано .po, показує рядки без
 * перекладу і зайві переклади:
 *   php tests/ui/extract_strings.php [languages/uk_UA/LC_MESSAGES/messages.po]
 * Вихід: JSON {"msgid": ["файл:рядок", ...]} у stdout; пропуски — у stderr.
 */

declare(strict_types=1);

require __DIR__ . '/strings_lib.php';

$found = sg_extract_strings(realpath(__DIR__ . '/../..'));
echo json_encode($found, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), "\n";

if (isset($argv[1])) {
    $po = sg_read_po($argv[1]);
    $missing = array_filter(array_keys($found), static function ($k) use ($po) {
        return ($po[$k] ?? '') === '';
    });
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
