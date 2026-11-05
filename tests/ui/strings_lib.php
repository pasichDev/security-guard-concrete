<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

/*
 * Спільне для інструментів перекладу: збір рядків t()/t2() з коду пакета,
 * розбір і запис .po. Без залежностей (чистий PHP 8.2).
 */

declare(strict_types=1);

/** Мови пакета: локаль => Plural-Forms. Нову мову додавайте сюди. */
const SG_LOCALES = [
    'uk_UA' => 'nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);',
    'pl_PL' => 'nplurals=3; plural=(n==1 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);',
    'de_DE' => 'nplurals=2; plural=(n != 1);',
    'fr_FR' => 'nplurals=2; plural=(n > 1);',
    'es_ES' => 'nplurals=2; plural=(n != 1);',
    'it_IT' => 'nplurals=2; plural=(n != 1);',
    'nl_NL' => 'nplurals=2; plural=(n != 1);',
    'pt_BR' => 'nplurals=2; plural=(n > 1);',
];

/**
 * @return array<string, string[]> msgid => ["файл:рядок", ...]
 */
function sg_extract_strings(string $root): array
{
    $found = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        $path = (string) $file;
        $rel = substr($path, strlen($root) + 1);
        if (substr($path, -4) !== '.php' || strpos($rel, 'tests/') === 0 || strpos($rel, '.git/') === 0 || strpos($rel, 'bin/') === 0) {
            continue;
        }
        $code = (string) file_get_contents($path);
        $tokens = token_get_all($code);
        $n = count($tokens);
        for ($i = 0; $i < $n; ++$i) {
            $tk = $tokens[$i];
            if (!is_array($tk) || $tk[0] !== T_STRING || !in_array($tk[1], ['t', 't2'], true)) {
                continue;
            }
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
            $found[sg_php_literal($tokens[$j][1])][] = $rel . ':' . $tk[2];
        }
        // Назви й описи сторінок (controller.php::SINGLE_PAGES) Concrete перекладає сам.
        if ($rel === 'controller.php' && preg_match('/SINGLE_PAGES\s*=\s*\[(.*?)\];/s', $code, $m)) {
            preg_match_all("/=>\s*\[\s*('(?:[^'\\\\]|\\\\.)*')\s*,\s*('(?:[^'\\\\]|\\\\.)*')\s*\]/", $m[1], $mm, PREG_SET_ORDER);
            foreach ($mm as $pair) {
                $found[sg_php_literal($pair[1])][] = 'controller.php';
                $found[sg_php_literal($pair[2])][] = 'controller.php';
            }
        }
    }
    ksort($found, SORT_STRING);

    return $found;
}

function sg_php_literal(string $lit): string
{
    return $lit[0] === "'" ? str_replace(["\\'", '\\\\'], ["'", '\\'], substr($lit, 1, -1)) : stripcslashes(substr($lit, 1, -1));
}

/** @return array<string, string> msgid => msgstr (без заголовка) */
function sg_read_po(string $file): array
{
    $out = [];
    if (!is_file($file)) {
        return $out;
    }
    $id = null;
    $str = null;
    $cur = null;
    $flush = static function () use (&$id, &$str, &$out) {
        if ($id !== null && $id !== '') {
            $out[$id] = (string) $str;
        }
    };
    foreach (file($file) as $line) {
        $line = rtrim($line, "\r\n");
        if (strpos($line, 'msgid ') === 0) {
            $flush();
            $id = stripcslashes(substr($line, 7, -1));
            $str = null;
            $cur = 'id';
        } elseif (strpos($line, 'msgstr ') === 0) {
            $str = stripcslashes(substr($line, 8, -1));
            $cur = 'str';
        } elseif ($line !== '' && $line[0] === '"') {
            $chunk = stripcslashes(substr($line, 1, -1));
            if ($cur === 'id') {
                $id .= $chunk;
            } elseif ($cur === 'str') {
                $str .= $chunk;
            }
        }
    }
    $flush();

    return $out;
}

function sg_po_escape(string $s): string
{
    return str_replace(['\\', '"', "\n", "\t"], ['\\\\', '\\"', '\\n', '\\t'], $s);
}

/** Записує .po: заголовок + записи в порядку msgid. */
function sg_write_po(string $file, string $locale, array $refs, array $translations): void
{
    $plural = SG_LOCALES[$locale] ?? 'nplurals=2; plural=(n != 1);';
    $lang = substr($locale, 0, 2);
    $out = [
        '# Security Guard for Concrete CMS — ' . $locale . ' translation.',
        '# Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.',
        'msgid ""',
        'msgstr ""',
        '"Project-Id-Version: security_guard\\n"',
        '"Language: ' . $locale . '\\n"',
        '"MIME-Version: 1.0\\n"',
        '"Content-Type: text/plain; charset=UTF-8\\n"',
        '"Content-Transfer-Encoding: 8bit\\n"',
        '"Plural-Forms: ' . $plural . '\\n"',
        '',
    ];
    unset($lang);
    foreach ($refs as $id => $where) {
        foreach (array_slice(array_unique($where), 0, 3) as $r) {
            $out[] = '#: ' . $r;
        }
        if (preg_match('/%(?:\d+\$)?[sd]/', (string) $id)) {
            $out[] = '#, php-format';
        }
        $out[] = 'msgid "' . sg_po_escape((string) $id) . '"';
        $out[] = 'msgstr "' . sg_po_escape((string) ($translations[$id] ?? '')) . '"';
        $out[] = '';
    }
    if (!is_dir(dirname($file))) {
        mkdir(dirname($file), 0775, true);
    }
    file_put_contents($file, implode("\n", $out));
}

/** Плейсхолдери рядка — для звірки перекладу з оригіналом. */
function sg_placeholders(string $s): array
{
    preg_match_all('/%(?:\d+\$)?[sd]/', $s, $m);
    $p = $m[0];
    sort($p);

    return $p;
}
