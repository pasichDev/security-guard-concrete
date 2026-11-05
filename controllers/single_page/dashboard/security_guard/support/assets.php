<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support;

defined('C5_EXECUTE') or die('Access Denied.');

/** Адреси статики пакета з версією = час зміни файлу (статика кешується на рік). */
final class Assets
{
    public static function url(string $rel): string
    {
        $dir = dirname(__DIR__, 5);
        $rel = ltrim(str_replace('..', '', $rel), '/');
        $v = @filemtime($dir . '/' . $rel) ?: 0;
        $base = defined('REL_DIR_PACKAGES') ? REL_DIR_PACKAGES : '/packages';

        return $base . '/security_guard/' . $rel . '?v=' . $v;
    }
}
