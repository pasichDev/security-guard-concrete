<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support;

use Throwable;

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * Хто має доступ до панелі: лише супер-користувач або член групи
 * адміністраторів. Це додатковий захист поверх прав сторінок Concrete —
 * якщо хтось пізніше послабить права на /dashboard/security_guard, панель
 * однаково лишиться закритою.
 */
final class Access
{
    public static function isAdministrator(): bool
    {
        try {
            $app = function_exists('app') ? app() : null;
            if ($app === null) {
                return false;
            }
            $u = $app->make(\Concrete\Core\User\User::class);
            if (!$u || !$u->isRegistered()) {
                return false;
            }
            if ($u->isSuperUser()) {
                return true;
            }
            $group = \Concrete\Core\User\Group\Group::getByID(defined('ADMIN_GROUP_ID') ? ADMIN_GROUP_ID : 3);

            return $group && $u->inGroup($group);
        } catch (Throwable $e) {
            return false;
        }
    }
}
