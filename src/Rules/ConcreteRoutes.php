<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Rules;

/**
 * Службові маршрути Concrete 9.5 (/ccm/...). Анонімний відвідувач фронтенду
 * користується лише невеликою частиною — список ALLOW нижче складено за
 * concrete/routes/*.php та src/Routing/SystemRouteList.php ядра 9.5.2. Решта
 * (діалоги, панелі, backend, file, page, block, user, permissions, workflow,
 * express, boards, calendar dialogs, search, tree, attribute, messenger,
 * summary_template, upgrade…) потрібна лише тому, хто увійшов. Для логів
 * хостингу ці правила не застосовуються: там не видно, хто увійшов.
 */
final class ConcreteRoutes
{
    /** Маршрути /ccm/, які законно відкриває анонімний відвідувач. */
    private const ALLOW = [
        '#^/ccm/assets/localization/#',                       // переклади для JS ядра
        '#^/ccm/frontend/(?:conversations|multilingual)/#',   // коментарі, перемикач мови
        '#^/ccm/system/captcha/picture/?$#',                  // зображення капчі у формах
        '#^/ccm/system/css/(?:layout|page)/#',                // CSS макетів і сторінок
        '#^/ccm/system/heartbeat/?$#',                        // відповідає й гостю; нешкідливий
        '#^/ccm/system/accept_privacy_policy/?$#',            // банер політики приватності
        '#^/ccm/system/country-(?:data-link|stateprovince-link)/#', // поле «Адреса» у формах
        '#^/ccm/system/jobs(?:/run_single)?/?$#',             // зовнішній cron за токеном
        '#^/ccm/calendar/(?:view_event|feed)/#',              // календар на фронтенді, RSS календаря
        '#^/ccm/calendar/event/export/?$#',                   // «Додати в календар» (блок calendar_event)
        '#^/ccm/site/redirect/#',                             // вибір сайту (мультисайт)
        '#^/ccm/api/#',                                       // REST API: власна автентифікація OAuth2 і права за scope
    ];

    /** Шлях без «/index.php» на початку, нормалізований. */
    public static function route(string $path): string
    {
        [$path] = Paths::split($path);
        $path = Paths::normalize($path);
        if (strncmp($path, '/index.php/', 11) === 0) {
            $path = substr($path, 10);
        }

        return $path;
    }

    /**
     * Чи анонімний запит іде на службовий маршрут, потрібний лише тому, хто
     * увійшов. Викликати ЛИШЕ для невідомих (не залогінених) відвідувачів.
     */
    public static function classifyAnonymous(string $path): ?array
    {
        $route = self::route($path);
        if (strncmp($route, '/ccm/', 5) !== 0) {
            return null;
        }
        if (preg_match('#^/ccm/system/upgrade(?:/|$)#', $route)) {
            return ['rule' => 'CONCRETE_UPGRADE_ANON', 'category' => 'concrete'];
        }
        foreach (self::ALLOW as $regex) {
            if (preg_match($regex, $route)) {
                return null;
            }
        }

        return ['rule' => 'CONCRETE_BACKEND_ANON', 'category' => 'concrete'];
    }
}
