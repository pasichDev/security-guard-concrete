<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace PasichDev\SecurityGuard\Contract;

/**
 * Журнал подій WAF (таблиця SecurityGuardEvents).
 *
 * Категорії (поле category): wordpress, joomla, secrets, shells, injection,
 * xss, traversal, scanner, ai_crawler, honeypot, bruteforce, ratelimit,
 * php_probe, behavior, ddos, geo, fake_bot, blocked_ip.
 * Дії (поле action): logged (monitor), blocked (відмова 403/404), banned (поставлено бан),
 * denied (запит від уже забаненої IP).
 */
interface EventLogInterface
{
    public function log(string $ip, string $rule, string $category, string $action, array $request = []): void;

    /**
     * Фільтри: category, action, ip, from (unix), to (unix), search (url/ua).
     * @return array{rows: array, total: int}
     */
    public function query(array $filters = [], int $limit = 50, int $offset = 0): array;

    /**
     * Агрегати для панелі за період [from, to):
     * ['total' => int, 'byCategory' => [cat => n], 'byAction' => [..], 'byDay' => ['YYYY-MM-DD' => n],
     *  'topIps' => [['ip'=>..,'count'=>..,'country'=>..]], 'topRules' => [..], 'uniqueIps' => int]
     */
    public function summary(int $from, int $to): array;

    public function purgeOlderThan(int $days): int;
}
