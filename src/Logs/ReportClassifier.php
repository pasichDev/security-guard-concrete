<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/**
 * Спрощена класифікація для звірки з ручними підрахунками за логами: атака —
 * запит, URL якого відповідає одному регексу (без урахування регістру).
 * Основна класифікація — RuleSetClassifier.
 */
final class ReportClassifier implements AttackClassifierInterface
{
    public const PATTERN = '~wp-|xmlrpc|\.env|\.git|phpmyadmin|eval\(|shell|option=com_|/(zwso|xxx|alfa|wso|c99|r57|up|cmd|bypass|admin)\.php|\.\./|union.*select|/etc/passwd~i';

    /** Категорія за першим збігом (порядок важливий). */
    private const CATEGORIES = [
        'wordpress' => '~wp-|xmlrpc~i',
        'joomla' => '~option=com_~i',
        'secrets' => '~\.env|\.git|phpmyadmin~i',
        'injection' => '~\.\./|union.*select|/etc/passwd~i',
        'shells' => '~eval\(|shell|/(zwso|xxx|alfa|wso|c99|r57|up|cmd|bypass|admin)\.php~i',
    ];

    public function classify(string $method, string $uri, string $userAgent): ?array
    {
        if ($uri === '' || !preg_match(self::PATTERN, $uri)) {
            return null;
        }
        foreach (self::CATEGORIES as $category => $re) {
            if (preg_match($re, $uri)) {
                return ['rule' => 'REPORT_' . strtoupper($category), 'category' => $category];
            }
        }

        return ['rule' => 'REPORT_OTHER', 'category' => 'other'];
    }

    /** Невдалий вхід «як у звіті»: POST, у URL є "login", відповідь 200 або 400. */
    public static function isLoginFailure(string $method, string $uri, int $status): bool
    {
        return $method === 'POST' && ($status === 200 || $status === 400) && stripos($uri, 'login') !== false;
    }
}
