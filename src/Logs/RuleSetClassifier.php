<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

use PasichDev\SecurityGuard\Rules\RuleSet;

/**
 * Основна класифікація: ті самі правила, що й у WAF.
 * Категорії, які означають «бот», а не атаку (категорія ai_crawler), атакою не рахуються —
 * для них є окремий лічильник botRequests.
 */
final class RuleSetClassifier implements AttackClassifierInterface
{
    public const NON_ATTACK_CATEGORIES = ['ai_crawler'];

    /** @var RuleSet */
    private $rules;

    public function __construct(RuleSet $rules)
    {
        $this->rules = $rules;
    }

    public function classify(string $method, string $uri, string $userAgent): ?array
    {
        if ($uri === '' && $method === '') {
            return null;
        }
        $hit = $this->rules->classifyRequest($method === '' ? 'GET' : $method, $uri, $userAgent);
        if (!is_array($hit) || !isset($hit['category'])) {
            return null;
        }
        if (in_array($hit['category'], self::NON_ATTACK_CATEGORIES, true)) {
            return null;
        }

        return ['rule' => (string) ($hit['rule'] ?? ''), 'category' => (string) $hit['category']];
    }

    /** Класифікація без відсіювання «бот»-категорій (для розбивки відмов хостингу). */
    public function classifyAny(string $method, string $uri, string $userAgent): ?array
    {
        if ($uri === '' && $method === '') {
            return null;
        }
        $hit = $this->rules->classifyRequest($method === '' ? 'GET' : $method, $uri, $userAgent);
        if (!is_array($hit) || !isset($hit['category'])) {
            return null;
        }

        return ['rule' => (string) ($hit['rule'] ?? ''), 'category' => (string) $hit['category']];
    }
}
