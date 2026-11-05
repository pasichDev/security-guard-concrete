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
    /** @var array<string, array|false> кеш результатів: у логах ті самі URL і UA повторюються тисячі разів */
    private $memo = [];
    private const MEMO_MAX = 10000;

    public function __construct(RuleSet $rules)
    {
        $this->rules = $rules;
    }

    public function classify(string $method, string $uri, string $userAgent): ?array
    {
        if ($uri === '' && $method === '') {
            return null;
        }
        $hit = $this->classifyAny($method, $uri, $userAgent);
        if ($hit === null || in_array($hit['category'], self::NON_ATTACK_CATEGORIES, true)) {
            return null;
        }

        return $hit;
    }

    /** Класифікація без відсіювання «бот»-категорій (для розбивки відмов хостингу). */
    public function classifyAny(string $method, string $uri, string $userAgent): ?array
    {
        if ($uri === '' && $method === '') {
            return null;
        }
        $key = $method . ' ' . $uri . "\0" . $userAgent;
        if (strlen($key) > 600) {
            $key = md5($key);
        }
        if (isset($this->memo[$key])) {
            return $this->memo[$key] === false ? null : $this->memo[$key];
        }
        $hit = $this->rules->classifyRequest($method === '' ? 'GET' : $method, $uri, $userAgent);
        $out = is_array($hit) && isset($hit['category'])
            ? ['rule' => (string) ($hit['rule'] ?? ''), 'category' => (string) $hit['category'],
                'strength' => ($hit['strength'] ?? 'strong') === 'weak' ? 'weak' : 'strong']
            : null;
        if (count($this->memo) >= self::MEMO_MAX) {
            $this->memo = [];
        }
        $this->memo[$key] = $out ?? false;

        return $out;
    }
}
