<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Waf;

/** Рішення відмовити: код відповіді й причина (у відповідь причина не потрапляє). */
final class Decision
{
    /** @var int */
    public $status;
    /** @var string */
    public $rule;
    /** @var string */
    public $category;
    /** Секунд до кінця бану (для Retry-After), 0 — невідомо/назавжди. @var int */
    public $retryAfter;

    public function __construct(int $status, string $rule, string $category, int $retryAfter = 0)
    {
        $this->status = $status;
        $this->rule = $rule;
        $this->category = $category;
        $this->retryAfter = $retryAfter;
    }

    public function isBruteforce(): bool
    {
        return $this->status === 429;
    }
}
