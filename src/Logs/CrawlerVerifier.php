<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

use PasichDev\SecurityGuard\Rules\RuleSet;

/**
 * Справжній пошуковий краулер = User-Agent пошуковика (RuleSet::searchBots())
 * І IP з опублікованих діапазонів цього пошуковика (CrawlerRanges), або IP,
 * уже підтверджена rDNS у WAF (кеш SecurityGuardBotCache). Без мережевих запитів.
 * UA пошуковика з чужої IP — підробка, такий запит класифікується як звичайний.
 */
final class CrawlerVerifier
{
    /** @var array<string, string> назва => regex UA */
    private $uaRules = [];
    /** @var array<string, IpMatcher> */
    private $ranges = [];
    /** @var array<string, string> ip => назва бота (підтверджено rDNS) */
    private $verifiedIps;
    /** @var array<string, string|null> */
    private $memo = [];

    /**
     * @param array<string, string> $verifiedIps ip => назва з кешу rDNS WAF
     * @param array<string, string[]> $storedRanges бот => CIDR з SecurityGuardBotRanges (замінюють вбудовані PUBLISHED цього бота)
     */
    public function __construct(array $verifiedIps = [], array $storedRanges = [])
    {
        foreach (RuleSet::searchBots() as $name => [$re]) {
            $this->uaRules[$name] = $re;
        }
        $published = CrawlerRanges::PUBLISHED;
        foreach ($storedRanges as $name => $list) {
            if (isset($published[$name]) && is_array($list) && $list) {
                $published[$name] = array_values(array_map('strval', $list));
            }
        }
        foreach ([$published, CrawlerRanges::HEURISTIC] as $set) {
            foreach ($set as $name => $list) {
                $this->ranges[$name] = isset($this->ranges[$name])
                    ? new IpMatcher(array_merge($this->ranges[$name]->items(), $list))
                    : new IpMatcher($list);
            }
        }
        $this->verifiedIps = $verifiedIps;
    }

    /** Назва пошуковика з UA (без перевірки IP) або null. */
    public function claimedBot(string $userAgent): ?string
    {
        if ($userAgent === '') {
            return null;
        }
        foreach ($this->uaRules as $name => $re) {
            if (preg_match($re, $userAgent)) {
                return $name;
            }
        }

        return null;
    }

    /** Назва підтвердженого краулера або null (не пошуковик або підробка). */
    public function verify(string $ip, string $userAgent): ?string
    {
        $name = $this->claimedBot($userAgent);
        if ($name === null) {
            return null;
        }

        return $this->ipBelongsTo($ip, $name) ? $name : null;
    }

    public function ipBelongsTo(string $ip, string $name): bool
    {
        $key = $name . '|' . $ip;
        if (!array_key_exists($key, $this->memo)) {
            if (count($this->memo) > 20000) {
                $this->memo = [];
            }
            $ok = (isset($this->verifiedIps[$ip]) && strcasecmp($this->verifiedIps[$ip], $name) === 0)
                || (isset($this->ranges[$name]) && $this->ranges[$name]->matches($ip));
            $this->memo[$key] = $ok ? $name : null;
        }

        return $this->memo[$key] !== null;
    }
}
