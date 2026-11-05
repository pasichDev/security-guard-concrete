<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Update;

use PasichDev\SecurityGuard\Logs\CrawlerRanges;
use Throwable;

/**
 * Оновлення діапазонів IP пошукових краулерів з офіційних списків.
 * Мережу дає $fetch (url => тіло відповіді), тож логіку можна перевіряти без мережі.
 * Бот оновлюється лише цілком: якщо хоч одне його джерело не завантажилось або не
 * пройшло перевірку, або новий список менший за половину попереднього, лишається старий.
 */
final class BotRangeUpdater
{
    public const SOURCES = [
        'Googlebot' => [
            'https://developers.google.com/static/search/apis/ipranges/googlebot.json',
            'https://developers.google.com/static/search/apis/ipranges/special-crawlers.json',
        ],
        'Bingbot' => ['https://www.bing.com/toolbox/bingbot.json'],
        'Applebot' => ['https://search.developer.apple.com/applebot.json'],
        'DuckDuckBot' => ['https://duckduckgo.com/duckduckbot.json'],
    ];
    /** Новий список не може бути меншим за цю частку попереднього. */
    public const MIN_KEEP_RATIO = 0.5;

    /** @var callable(string): string */
    private $fetch;
    /** @var BotRangeStoreInterface */
    private $store;

    public function __construct(callable $fetch, BotRangeStoreInterface $store)
    {
        $this->fetch = $fetch;
        $this->store = $store;
    }

    /**
     * @return array{updated: array<string, int>, unchanged: array<string, int>, errors: array<string, string>}
     */
    public function update(bool $dryRun = false, ?int $now = null): array
    {
        $now = $now ?? time();
        $result = ['updated' => [], 'unchanged' => [], 'errors' => []];
        $stored = $this->store->rangesByBot();
        foreach (self::SOURCES as $bot => $urls) {
            try {
                $all = [];
                $stamps = [];
                foreach ($urls as $url) {
                    $parsed = RangeListParser::parse(($this->fetch)($url));
                    foreach ($parsed['prefixes'] as $p) {
                        $all[$p] = true;
                    }
                    $stamps[] = $parsed['creationTime'];
                }
                $new = array_keys($all);
                sort($new);
                $previous = $stored[$bot] ?? (CrawlerRanges::PUBLISHED[$bot] ?? []);
                if (count($previous) > 0 && count($new) < count($previous) * self::MIN_KEEP_RATIO) {
                    throw new \RuntimeException(sprintf('List shrank from %d to %d prefixes; kept the previous one', count($previous), count($new)));
                }
                $old = $stored[$bot] ?? null;
                if ($old !== null) {
                    sort($old);
                }
                if ($old === $new) {
                    $result['unchanged'][$bot] = count($new);
                    if (!$dryRun) {
                        // Час перевірки оновлюємо, щоб було видно, що джерело живе.
                        $this->store->save($bot, $new, self::sourceLabel($urls, $stamps), $now);
                    }
                    continue;
                }
                if (!$dryRun) {
                    $this->store->save($bot, $new, self::sourceLabel($urls, $stamps), $now);
                }
                $result['updated'][$bot] = count($new);
            } catch (Throwable $e) {
                $result['errors'][$bot] = $e->getMessage();
            }
        }

        return $result;
    }

    private static function sourceLabel(array $urls, array $stamps): string
    {
        $parts = [];
        foreach ($urls as $i => $u) {
            $parts[] = basename((string) parse_url($u, PHP_URL_PATH)) . ($stamps[$i] !== '' ? '@' . $stamps[$i] : '');
        }

        return substr(implode(' ', $parts), 0, 255);
    }
}
