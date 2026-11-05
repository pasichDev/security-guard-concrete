<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/**
 * Розпізнає в логах сторінку 403 сервера хостингу (ModSecurity/Imunify, nginx,
 * правила .htaccess) — запити, відхилені ДО PHP, які пакет на запиті не бачить.
 *
 * Така сторінка статична, тож розмір відповіді в логах однаковий для будь-якого
 * URL і будь-якої IP (окремий розмір для кожного стиснення: без стиснення, gzip, br).
 * Евристика: розмір 403-відповіді вважається відбитком сервера, якщо
 *   - розмір ≥ MIN_BYTES (сторінка відмови самого пакета — кілька сотень байтів,
 *     порожні відповіді HEAD/обірвані з'єднання — 0), і
 *   - той самий розмір бачили щонайменше з MIN_IPS різних IP і на MIN_URLS різних шляхах.
 * Динамічні сторінки Concrete дають різні розміри для різних URL і цих порогів не досягають.
 * Ознаки — множини (IP, хеш шляху), тож повторне читання тих самих рядків
 * (ротація, повторний запуск) результату не змінює. Підтверджений розмір лишається
 * підтвердженим до --rebuild.
 */
final class HostWafDetector
{
    public const MIN_BYTES = 1024;
    public const MIN_IPS = 10;
    public const MIN_URLS = 20;
    private const MAX_CANDIDATES = 100;

    /** @var array<int, true> */
    private $confirmed = [];
    /** @var array<int, array{ips: array<string, true>, urls: array<string, true>}> */
    private $candidates = [];

    public function __construct(array $state = [])
    {
        foreach ((array) ($state['confirmed'] ?? []) as $size) {
            $this->confirmed[(int) $size] = true;
        }
        foreach ((array) ($state['candidates'] ?? []) as $size => $c) {
            if (!is_array($c)) {
                continue;
            }
            $this->candidates[(int) $size] = [
                'ips' => array_fill_keys(array_map('strval', (array) ($c['ips'] ?? [])), true),
                'urls' => array_fill_keys(array_map('strval', (array) ($c['urls'] ?? [])), true),
            ];
        }
    }

    /** Розбирає рядок, лише якщо це схоже на 403 (дешева перевірка до регексу). */
    public function observeLine(string $line): void
    {
        if (strpos($line, '" 403 ') === false) {
            return;
        }
        $r = LogParser::parse($line);
        if ($r !== null && $r['status'] === 403) {
            $this->observe($r['bytes'], $r['ip'], $r['path']);
        }
    }

    public function observe(int $bytes, string $ip, string $path): void
    {
        if ($bytes < self::MIN_BYTES || isset($this->confirmed[$bytes])) {
            return;
        }
        if (!isset($this->candidates[$bytes])) {
            if (count($this->candidates) >= self::MAX_CANDIDATES) {
                $this->evictWeakest();
            }
            $this->candidates[$bytes] = ['ips' => [], 'urls' => []];
        }
        $c = &$this->candidates[$bytes];
        if (count($c['ips']) < self::MIN_IPS) {
            $c['ips'][$ip] = true;
        }
        if (count($c['urls']) < self::MIN_URLS) {
            $c['urls'][substr(md5(strtolower($path)), 0, 10)] = true;
        }
        $done = count($c['ips']) >= self::MIN_IPS && count($c['urls']) >= self::MIN_URLS;
        unset($c);
        if ($done) {
            $this->confirmed[$bytes] = true;
            unset($this->candidates[$bytes]);
        }
    }

    /** @return int[] */
    public function confirmed(): array
    {
        $s = array_keys($this->confirmed);
        sort($s);

        return $s;
    }

    public function state(): array
    {
        $cand = [];
        ksort($this->candidates);
        foreach ($this->candidates as $size => $c) {
            $cand[(string) $size] = ['ips' => array_keys($c['ips']), 'urls' => array_keys($c['urls'])];
        }

        return ['confirmed' => $this->confirmed(), 'candidates' => $cand];
    }

    /** Розміри з налаштування host_waf_sizes ("3809, 3387 12588"). */
    public static function parseSizes(string $setting): array
    {
        $out = [];
        foreach (preg_split('/[\s,;]+/', $setting) ?: [] as $v) {
            if ($v !== '' && ctype_digit($v)) {
                $out[(int) $v] = true;
            }
        }
        $s = array_keys($out);
        sort($s);

        return $s;
    }

    private function evictWeakest(): void
    {
        $weakest = null;
        $score = PHP_INT_MAX;
        foreach ($this->candidates as $size => $c) {
            $n = count($c['ips']) + count($c['urls']);
            if ($n < $score) {
                $score = $n;
                $weakest = $size;
            }
        }
        if ($weakest !== null) {
            unset($this->candidates[$weakest]);
        }
    }
}
