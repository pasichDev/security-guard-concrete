<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/**
 * Розбір рядка Apache combined / common log. Чистий PHP, без Concrete.
 *
 * Рядок рахується запитом, якщо в ньому є IP і коректний час — навіть коли
 * сам запит порожній ("" або "-"), як буває у сканерів і битих з'єднань.
 */
final class LogParser
{
    private const MONTHS = [
        'Jan' => 1, 'Feb' => 2, 'Mar' => 3, 'Apr' => 4, 'May' => 5, 'Jun' => 6,
        'Jul' => 7, 'Aug' => 8, 'Sep' => 9, 'Oct' => 10, 'Nov' => 11, 'Dec' => 12,
    ];

    // authuser може містити пробіли (HTTP Basic з ім'ям на кшталт «John Doe»), тому він лінивий.
    private const LINE_RE = '/^(\S+) \S+ .*? \[[^\]]+\] "((?:[^"\\\\]|\\\\.)*)" (\d{3}|-) (\d+|-)(?: "((?:[^"\\\\]|\\\\.)*)" "((?:[^"\\\\]|\\\\.)*)")?/';

    /** @var array<string, int> кеш "дата:година зсув" => unix-час початку години */
    private static $hourCache = [];

    /**
     * Лише час рядка (unix) — дешево, без регулярних виразів. null — рядок битий.
     */
    public static function timestamp(string $line): ?int
    {
        $p = strpos($line, '[');
        if ($p === false || $p > 300 || strlen($line) < $p + 28 || $line[$p + 27] !== ']') {
            return null;
        }
        // 31/Oct/2026:22:18:03 +0200
        $key = substr($line, $p + 1, 14) . substr($line, $p + 21, 6);
        $base = self::$hourCache[$key] ?? null;
        if ($base === null) {
            $base = self::hourStart(substr($line, $p + 1, 26));
            if ($base === null) {
                return null;
            }
            if (count(self::$hourCache) > 5000) {
                self::$hourCache = [];
            }
            self::$hourCache[$key] = $base;
        }
        $mi = substr($line, $p + 16, 2);
        $se = substr($line, $p + 19, 2);
        if (!ctype_digit($mi) || !ctype_digit($se) || (int) $mi > 59 || (int) $se > 60) {
            return null;
        }

        return $base + (int) $mi * 60 + (int) $se;
    }

    /** Дата з самого рядка логу (YYYY-MM-DD у часовому поясі сервера) або null. */
    public static function literalDay(string $line): ?string
    {
        $p = strpos($line, '[');
        if ($p === false || strlen($line) < $p + 12) {
            return null;
        }
        $m = self::MONTHS[substr($line, $p + 4, 3)] ?? null;
        $d = substr($line, $p + 1, 2);
        $y = substr($line, $p + 8, 4);
        if ($m === null || !ctype_digit($d) || !ctype_digit($y)) {
            return null;
        }

        return sprintf('%s-%02d-%s', $y, $m, $d);
    }

    /**
     * Повний розбір. null — немає IP/часу (такий рядок пропускається).
     *
     * @return array{ip:string, ts:int, method:string, uri:string, path:string, status:int, bytes:int, referer:string, ua:string, partial:bool}|null
     */
    public static function parse(string $line): ?array
    {
        $line = rtrim($line, "\r\n");
        $ts = self::timestamp($line);
        if ($ts === null) {
            return null;
        }
        $sp = strpos($line, ' ');
        if ($sp === false || $sp === 0) {
            return null;
        }
        $ip = substr($line, 0, $sp);

        $out = [
            'ip' => $ip, 'ts' => $ts, 'method' => '', 'uri' => '', 'path' => '',
            'status' => 0, 'bytes' => 0, 'referer' => '', 'ua' => '', 'partial' => true, 'rawUri' => '',
        ];
        if (!preg_match(self::LINE_RE, $line, $m)) {
            return $out;
        }
        // Apache екранує лапки й керівні символи (\" та \xhh) у запиті, referer і UA.
        $rawReq = $m[2];
        $req = strpos($rawReq, '\\') !== false ? stripcslashes($rawReq) : $rawReq;
        if ($rawReq !== '' && $rawReq !== '-') {
            // Сирий URI (як у логу) — для класифікації «як у звіті», що рахувала саме його.
            $rawParts = explode(' ', $rawReq, 3);
            $out['rawUri'] = count($rawParts) >= 2 ? $rawParts[1] : $rawParts[0];
        }
        if ($req !== '' && $req !== '-') {
            $parts = explode(' ', $req, 3);
            if (count($parts) >= 2) {
                $out['method'] = strtoupper(substr($parts[0], 0, 10));
                $out['uri'] = $parts[1];
            } else {
                $out['uri'] = $parts[0];
            }
        }
        $out['path'] = self::pathOf($out['uri']);
        $out['status'] = $m[3] === '-' ? 0 : (int) $m[3];
        $out['bytes'] = $m[4] === '-' ? 0 : (int) $m[4];
        $out['referer'] = isset($m[5]) && $m[5] !== '-' ? stripcslashes($m[5]) : '';
        $out['ua'] = isset($m[6]) && $m[6] !== '-' ? stripcslashes($m[6]) : '';
        $out['partial'] = false;

        return $out;
    }

    /** Шлях без query і без схеми/хоста (у логах бувають абсолютні URI проксі-запитів). */
    public static function pathOf(string $uri): string
    {
        if ($uri === '') {
            return '';
        }
        if (stripos($uri, 'http://') === 0 || stripos($uri, 'https://') === 0) {
            $slash = strpos($uri, '/', strpos($uri, '//') + 2);
            $uri = $slash === false ? '/' : substr($uri, $slash);
        }
        $q = strpos($uri, '?');

        return $q === false ? $uri : substr($uri, 0, $q);
    }

    /** Uri для показу в топах: без схеми/хоста, обрізаний. */
    public static function displayUri(string $uri, int $max = 150): string
    {
        if (stripos($uri, 'http://') === 0 || stripos($uri, 'https://') === 0) {
            $slash = strpos($uri, '/', strpos($uri, '//') + 2);
            $uri = $slash === false ? '/' : substr($uri, $slash);
        }
        if (strlen($uri) > $max) {
            $uri = substr($uri, 0, $max);
        }
        // Битий UTF-8 зламав би json_encode усього breakdown.
        if (!preg_match('//u', $uri)) {
            $uri = mb_convert_encoding($uri, 'UTF-8', 'UTF-8');
        }

        return $uri;
    }

    private static function hourStart(string $s): ?int
    {
        // 31/Oct/2026:22:18:03 +0200
        if (!preg_match('#^(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):\d{2}:\d{2} ([+-])(\d{2})(\d{2})$#', $s, $m)) {
            return null;
        }
        $mon = self::MONTHS[$m[2]] ?? null;
        // gmmktime мовчки «нормалізує» 31/Feb у 3/Mar — такі дати відкидаємо.
        if ($mon === null || !checkdate($mon, (int) $m[1], (int) $m[3]) || (int) $m[4] > 23 || (int) $m[6] > 14 || (int) $m[7] > 59) {
            return null;
        }
        $offset = ((int) $m[6] * 3600 + (int) $m[7] * 60) * ($m[5] === '-' ? -1 : 1);

        return gmmktime((int) $m[4], 0, 0, $mon, (int) $m[1], (int) $m[3]) - $offset;
    }
}
