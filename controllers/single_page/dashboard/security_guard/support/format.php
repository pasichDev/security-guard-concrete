<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support;

use Throwable;

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * Форматування для шаблонів. Усі методи повертають ТЕКСТ (не HTML) —
 * у шаблоні його однаково треба пропустити через h().
 */
final class Format
{
    public static function num($n): string
    {
        $n = (int) $n;
        try {
            if (class_exists('\Punic\Number')) {
                return \Punic\Number::format($n);
            }
        } catch (Throwable $e) {
        }

        return number_format($n, 0, ',', "\u{00A0}");
    }

    public static function bytes($n): string
    {
        $n = (float) $n;
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $i = 0;
        while ($n >= 1024 && $i < count($units) - 1) {
            $n /= 1024;
            ++$i;
        }

        return ($i === 0 ? (string) (int) $n : number_format($n, $n >= 100 ? 0 : 1, ',', "\u{00A0}")) . "\u{00A0}" . $units[$i];
    }

    public static function dateTime($ts): string
    {
        $ts = (int) $ts;
        if ($ts <= 0) {
            return '—';
        }
        try {
            if (function_exists('app')) {
                return (string) app('date')->formatDateTime($ts, false, false);
            }
        } catch (Throwable $e) {
        }

        return date('d.m.Y H:i', $ts);
    }

    /** 'YYYY-MM-DD' → 'DD.MM.YYYY'. */
    public static function day(string $ymd): string
    {
        return preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $ymd, $m) ? $m[3] . '.' . $m[2] . '.' . $m[1] : $ymd;
    }

    /** Відносний час «5 хв тому» / «через 2 год». */
    public static function relative($ts, ?int $now = null): string
    {
        $ts = (int) $ts;
        if ($ts <= 0) {
            return '';
        }
        $now = $now ?? time();
        $diff = abs($now - $ts);
        if ($diff < 60) {
            $s = t('%d s', $diff);
        } elseif ($diff < 3600) {
            $s = t('%d min', intdiv($diff, 60));
        } elseif ($diff < 86400) {
            $s = t('%d h', intdiv($diff, 3600));
        } else {
            $s = t('%d d', intdiv($diff, 86400));
        }

        return $ts <= $now ? t('%s ago', $s) : t('in %s', $s);
    }

    public static function duration(int $seconds): string
    {
        if ($seconds <= 0) {
            return t('Permanent');
        }
        if ($seconds % 86400 === 0) {
            return t('%d d', intdiv($seconds, 86400));
        }
        if ($seconds % 3600 === 0) {
            return t('%d h', intdiv($seconds, 3600));
        }
        if ($seconds % 60 === 0) {
            return t('%d min', intdiv($seconds, 60));
        }

        return t('%d s', $seconds);
    }

    public static function truncate($s, int $len = 80): string
    {
        $s = mb_scrub((string) $s, 'UTF-8');
        // Керівні символи з чужих URL/UA не мають потрапити в розмітку.
        $s = preg_replace('/[\x00-\x1F\x7F]/u', ' ', $s) ?? '';
        if (mb_strlen($s) <= $len) {
            return $s;
        }

        return mb_substr($s, 0, $len - 1) . '…';
    }

    /** Прапор країни з ISO-коду (регіональні індикатори Unicode). */
    public static function flag($cc): string
    {
        $cc = strtoupper(trim((string) $cc));
        if (!preg_match('/^[A-Z]{2}$/', $cc) || in_array($cc, ['XX', 'ZZ', 'EU', 'AP'], true)) {
            return '';
        }

        return mb_chr(0x1F1E6 + ord($cc[0]) - 65) . mb_chr(0x1F1E6 + ord($cc[1]) - 65);
    }

    public static function categoryLabel($cat): string
    {
        $cat = (string) $cat;
        $map = self::categoryLabels();

        return $map[$cat] ?? ($cat === '' ? t('Other') : $cat);
    }

    /** @return array<string,string> */
    public static function categoryLabels(): array
    {
        return [
            'wordpress' => t('WordPress probing'),
            'joomla' => t('Joomla exploits'),
            'secrets' => t('Sensitive files'),
            'shells' => t('Web shells'),
            'injection' => t('SQL / code injection'),
            'xss' => t('XSS'),
            'traversal' => t('Path traversal'),
            'scanner' => t('Scanners'),
            'ai_crawler' => t('AI crawlers'),
            'honeypot' => t('Honeypot'),
            'bruteforce' => t('Password guessing'),
            'ratelimit' => t('Rate limit'),
            'php_probe' => t('PHP probing'),
            'behavior' => t('Suspicious behaviour'),
            'ddos' => t('Traffic spike'),
            'geo' => t('Geo block'),
            'fake_bot' => t('Fake search bot'),
            'blocked_ip' => t('Blocked IP'),
            'manual' => t('Manual block'),
            'concrete' => t('Concrete CMS internals'),
            'other' => t('Other'),
            'unclassified' => t('Unclassified'),
        ];
    }

    /** @return array<string,string> */
    public static function actionLabels(): array
    {
        return [
            'logged' => t('Logged'),
            'blocked' => t('Blocked'),
            'banned' => t('Banned'),
            'denied' => t('Denied (banned IP)'),
        ];
    }

    public static function actionLabel($a): string
    {
        $map = self::actionLabels();

        return $map[(string) $a] ?? (string) $a;
    }

    public static function actionBadge($a): string
    {
        switch ((string) $a) {
            case 'banned':
                return 'text-bg-danger';
            case 'blocked':
            case 'denied':
                return 'text-bg-warning';
            default:
                return 'text-bg-secondary';
        }
    }

    public static function severityBadge($s): string
    {
        switch ((string) $s) {
            case 'critical':
                return 'text-bg-danger';
            case 'warning':
                return 'text-bg-warning';
            default:
                return 'text-bg-info';
        }
    }

    public static function severityLabel($s): string
    {
        $map = ['critical' => t('Critical'), 'warning' => t('Warning'), 'info' => t('Info')];

        return $map[(string) $s] ?? (string) $s;
    }

    /**
     * Приводить різні форми «топів» до [[ключ, число], ...]:
     * {"a": 5}, [["a", 5]], [{"ip": "a", "count": 5}], [{"url": "a", "hits": 5}].
     *
     * @return array<int, array{0: string, 1: int, 2: array}>
     */
    public static function pairs($data, int $limit = 10): array
    {
        $out = [];
        if (!is_array($data)) {
            return $out;
        }
        foreach ($data as $k => $v) {
            if (is_array($v)) {
                $vals = array_values($v);
                $isList = array_keys($v) === range(0, count($v) - 1);
                if ($isList && count($vals) >= 2) {
                    $out[] = [(string) $vals[0], (int) $vals[1], []];
                    continue;
                }
                $key = $v['ip'] ?? $v['url'] ?? $v['key'] ?? $v['name'] ?? $v['code'] ?? $v['country'] ?? (is_string($k) ? $k : '');
                $num = $v['count'] ?? $v['hits'] ?? $v['n'] ?? $v['requests'] ?? $v['value'] ?? 0;
                $out[] = [(string) $key, (int) $num, $v];
            } elseif (is_numeric($v)) {
                $out[] = [(string) $k, (int) $v, []];
            }
        }
        usort($out, static function ($a, $b) {
            return $b[1] <=> $a[1];
        });

        return array_slice($out, 0, $limit);
    }
}
