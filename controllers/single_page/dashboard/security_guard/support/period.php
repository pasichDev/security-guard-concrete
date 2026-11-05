<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support;

use DateTimeImmutable;
use DateTimeZone;
use Throwable;

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * Період звіту в часовому поясі сайту. Межі днів рахуються в тому ж поясі,
 * що й SecurityGuardDailyStats.day, — інакше графіки WAF і логів хостингу
 * розійдуться на день.
 */
final class Period
{
    public const PRESETS = ['7', '30', '90'];
    public const MAX_DAYS = 366;

    /** @var string */
    public $key;
    /** @var string */
    public $fromDay;
    /** @var string */
    public $toDay;
    /** @var int */
    public $fromTs;
    /** @var int кінець, не включно */
    public $toTs;
    /** @var DateTimeZone */
    public $tz;
    /** @var string повідомлення, якщо введений період довелося виправити */
    public $notice = '';

    private function __construct()
    {
    }

    public static function timezone(): DateTimeZone
    {
        try {
            if (function_exists('app')) {
                $tz = app('date')->getTimezone('app');
                if ($tz instanceof DateTimeZone) {
                    return $tz;
                }
            }
        } catch (Throwable $e) {
        }

        return new DateTimeZone(date_default_timezone_get());
    }

    public static function fromInput(string $key, string $from = '', string $to = '', ?int $now = null): self
    {
        $tz = self::timezone();
        $today = (new DateTimeImmutable('@' . ($now ?? time())))->setTimezone($tz)->setTime(0, 0);
        $p = new self();
        $p->tz = $tz;

        $start = null;
        $end = null;
        if ($key === 'custom') {
            $start = self::parseDay($from, $tz);
            $end = self::parseDay($to, $tz);
            if ($start === null || $end === null) {
                $key = '30';
            } else {
                if ($end < $start) {
                    [$start, $end] = [$end, $start];
                }
                if ($end > $today) {
                    $end = $today;
                    $p->notice = t('The selected period ends in the future; data is shown up to today.');
                }
                if ($start > $today) {
                    $start = $today;
                    $p->notice = t('The selected period is entirely in the future; showing today instead.');
                }
                $maxStart = $end->modify('-' . (self::MAX_DAYS - 1) . ' days');
                if ($start < $maxStart) {
                    $start = $maxStart;
                }
            }
        }
        if ($key !== 'custom') {
            if (!in_array($key, self::PRESETS, true)) {
                $key = '30';
            }
            $end = $today;
            $start = $today->modify('-' . ((int) $key - 1) . ' days');
        }
        $p->key = $key;
        $p->fromDay = $start->format('Y-m-d');
        $p->toDay = $end->format('Y-m-d');
        $p->fromTs = $start->getTimestamp();
        $p->toTs = $end->modify('+1 day')->getTimestamp();

        return $p;
    }

    /** Останні N днів, включно з сьогоднішнім. */
    public static function lastDays(int $days, ?int $now = null): self
    {
        $tz = self::timezone();
        $today = (new DateTimeImmutable('@' . ($now ?? time())))->setTimezone($tz)->setTime(0, 0);
        $start = $today->modify('-' . max(0, $days - 1) . ' days');

        return self::fromInput('custom', $start->format('Y-m-d'), $today->format('Y-m-d'), $now);
    }

    private static function parseDay(string $s, DateTimeZone $tz): ?DateTimeImmutable
    {
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $s)) {
            return null;
        }
        $d = DateTimeImmutable::createFromFormat('!Y-m-d', $s, $tz);

        return $d && $d->format('Y-m-d') === $s ? $d : null;
    }

    /** @return string[] усі дні періоду Y-m-d */
    public function days(): array
    {
        $out = [];
        $d = DateTimeImmutable::createFromFormat('!Y-m-d', $this->fromDay, $this->tz);
        $end = $this->toDay;
        $guard = 0;
        while ($d && $d->format('Y-m-d') <= $end && $guard++ < self::MAX_DAYS + 1) {
            $out[] = $d->format('Y-m-d');
            $d = $d->modify('+1 day');
        }

        return $out;
    }

    public function dayCount(): int
    {
        return count($this->days());
    }

    /** Параметри для посилань (зберегти фільтр). */
    public function query(): array
    {
        return $this->key === 'custom'
            ? ['period' => 'custom', 'from' => $this->fromDay, 'to' => $this->toDay]
            : ['period' => $this->key];
    }
}
