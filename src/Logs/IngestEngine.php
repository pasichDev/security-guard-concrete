<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/**
 * Інкрементальний розбір логів. Чистий PHP: сховища передаються інтерфейсами.
 *
 * Прохід A (дешевий): для кожного файлу за курсором читаються лише нові рядки,
 * з них — тільки час; збирається множина «торкнутих» днів. Дні спершу
 * додаються до черги (PendingDaysStore), лише потім зсуваються курсори — тож
 * обрив між ними не губить днів.
 *
 * Прохід B: кожен день із черги перераховується ПОВНІСТЮ з усіх рядків усіх
 * джерел, які його містять, і рядок дня перезаписується. Тому повторний
 * запуск і ротація (рядки переїхали з живого логу в архів) не дають подвійного
 * рахунку: на момент перерахунку рядок або в одному файлі, або в двох файлах
 * одного потоку з перекриттям часу — тоді враховується максимум входжень
 * однакового рядка серед цих файлів (а не сума).
 */
final class IngestEngine
{
    /** Скільки днів перераховувати за один прохід по файлах (обмежує пам'ять). */
    public const GROUP_DAYS = 7;
    private const CHECK_EVERY = 2000;
    /** Ліміт записів у пам'яті дедуплікації перекриттів за одну групу днів. */
    public const SEEN_MAX = 300000;

    /** @var DateTimeZone */
    private $tz;
    /** @var callable(): AttackClassifierInterface */
    private $classifierFactory;
    /** @var IpMatcher */
    private $exclude;
    /** @var CursorStoreInterface */
    private $cursors;
    /** @var PendingDaysStoreInterface */
    private $pending;
    /** @var DayWriterInterface */
    private $writer;
    /** @var DayAggregator лише для перетворення часу в день */
    private $clock;
    /** @var CrawlerVerifier */
    private $crawlers;
    /** @var HostWafStateStoreInterface|null */
    private $hostWafState;
    /** @var int[] розміри сторінки 403 хостингу для поточного запуску */
    private $hostWafSizes = [];
    /** @var array стан детектора, якщо сховища немає (тести) */
    private $memoryHostWafState = [];
    /** @var DayIndexStoreInterface|null */
    private $indexStore;
    /** @var array покажчик днів у файлах (див. DayIndexStoreInterface) */
    private $index = [];
    /** @var float */
    private $deadline = INF;
    /** @var callable(): float годинник для лімітів часу (у тестах підмінюється) */
    private $clockFn;
    /** @var int як часто перевіряти час, рядків */
    private $checkEvery = self::CHECK_EVERY;
    /** @var int ліміт ключів дедуплікації (у тестах менший) */
    private $seenMax = self::SEEN_MAX;

    public function __construct(
        DateTimeZone $tz,
        callable $classifierFactory,
        IpMatcher $exclude,
        CursorStoreInterface $cursors,
        PendingDaysStoreInterface $pending,
        DayWriterInterface $writer,
        ?CrawlerVerifier $crawlers = null,
        ?HostWafStateStoreInterface $hostWafState = null,
        ?DayIndexStoreInterface $indexStore = null
    ) {
        $this->indexStore = $indexStore;
        $this->clockFn = static function (): float {
            return microtime(true);
        };
        $this->hostWafState = $hostWafState;
        $this->crawlers = $crawlers ?? new CrawlerVerifier();
        $this->tz = $tz;
        $this->classifierFactory = $classifierFactory;
        $this->exclude = $exclude;
        $this->cursors = $cursors;
        $this->pending = $pending;
        $this->writer = $writer;
        $this->clock = new DayAggregator($tz, new ReportClassifier());
    }

    /**
     * @param array<string, array{size:int, mtime:int, stream:string}> $sources SourceLocator::discover()
     * @param array{rebuild?:bool, days?:int, timeBudget?:int, now?:int, deadlineAt?:float, hostWafDetect?:bool, hostWafSizes?:string} $options
     *   hostWafSizes — розміри з налаштування (порожнє = автовизначення HostWafDetector)
     * @return array{files:int, lines:int, days:string[], finished:bool, errors:string[], pending:int, deduplicated:int, malformed:int, hostWafSizes:int[]}
     */
    public function run(array $sources, array $options = []): array
    {
        $started = microtime(true);
        $budget = max(0, (int) ($options['timeBudget'] ?? 0));
        $deadline = $budget > 0 ? $started + $budget : INF;
        if (isset($options['deadlineAt'])) {
            $deadline = (float) $options['deadlineAt'];
        }
        $this->deadline = $deadline;
        $this->clockFn = isset($options['clock']) && is_callable($options['clock']) ? $options['clock'] : static function (): float {
            return microtime(true);
        };
        $this->checkEvery = max(1, (int) ($options['checkEvery'] ?? self::CHECK_EVERY));
        $this->seenMax = max(1, (int) ($options['seenMax'] ?? self::SEEN_MAX));
        $clock = $this->clockFn;
        $now = (int) ($options['now'] ?? time());
        $rebuild = !empty($options['rebuild']);
        $minDay = '';
        if (!empty($options['days']) && (int) $options['days'] > 0) {
            $minDay = (new DateTimeImmutable('@' . $now))->setTimezone($this->tz)
                ->modify('-' . ((int) $options['days'] - 1) . ' days')->format('Y-m-d');
        }

        $result = ['files' => 0, 'lines' => 0, 'days' => [], 'finished' => false, 'errors' => [], 'pending' => 0, 'deduplicated' => 0, 'malformed' => 0, 'hostWafSizes' => [], 'scanned' => 0, 'dedupOverflow' => false];
        $stored = $this->cursors->load();
        $pending = $rebuild ? [] : array_fill_keys($this->pending->get(), true);

        $hwDetect = !array_key_exists('hostWafDetect', $options) || !empty($options['hostWafDetect']);
        $hwExplicit = HostWafDetector::parseSizes((string) ($options['hostWafSizes'] ?? ''));
        $hwAuto = $hwDetect && !$hwExplicit;
        $hwPrevState = $rebuild ? [] : $this->loadHostWafState();
        $detector = new HostWafDetector($hwPrevState);
        $hwBefore = $detector->confirmed();
        $oldIndex = $rebuild ? [] : ($this->indexStore !== null ? $this->indexStore->getDayIndex() : $this->index);
        $index = [];

        // ---- Прохід A
        $states = [];
        $newDays = [];
        $cut = false;
        $cutB = false;
        foreach ($sources as $path => $meta) {
            ++$result['files'];
            $size = (int) $meta['size'];
            $cur = $stored[$path] ?? null;
            [$hash, $min, $max] = self::decodeFingerprint($cur['fingerprint'] ?? '');
            if ($cut) {
                // Час вичерпано: файл не чіпаємо, курсор лишаємо як був.
                if ($cur !== null) {
                    $states[$path] = $cur + ['stream' => $meta['stream']];
                }
                continue;
            }
            $first = LogReader::firstLine($path);
            $hashNow = $first === '' ? '' : sha1($first);
            if ($hashNow === '') {
                $states[$path] = self::cursorRow($path, '', 0, 0, $size, 0, true, $now) + ['stream' => $meta['stream']];
                $index[$path] = ['from0' => true, 'days' => []];
                continue;
            }
            $reset = $rebuild || $cur === null || $hash !== $hashNow || $size < (int) $cur['size'];
            if (!$reset && $size === (int) $cur['size'] && !empty($cur['completed'])) {
                $states[$path] = self::cursorRow($path, $hash, $min, $max, $size, (int) $cur['position'], true, $now) + ['stream' => $meta['stream']];
                if (isset($oldIndex[$path])) {
                    $index[$path] = $oldIndex[$path];
                }
                continue;
            }
            $start = $reset ? 0 : (int) $cur['position'];
            if ($reset) {
                $min = 0;
                $max = 0;
            }
            // Покажчик продовжується лише якщо він будувався з початку файлу.
            $fileIdx = $reset ? ['from0' => true, 'days' => []] : ($oldIndex[$path] ?? ['from0' => false, 'days' => []]);
            $completed = true;
            $position = $start;
            try {
                $reader = new LogReader($path);
                if ($start > 0 && !$reader->seek($start)) {
                    $reader->seek(0);
                    $min = 0;
                    $max = 0;
                    $fileIdx = ['from0' => true, 'days' => []];
                }
                $n = 0;
                $off = $reader->tell();
                while (($line = $reader->next()) !== null) {
                    $end = $reader->tell();
                    $ts = LogParser::timestamp($line);
                    if ($ts === null) {
                        ++$result['malformed'];
                    } else {
                        ++$result['lines'];
                        $lineDay = $this->clock->dayOf($ts);
                        $newDays[$lineDay] = true;
                        self::indexLine($fileIdx, $lineDay, $off, $end);
                        if ($hwAuto) {
                            $detector->observeLine($line);
                        }
                        if ($min === 0 || $ts < $min) {
                            $min = $ts;
                        }
                        if ($ts > $max) {
                            $max = $ts;
                        }
                    }
                    $off = $end;
                    if (++$n % $this->checkEvery === 0 && $clock() > $deadline) {
                        $completed = false;
                        $cut = true;
                        break;
                    }
                }
                $position = $reader->tell();
                $reader->close();
            } catch (Throwable $e) {
                $result['errors'][] = $path . ': ' . $e->getMessage();
                $completed = false;
            }
            $states[$path] = self::cursorRow($path, $hashNow, $min, $max, $size, $position, $completed, $now) + ['stream' => $meta['stream']];
            $index[$path] = $fileIdx;
        }
        // Файли, не відвідані через обрив, зберігають старий покажчик.
        foreach ($states as $path => $_) {
            if (!isset($index[$path]) && isset($oldIndex[$path])) {
                $index[$path] = $oldIndex[$path];
            }
        }
        $this->index = $index;

        if ($hwAuto && !$rebuild && $detector->confirmed() !== $hwBefore) {
            // Знайдено новий відбиток сторінки 403 хостингу: дні, пораховані раніше
            // без нього, застаріли — перераховуємо всі дні наявних файлів.
            foreach ($states as $st) {
                [, $fmin, $fmax] = self::decodeFingerprint($st['fingerprint']);
                if ($fmin > 0 && $fmax >= $fmin) {
                    for ($t = $fmin; $t <= $fmax + 86400; $t += 86400) {
                        $newDays[$this->clock->dayOf(min($t, $fmax))] = true;
                    }
                }
            }
        }
        // Дні з нових рядків ставляться в чергу завжди — навіть поза --days: курсори вже
        // пройшли ці рядки, і без черги дні лишились би непорахованими назавжди.
        foreach (array_keys($newDays) as $day) {
            $pending[(string) $day] = true;
        }
        $this->pending->set(self::sortedDays($pending));
        $this->saveIndex();
        if ($hwAuto) {
            $this->saveHostWafState($detector->state());
        }
        $this->hostWafSizes = !$hwDetect ? [] : ($hwExplicit ?: $detector->confirmed());
        $result['hostWafSizes'] = $this->hostWafSizes;
        $this->cursors->save(array_map(static function (array $r): array {
            unset($r['stream']);

            return $r;
        }, $states));

        // ---- Прохід B (з --days — лише дні вікна; старіші лишаються в черзі)
        $queue = array_values(array_filter(self::sortedDays($pending), static function (string $d) use ($minDay): bool {
            return $minDay === '' || strcmp($d, $minDay) >= 0;
        }));
        // З лімітом часу — по одному дню: обірваний день не пишеться, а лише повторюється.
        $groupDays = is_finite($deadline) ? 1 : self::GROUP_DAYS;
        $ranges = [];
        foreach ($states as $path => $st) {
            [, $min, $max] = self::decodeFingerprint($st['fingerprint']);
            if ($min === 0 && $max === 0 && $st['fingerprint'] === '') {
                continue; // порожній файл
            }
            $ranges[$path] = [
                'min' => $min > 0 ? $min : 0,
                'max' => !empty($st['completed']) && $max > 0 ? $max : PHP_INT_MAX,
                'stream' => $st['stream'],
            ];
        }

        // Якщо прохід A обірвано, частина файлів не має відомого діапазону —
        // перерахунок відкладаємо до запуску, який дочитає всі файли.
        while ($queue && !$cut) {
            if ($clock() > $deadline) {
                break;
            }
            $group = array_splice($queue, 0, $groupDays);
            try {
                $rows = $this->computeDays($group, $ranges, $result);
            } catch (DeadlineException $e) {
                $cutB = true;
                break;
            } catch (Throwable $e) {
                $result['errors'][] = $e->getMessage();
                break;
            } finally {
                $this->saveIndex();
            }
            foreach ($group as $day) {
                if (isset($rows[$day])) {
                    $this->writer->saveDay($day, $rows[$day]);
                    $result['days'][] = $day;
                }
                unset($pending[$day]);
            }
            $this->pending->set(self::sortedDays($pending));
        }

        $result['pending'] = count($pending);
        $windowLeft = array_filter(array_keys($pending), static function ($d) use ($minDay): bool {
            return $minDay === '' || strcmp((string) $d, $minDay) >= 0;
        });
        $result['finished'] = !$cut && !$cutB && !$windowLeft && !$result['errors'];

        return $result;
    }

    /**
     * Повний перерахунок набору днів з усіх файлів, що їх покривають (без запису).
     * @param string[] $days
     * @param array<string, array{min:int, max:int, stream:string}> $ranges
     * @return array<string, array>
     */
    public function computeDays(array $days, array $ranges, array &$stats = []): array
    {
        if (!$days) {
            return [];
        }
        sort($days);
        $from = $this->localMidnight($days[0]);
        $to = $this->localMidnight($days[count($days) - 1], 1);
        $agg = new DayAggregator($this->tz, ($this->classifierFactory)(), $this->exclude, $days, $this->crawlers);
        $agg->setHostWafSizes($this->hostWafSizes);

        $files = [];
        foreach ($ranges as $path => $r) {
            if ($r['max'] >= $from && $r['min'] < $to) {
                $files[$path] = $r;
            }
        }
        // Вікна перекриття з іншими файлами того самого потоку.
        $windows = [];
        foreach ($files as $a => $ra) {
            foreach ($files as $b => $rb) {
                if ($a === $b || $ra['stream'] !== $rb['stream']) {
                    continue;
                }
                $lo = max($ra['min'], $rb['min'], $from);
                $hi = min($ra['max'], $rb['max'], $to);
                if ($lo <= $hi) {
                    $windows[$a][] = [$lo, $hi];
                }
            }
        }

        $seen = [];
        $seenFull = false;
        $fi = 0;
        $n = 0;
        foreach ($files as $path => $r) {
            ++$fi;
            $win = $windows[$path] ?? [];
            $idx = $this->index[$path] ?? null;
            $useIdx = is_array($idx) && !empty($idx['from0']) && $r['max'] !== PHP_INT_MAX;
            $readFrom = 0;
            $readTo = PHP_INT_MAX;
            if ($useIdx) {
                $lo = PHP_INT_MAX;
                $hi = 0;
                foreach ($days as $d) {
                    if (isset($idx['days'][$d])) {
                        $lo = min($lo, (int) $idx['days'][$d][0]);
                        $hi = max($hi, (int) $idx['days'][$d][1]);
                    }
                }
                if ($lo === PHP_INT_MAX) {
                    continue; // у файлі немає рядків цих днів
                }
                $readFrom = $lo;
                $readTo = $hi;
            }
            // Повне читання файлу без покажчика — заодно будуємо покажчик.
            $build = !$useIdx && $r['max'] !== PHP_INT_MAX ? ['from0' => true, 'days' => []] : null;
            $reader = new LogReader($path);
            if ($readFrom > 0) {
                $reader->seek($readFrom);
            }
            $off = $reader->tell();
            $line = '';
            while ($off < $readTo && ($line = $reader->next()) !== null) {
                $end = $reader->tell();
                if (++$n % $this->checkEvery === 0 && ($this->clockFn)() > $this->deadline) {
                    $reader->close();
                    throw new DeadlineException('Time budget exhausted');
                }
                $stats['scanned'] = ($stats['scanned'] ?? 0) + 1;
                $ts = LogParser::timestamp($line);
                if ($ts !== null && $build !== null) {
                    self::indexLine($build, $this->clock->dayOf($ts), $off, $end);
                }
                $off = $end;
                if ($ts === null || $ts < $from - 86400 || $ts > $to + 86400 || !$agg->wants($ts)) {
                    continue;
                }
                $parsed = LogParser::parse($line);
                if ($parsed === null) {
                    continue;
                }
                if ($win && !$seenFull && self::inWindows($ts, $win)) {
                    // Той самий запит у двох файлах одного потоку (живий лог і архів, або
                    // Apache- і nginx-архів з різним форматом рядка) — ключ з полів, а не з рядка.
                    $key = md5($r['stream'] . "\0" . $ts . "\0" . $parsed['ip'] . "\0" . $parsed['method'] . "\0" . $parsed['rawUri'], true);
                    $counts = $seen[$key] ?? [];
                    $c = ($counts[$fi] ?? 0) + 1;
                    $counts[$fi] = $c;
                    $seen[$key] = $counts;
                    unset($counts[$fi]);
                    if (count($seen) >= $this->seenMax) {
                        $seenFull = true;
                        $stats['dedupOverflow'] = true;
                    }
                    if ($counts && $c <= max($counts)) {
                        $stats['deduplicated'] = ($stats['deduplicated'] ?? 0) + 1;
                        $agg->addReportOnly($parsed);
                        continue;
                    }
                }
                $agg->add($parsed);
            }
            $reader->close();
            if ($build !== null && $line === null) {
                $this->index[$path] = $build;
            }
        }

        return $agg->finish();
    }

    /** Позначає в покажчику файлу, що рядок дня $day займає байти [$start, $end). */
    private static function indexLine(array &$fileIdx, string $day, int $start, int $end): void
    {
        if (!isset($fileIdx['days'][$day])) {
            $fileIdx['days'][$day] = [$start, $end];

            return;
        }
        if ($start < $fileIdx['days'][$day][0]) {
            $fileIdx['days'][$day][0] = $start;
        }
        if ($end > $fileIdx['days'][$day][1]) {
            $fileIdx['days'][$day][1] = $end;
        }
    }

    private function saveIndex(): void
    {
        if ($this->indexStore !== null) {
            $this->indexStore->setDayIndex($this->index);
        }
    }

    /** Розміри сторінки 403 хостингу, з якими рахує computeDays() (для прямого виклику). */
    public function setHostWafSizes(array $sizes): void
    {
        $this->hostWafSizes = array_values(array_map('intval', $sizes));
    }

    private function loadHostWafState(): array
    {
        return $this->hostWafState !== null ? $this->hostWafState->getHostWafState() : $this->memoryHostWafState;
    }

    private function saveHostWafState(array $state): void
    {
        if ($this->hostWafState !== null) {
            $this->hostWafState->setHostWafState($state);
        } else {
            $this->memoryHostWafState = $state;
        }
    }

    public function localMidnight(string $day, int $plusDays = 0): int
    {
        $dt = new DateTimeImmutable($day . ' 00:00:00', $this->tz);
        if ($plusDays) {
            $dt = $dt->modify('+' . $plusDays . ' day');
        }

        return $dt->getTimestamp();
    }

    /** Відбиток: sha1 першого рядка + діапазон часу рядків файлу (вміщується в 64 символи). */
    public static function encodeFingerprint(string $hash, int $min, int $max): string
    {
        return $hash === '' ? '' : $hash . ':' . $min . ':' . $max;
    }

    /** @return array{0:string, 1:int, 2:int} */
    public static function decodeFingerprint(string $fp): array
    {
        $p = explode(':', $fp);

        return [$p[0], isset($p[1]) ? (int) $p[1] : 0, isset($p[2]) ? (int) $p[2] : 0];
    }

    private static function cursorRow(string $path, string $hash, int $min, int $max, int $size, int $position, bool $completed, int $now): array
    {
        return [
            'path' => $path,
            'fingerprint' => self::encodeFingerprint($hash, $min, $max),
            'size' => $size,
            'position' => $position,
            'completed' => $completed,
            'updatedAt' => $now,
        ];
    }

    private static function inWindows(int $ts, array $windows): bool
    {
        foreach ($windows as [$lo, $hi]) {
            if ($ts >= $lo && $ts <= $hi) {
                return true;
            }
        }

        return false;
    }

    /** @param array<string, true> $set */
    private static function sortedDays(array $set): array
    {
        $d = array_map('strval', array_keys($set));
        sort($d);

        return $d;
    }
}
