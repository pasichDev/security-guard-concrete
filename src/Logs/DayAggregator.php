<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

use DateTimeImmutable;
use DateTimeZone;

/**
 * Збирає розібрані рядки логу в агрегати по днях (часовий пояс сайту).
 * Чистий PHP. Результат — рядки таблиці SecurityGuardDailyStats.
 *
 * Пам'ять обмежена: на день тримаються лише множини IP і лічильники URL
 * (останні періодично обрізаються до найчастіших).
 */
final class DayAggregator
{
    public const TOP_N = 20;
    public const ATTACK_IP_LIST_MAX = 1000;
    /** Понад стільки різних IP за день точні мапи IP більше не ростуть — далі лише HLL. */
    public const IP_MAP_MAX = 50000;
    private const URL_MAP_MAX = 5000;
    private const BREAKDOWN_MAX_BYTES = 60000;

    private const LOGIN_RE = '#^(?:/index\.php)?/login/authenticate(?:/|$)#i';
    private const BOT_RE = '/bot\b|bot\/|crawl|spider|slurp|facebookexternalhit|ia_archiver|externalagent|-user\/\d/i';
    private const BOT_NAME_RE = '/([A-Za-z][\w.-]*?(?:bot|spider|crawler|externalagent|-user))\b/i';

    /** @var DateTimeZone */
    private $tz;
    /** @var AttackClassifierInterface */
    private $classifier;
    /** @var ReportClassifier */
    private $report;
    /** @var IpMatcher */
    private $exclude;
    /** @var array<string, true>|null дні, які рахувати (null — усі) */
    private $onlyDays;
    /** @var array<int, array{0:string, 1:int}> */
    private $bucketCache = [];
    /** @var array<string, array> */
    private $days = [];
    /** @var CrawlerVerifier */
    private $crawlers;
    /** @var array<int, true> розміри сторінки 403 сервера хостингу */
    private $hostWafSizes = [];

    /** @param string[]|null $onlyDays */
    public function __construct(DateTimeZone $tz, AttackClassifierInterface $classifier, ?IpMatcher $exclude = null, ?array $onlyDays = null, ?CrawlerVerifier $crawlers = null)
    {
        $this->crawlers = $crawlers ?? new CrawlerVerifier();
        $this->tz = $tz;
        $this->classifier = $classifier;
        $this->report = new ReportClassifier();
        $this->exclude = $exclude ?? new IpMatcher('');
        $this->onlyDays = $onlyDays === null ? null : array_fill_keys($onlyDays, true);
    }

    /** Розміри відповіді, за якими 403 вважається відмовою сервера хостингу (HostWafDetector). */
    public function setHostWafSizes(array $sizes): void
    {
        $this->hostWafSizes = [];
        foreach ($sizes as $s) {
            $this->hostWafSizes[(int) $s] = true;
        }
    }

    /** День і година (у часовому поясі сайту) для unix-часу. */
    public function dayHour(int $ts): array
    {
        $b = intdiv($ts, 900);
        if (!isset($this->bucketCache[$b])) {
            if (count($this->bucketCache) > 20000) {
                $this->bucketCache = [];
            }
            $dt = (new DateTimeImmutable('@' . ($b * 900)))->setTimezone($this->tz);
            $this->bucketCache[$b] = [$dt->format('Y-m-d'), (int) $dt->format('G')];
        }

        return $this->bucketCache[$b];
    }

    public function dayOf(int $ts): string
    {
        return $this->dayHour($ts)[0];
    }

    /** Чи потрібен рядок із цим часом (дешева перевірка до повного розбору). */
    public function wants(int $ts): bool
    {
        return $this->onlyDays === null || isset($this->onlyDays[$this->dayHour($ts)[0]]);
    }

    /** Позначити день як «бачений у джерелах», навіть якщо всі його рядки виключені. */
    public function touch(string $day): void
    {
        if (!isset($this->days[$day])) {
            $this->days[$day] = self::emptyDay();
        }
    }

    /** @param array $r результат LogParser::parse() */
    public function add(array $r): void
    {
        [$day, $hour] = $this->dayHour($r['ts']);
        if ($this->onlyDays !== null && !isset($this->onlyDays[$day])) {
            return;
        }
        if (!isset($this->days[$day])) {
            $this->days[$day] = self::emptyDay();
        }
        $d = &$this->days[$day];
        $ip = $r['ip'];
        if ($this->exclude->matches($ip)) {
            ++$d['excluded'];
            unset($d);

            return;
        }

        ++$d['total'];
        self::countIp($d, 'ips', 'ipSk', $ip);
        ++$d['hours'][$hour];
        $d['bytes'] += $r['bytes'];
        if ($r['partial']) {
            ++$d['partial'];
        }
        $status = $r['status'];
        $d['statuses'][$status] = ($d['statuses'][$status] ?? 0) + 1;
        if ($status === 403) {
            ++$d['blocked403'];
        } elseif ($status === 404) {
            ++$d['errors404'];
        } elseif ($status === 508) {
            ++$d['overload508'];
        }
        if ($status >= 500 && $status <= 599) {
            ++$d['errors5xx'];
        }

        $method = $r['method'];
        $uri = $r['uri'];
        if ($method === 'POST' && ($status === 200 || $status === 400) && preg_match(self::LOGIN_RE, $r['path'])) {
            ++$d['loginFailed'];
        }

        $ua = $r['ua'];
        // Підтверджений пошуковий краулер (UA + опублікований діапазон IP) — не атакуючий.
        $verifiedBot = $this->crawlers->verify($ip, $ua);
        if ($verifiedBot !== null) {
            $d['ipBot'][$ip] = $verifiedBot;
            ++$d['verifiedBotRequests'];
        }
        if ($verifiedBot !== null || ($ua !== '' && preg_match(self::BOT_RE, $ua))) {
            ++$d['botRequests'];
            $name = $verifiedBot ?? $this->botName($ua);
            $d['bots'][$name] = ($d['bots'][$name] ?? 0) + 1;
        }

        if ($uri !== '') {
            $show = LogParser::displayUri($uri);
            $d['urls'][$show] = ($d['urls'][$show] ?? 0) + 1;
            if (count($d['urls']) > self::URL_MAP_MAX) {
                $d['urls'] = self::prune($d['urls']);
            }
            if ($status === 404) {
                $d['u404'][$show] = ($d['u404'][$show] ?? 0) + 1;
                if (count($d['u404']) > self::URL_MAP_MAX) {
                    $d['u404'] = self::prune($d['u404']);
                }
            }
        }

        $hit = $this->classifier->classify($method, $uri, $ua);
        if ($status === 403 && isset($this->hostWafSizes[$r['bytes']])) {
            // Відмова сервера хостингу до PHP: пакет цього запиту не бачив.
            $hw = $hit;
            if ($hw === null && $this->classifier instanceof RuleSetClassifier) {
                $hw = $this->classifier->classifyAny($method, $uri, $ua);
            }
            $c = $hw['category'] ?? 'unclassified';
            $rule = $hw['rule'] ?? 'NONE';
            ++$d['hwTotal'];
            self::countIp($d, 'hwIps', 'hwSk', $ip);
            $d['hwCategories'][$c] = ($d['hwCategories'][$c] ?? 0) + 1;
            $d['hwRules'][$rule] = ($d['hwRules'][$rule] ?? 0) + 1;
            if ($uri !== '') {
                $show = LogParser::displayUri($uri);
                $d['hwUrls'][$show] = ($d['hwUrls'][$show] ?? 0) + 1;
                if (count($d['hwUrls']) > self::URL_MAP_MAX) {
                    $d['hwUrls'] = self::prune($d['hwUrls']);
                }
            }
        }
        if ($hit !== null && ($hit['strength'] ?? 'strong') === 'weak') {
            // Слабкий збіг (звичайний текст, схожий на payload) — не атака.
            ++$d['weakAttackLike'];
            $hit = null;
        }
        if ($hit !== null && $verifiedBot !== null) {
            // Краулер ходить старими (Joomla) адресами, які схожі на проби, — рахуємо окремо.
            ++$d['botAttackLike'];
            $hit = null;
        }
        if ($hit !== null) {
            ++$d['attacks'];
            ++$d['hoursAttacks'][$hour];
            self::countIp($d, 'attackIps', 'attackSk', $ip);
            $c = $hit['category'];
            $d['categories'][$c] = ($d['categories'][$c] ?? 0) + 1;
            $rule = $hit['rule'];
            $d['rules'][$rule] = ($d['rules'][$rule] ?? 0) + 1;
        }

        $this->addReport($d, $r);
        unset($d);
    }

    /**
     * Рядок, який основна статистика відкинула як дубль іншого файлу того самого
     * потоку (напр. той самий запит в Apache- і nginx-архіві), — враховується лише
     * в цифрах «як у звіті»: ручний звіт рахував усі рядки всіх файлів.
     */
    public function addReportOnly(array $r): void
    {
        $day = $this->dayHour($r['ts'])[0];
        if ($this->onlyDays !== null && !isset($this->onlyDays[$day])) {
            return;
        }
        if (!isset($this->days[$day])) {
            $this->days[$day] = self::emptyDay();
        }
        $d = &$this->days[$day];
        if (!$this->exclude->matches($r['ip'])) {
            $this->addReport($d, $r);
        }
        unset($d);
    }

    private function addReport(array &$d, array $r): void
    {
        $uri = $r['rawUri'] ?? $r['uri'];
        ++$d['rTotal'];
        if ($r['status'] === 403) {
            ++$d['r403'];
        } elseif ($r['status'] === 508) {
            ++$d['r508'];
        }
        $rep = $this->report->classify($r['method'], $uri, $r['ua']);
        if ($rep !== null) {
            ++$d['rAttacks'];
            if (count($d['rAttackIps']) < self::IP_MAP_MAX) {
                $d['rAttackIps'][$r['ip']] = true;
            }
            $c = $rep['category'];
            $d['rCategories'][$c] = ($d['rCategories'][$c] ?? 0) + 1;
        }
        if (ReportClassifier::isLoginFailure($r['method'], $uri, $r['status'])) {
            ++$d['rLoginFailed'];
        }
    }

    /** Лічильник IP з обмеженням пам'яті: нові IP понад IP_MAP_MAX ідуть лише в HLL. */
    private static function countIp(array &$d, string $map, string $sketch, string $ip): void
    {
        if (isset($d[$map][$ip])) {
            ++$d[$map][$ip];

            return;
        }
        if ($d[$sketch] === null) {
            $d[$sketch] = new CardinalitySketch();
        }
        $d[$sketch]->add($ip);
        if (count($d[$map]) < self::IP_MAP_MAX) {
            $d[$map][$ip] = 1;
        } else {
            $d[$map . 'Overflow'] = true;
        }
    }

    /** @return string[] */
    public function days(): array
    {
        $k = array_keys($this->days);
        sort($k);

        return $k;
    }

    /**
     * Рядки таблиці: day => [колонки..., 'breakdown' => array].
     * @return array<string, array>
     */
    public function finish(): array
    {
        $out = [];
        foreach ($this->days() as $day) {
            $out[$day] = self::buildRow($this->days[$day]);
        }

        return $out;
    }

    private static function emptyDay(): array
    {
        return [
            'total' => 0, 'ips' => [], 'attacks' => 0, 'attackIps' => [], 'categories' => [], 'rules' => [],
            'blocked403' => 0, 'loginFailed' => 0, 'overload508' => 0, 'errors404' => 0, 'errors5xx' => 0,
            'bytes' => 0, 'botRequests' => 0, 'bots' => [], 'urls' => [], 'u404' => [],
            'hours' => array_fill(0, 24, 0), 'hoursAttacks' => array_fill(0, 24, 0), 'statuses' => [],
            'excluded' => 0, 'partial' => 0, 'ipBot' => [], 'verifiedBotRequests' => 0, 'botAttackLike' => 0, 'weakAttackLike' => 0,
            'rAttacks' => 0, 'rAttackIps' => [], 'rCategories' => [], 'rLoginFailed' => 0,
            'hwTotal' => 0, 'hwIps' => [], 'hwCategories' => [], 'hwRules' => [], 'hwUrls' => [],
            'rTotal' => 0, 'r403' => 0, 'r508' => 0,
            'ipSk' => null, 'attackSk' => null, 'hwSk' => null,
            'ipsOverflow' => false, 'attackIpsOverflow' => false, 'hwIpsOverflow' => false,
        ];
    }

    private static function buildRow(array $d): array
    {
        $ipSketch = $d['ipSk'] ?? new CardinalitySketch();
        $attackSketch = $d['attackSk'] ?? new CardinalitySketch();
        $hwSketch = $d['hwSk'] ?? new CardinalitySketch();
        $uniqueIps = $d['ipsOverflow'] ? max(count($d['ips']), $ipSketch->count()) : count($d['ips']);
        $attackIpCount = $d['attackIpsOverflow'] ? max(count($d['attackIps']), $attackSketch->count()) : count($d['attackIps']);
        $hwIpCount = $d['hwIpsOverflow'] ? max(count($d['hwIps']), $hwSketch->count()) : count($d['hwIps']);

        $topIps = [];
        $ips = $d['ips'];
        arsort($ips);
        foreach (array_slice($ips, 0, self::TOP_N, true) as $ip => $n) {
            $topIps[] = ['ip' => (string) $ip, 'count' => $n, 'attacks' => $d['attackIps'][$ip] ?? 0, 'bot' => $d['ipBot'][$ip] ?? null];
        }
        $topAttackIps = [];
        $aips = $d['attackIps'];
        arsort($aips);
        foreach (array_slice($aips, 0, self::TOP_N, true) as $ip => $n) {
            $topAttackIps[] = ['ip' => (string) $ip, 'count' => $n, 'bot' => $d['ipBot'][$ip] ?? null];
        }

        $attackIpList = array_map('strval', array_keys($d['attackIps']));
        sort($attackIpList);
        $truncated = count($attackIpList) > self::ATTACK_IP_LIST_MAX || $d['attackIpsOverflow'];
        if ($truncated) {
            $attackIpList = array_map('strval', array_keys(array_slice($aips, 0, self::ATTACK_IP_LIST_MAX, true)));
        }
        $rIpList = array_map('strval', array_keys($d['rAttackIps']));
        sort($rIpList);
        $rTruncated = count($rIpList) > self::ATTACK_IP_LIST_MAX;
        if ($rTruncated) {
            $rIpList = array_slice($rIpList, 0, self::ATTACK_IP_LIST_MAX);
        }

        $statuses = $d['statuses'];
        ksort($statuses);
        $categories = $d['categories'];
        arsort($categories);
        $rules = $d['rules'];
        arsort($rules);
        $bots = $d['bots'];
        arsort($bots);
        $rCats = $d['rCategories'];
        arsort($rCats);
        $hwIps = $d['hwIps'];
        arsort($hwIps);
        $hwTop = [];
        foreach (array_slice($hwIps, 0, self::TOP_N, true) as $ip => $n) {
            $hwTop[] = ['ip' => (string) $ip, 'count' => $n, 'bot' => $d['ipBot'][$ip] ?? null];
        }
        $hwList = array_map('strval', array_keys($hwIps));
        $hwTruncated = count($hwList) > self::ATTACK_IP_LIST_MAX || $d['hwIpsOverflow'];
        $hwList = array_slice($hwList, 0, self::ATTACK_IP_LIST_MAX);
        sort($hwList);
        $hwCats = $d['hwCategories'];
        arsort($hwCats);
        $hwRules = $d['hwRules'];
        arsort($hwRules);

        $breakdown = [
            'categories' => $categories,
            'rules' => array_slice($rules, 0, self::TOP_N, true),
            'topIps' => $topIps,
            'topAttackIps' => $topAttackIps,
            'topUrls' => self::topList($d['urls'], 'url'),
            'top404' => self::topList($d['u404'], 'url'),
            'countries' => [],
            'hours' => $d['hours'],
            'hoursAttacks' => $d['hoursAttacks'],
            'statuses' => array_map('intval', $statuses),
            'bots' => array_slice($bots, 0, self::TOP_N, true),
            'verifiedBotRequests' => $d['verifiedBotRequests'],
            'botAttackLike' => $d['botAttackLike'],
            'weakAttackLike' => $d['weakAttackLike'],
            'attackIpList' => $attackIpList,
            'attackIpListTruncated' => $truncated,
            'ipSketch' => $ipSketch->serialize(),
            'attackIpSketch' => $attackSketch->serialize(),
            'excluded' => $d['excluded'],
            'partialLines' => $d['partial'],
            'hostWaf' => [
                'categories' => $hwCats,
                'topRules' => array_slice($hwRules, 0, self::TOP_N, true),
                'topIps' => $hwTop,
                'topUrls' => self::topList($d['hwUrls'], 'url'),
                'ipList' => $hwList,
                'ipListTruncated' => $hwTruncated,
                'ipSketch' => $hwSketch->serialize(),
            ],
            'ipMapsCapped' => $d['ipsOverflow'] || $d['attackIpsOverflow'] || $d['hwIpsOverflow'],
            'report' => [
                'totalRequests' => $d['rTotal'],
                'blocked403' => $d['r403'],
                'overload508' => $d['r508'],
                'attackRequests' => $d['rAttacks'],
                'attackIps' => count($d['rAttackIps']),
                'attackIpList' => $rIpList,
                'attackIpListTruncated' => $rTruncated,
                'loginFailed' => $d['rLoginFailed'],
                'categories' => $rCats,
            ],
        ];
        $breakdown = self::fitBreakdown($breakdown);

        return [
            'totalRequests' => $d['total'],
            'uniqueIps' => $uniqueIps,
            'attackRequests' => $d['attacks'],
            'attackIps' => $attackIpCount,
            'blocked403' => $d['blocked403'],
            'loginFailed' => $d['loginFailed'],
            'overload508' => $d['overload508'],
            'errors404' => $d['errors404'],
            'errors5xx' => $d['errors5xx'],
            'bytes' => $d['bytes'],
            'botRequests' => $d['botRequests'],
            'hostWafBlocked' => $d['hwTotal'],
            'hostWafIps' => $hwIpCount,
            'breakdown' => $breakdown,
        ];
    }

    /** Колонка TEXT вміщує 64 КБ: якщо JSON завеликий — скорочуємо списки. */
    private static function fitBreakdown(array $b): array
    {
        $limits = [10, 5, 0];
        $i = 0;
        while (strlen((string) json_encode($b, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)) > self::BREAKDOWN_MAX_BYTES && $i < count($limits) + 2) {
            if ($i < count($limits)) {
                $n = $limits[$i];
                foreach (['topUrls', 'top404', 'topIps', 'topAttackIps'] as $k) {
                    $b[$k] = array_slice($b[$k], 0, $n);
                }
                $b['hostWaf']['topUrls'] = array_slice($b['hostWaf']['topUrls'], 0, $n);
                $b['hostWaf']['topIps'] = array_slice($b['hostWaf']['topIps'], 0, $n);
            } elseif ($i === count($limits)) {
                $b['attackIpList'] = array_slice($b['attackIpList'], 0, 200);
                $b['attackIpListTruncated'] = true;
                $b['report']['attackIpList'] = array_slice($b['report']['attackIpList'], 0, 200);
                $b['report']['attackIpListTruncated'] = true;
                $b['hostWaf']['ipList'] = array_slice($b['hostWaf']['ipList'], 0, 200);
                $b['hostWaf']['ipListTruncated'] = true;
            } else {
                $b['attackIpList'] = [];
                $b['report']['attackIpList'] = [];
                $b['hostWaf']['ipList'] = [];
            }
            ++$i;
        }

        return $b;
    }

    private static function topList(array $map, string $key): array
    {
        arsort($map);
        $out = [];
        foreach (array_slice($map, 0, self::TOP_N, true) as $k => $n) {
            $out[] = [$key => (string) $k, 'count' => $n];
        }

        return $out;
    }

    private static function prune(array $map): array
    {
        arsort($map);

        return array_slice($map, 0, intdiv(self::URL_MAP_MAX, 2), true);
    }

    private function botName(string $ua): string
    {
        $claimed = $this->crawlers->claimedBot($ua);
        if ($claimed !== null) {
            // UA пошуковика з чужої IP.
            return $claimed . ' (unverified)';
        }
        if (preg_match(self::BOT_NAME_RE, $ua, $m)) {
            return substr($m[1], 0, 40);
        }

        return 'other';
    }
}
