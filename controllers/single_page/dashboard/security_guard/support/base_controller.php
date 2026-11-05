<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support;

use Concrete\Core\Http\ResponseFactoryInterface;
use Concrete\Core\Page\Controller\DashboardPageController;
use Concrete\Core\Url\Resolver\Manager\ResolverManagerInterface;
use PasichDev\SecurityGuard\Config\Settings;
use PasichDev\SecurityGuard\Contract\BlockServiceInterface;
use PasichDev\SecurityGuard\Contract\LogIngestInterface;
use PasichDev\SecurityGuard\Contract\StateCacheInterface;
use PasichDev\SecurityGuard\Contract\WhitelistInterface;
use Throwable;

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * Спільна основа сторінок пакета: ресурси, безпечний виклик сервісів,
 * перевірка POST+токена, redirect-after-POST, IP поточного адміністратора.
 *
 * Права на сторінку перевіряє сам Concrete (DashboardPageController);
 * тут — лише токен і метод запиту. Усі допоміжні методи protected,
 * щоб їх не можна було викликати як дію через URL.
 */
abstract class BaseController extends DashboardPageController
{
    public const PKG = 'security_guard';

    /** @var string[] помилки сервісів, показуються на сторінці */
    protected $serviceErrors = [];

    /** @var Settings|null */
    private $settingsObject;

    /** @var array{ip: string, bot: string}|null бан бота, що чекає підтвердження */
    protected $pendingBotBan;

    public function on_start()
    {
        parent::on_start();
        // Версія = час зміни файлу: статику віддають з кешем на рік, а після
        // деплою браузер має взяти нову.
        $this->addHeaderItem('<link rel="stylesheet" href="' . h(self::assetUrl('css/security-guard.css')) . '">');
        $this->addFooterItem('<script src="' . h(self::assetUrl('js/security-guard.js')) . '"></script>');
    }

    public static function assetUrl(string $rel): string
    {
        $dir = dirname(__DIR__, 5);
        $v = @filemtime($dir . '/' . $rel) ?: 0;
        $base = defined('REL_DIR_PACKAGES') ? REL_DIR_PACKAGES : '/packages';

        return $base . '/' . self::PKG . '/' . $rel . '?v=' . $v;
    }

    public function on_before_render()
    {
        parent::on_before_render();
        $this->set('sgServiceErrors', $this->serviceErrors);
        $this->set('sgPagePath', $this->getPageObject() ? (string) $this->getPageObject()->getCollectionPath() : '');
        $this->set('sgPageUrl', $this->pageUrl());
        $this->set('sgMode', $this->safe(function () {
            $s = $this->settings();

            return $s->get('enabled') ? (string) $s->get('mode') : 'disabled';
        }, 'unknown', ''));
    }

    /**
     * Викликає сервіс; будь-яка помилка (ще не встановлені таблиці, відсутня
     * реалізація) не валить сторінку, а показується попередженням.
     *
     * @return mixed
     */
    protected function safe(callable $fn, $default, string $what = '')
    {
        try {
            return $fn();
        } catch (Throwable $e) {
            if ($what !== '') {
                $this->serviceErrors[] = t('%s is unavailable: %s', $what, $e->getMessage());
            }
            try {
                $this->app->make('log')->warning('Security Guard dashboard: ' . $e->getMessage());
            } catch (Throwable $ignored) {
            }

            return $default;
        }
    }

    /** @return object */
    protected function service(string $interface)
    {
        return $this->app->make($interface);
    }

    /** Сервіс, який створюється лише при першому виклику методу (див. LazyService). */
    protected function lazy(string $interface): LazyService
    {
        return new LazyService($this->app, $interface);
    }

    protected function settings(): Settings
    {
        if ($this->settingsObject === null) {
            $this->settingsObject = $this->app->make(Settings::class);
        }

        return $this->settingsObject;
    }

    protected function rebuildState(): void
    {
        $this->safe(function () {
            $this->service(StateCacheInterface::class)->rebuild();
        }, null, t('State cache'));
    }

    /**
     * true — запит POST з чинним токеном дії. Інакше ставить flash-помилку.
     */
    protected function isValidPost(string $action): bool
    {
        if (!$this->request->isMethod('POST')) {
            $this->flash('error', t('This action requires a form submission.'));

            return false;
        }
        if (!$this->token->validate($action)) {
            $this->flash('error', $this->token->getErrorMessage());

            return false;
        }

        return true;
    }

    /**
     * Redirect-after-POST на головну дію сторінки з параметрами запиту.
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    protected function back(array $query = [])
    {
        $url = $this->pageUrl();
        $query = array_filter($query, static function ($v) {
            return $v !== null && $v !== '';
        });
        if ($query) {
            $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($query);
        }

        return $this->app->make(ResponseFactoryInterface::class)->redirect($url, 302);
    }

    protected function pageUrl(): string
    {
        return (string) $this->app->make(ResolverManagerInterface::class)->resolve([$this->getPageObject()]);
    }

    /** Рядок з POST, обрізаний і обмежений за довжиною. */
    protected function postString(string $key, int $max = 255): string
    {
        $v = $this->request->request->get($key, '');

        return is_string($v) ? mb_substr(trim($v), 0, $max) : '';
    }

    /** Фільтр періоду з прихованих полів форми — щоб повернутися на той самий вигляд. */
    protected function postedPeriod(): array
    {
        $out = [];
        foreach (['period' => '/^(7|30|90|custom)$/', 'from' => '/^\d{4}-\d{2}-\d{2}$/', 'to' => '/^\d{4}-\d{2}-\d{2}$/'] as $k => $re) {
            $v = $this->postString($k, 10);
            if ($v !== '' && preg_match($re, $v)) {
                $out[$k] = $v;
            }
        }

        return $out;
    }

    protected function queryString(string $key, int $max = 255): string
    {
        $v = $this->request->query->get($key, '');

        return is_string($v) ? mb_substr(trim($v), 0, $max) : '';
    }

    protected function currentPage(): int
    {
        return max(1, (int) $this->request->query->get('page', 1));
    }

    /**
     * IP поточного адміністратора. 'resolved' — як бачить Concrete (з
     * урахуванням його довірених проксі), 'remote' — REMOTE_ADDR.
     *
     * @return array{resolved: string, remote: string, all: string[]}
     */
    protected function clientIps(): array
    {
        $resolved = (string) $this->request->getClientIp();
        $remote = (string) $this->request->server->get('REMOTE_ADDR', '');
        $all = [];
        foreach ([$resolved, $remote] as $ip) {
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) && !in_array($ip, $all, true)) {
                $all[] = $ip;
            }
        }

        return ['resolved' => $resolved, 'remote' => $remote, 'all' => $all];
    }

    /** Спільна логіка ручного бану (використовують кілька сторінок). */
    protected function doBan(string $ip, string $duration, string $reason, string $category): bool
    {
        $ip = trim($ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->flash('error', t('"%s" is not a valid IP address.', $ip));

            return false;
        }
        if (in_array($ip, $this->clientIps()['all'], true)) {
            $this->flash('error', t('You cannot block your own IP address (%s).', $ip));

            return false;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE) === false) {
            $this->flash('error', t('Loopback and reserved addresses cannot be blocked.'));

            return false;
        }
        $whitelisted = $this->safe(function () use ($ip) {
            $wl = $this->service(WhitelistInterface::class);
            $ranges = array_map(static function ($w) {
                return (string) ($w['ipRange'] ?? '');
            }, $wl->all());
            $ranges = array_merge($ranges, preg_split('/[\s,]+/', (string) $this->settings()->get('whitelist_ranges')) ?: []);
            foreach ($ranges as $range) {
                if ($range !== '' && $wl::matches($ip, $range)) {
                    return true;
                }
            }

            return false;
        }, false, '');
        if ($whitelisted) {
            $this->flash('error', t('%s is in the whitelist. Remove it from the whitelist first.', $ip));

            return false;
        }
        // Пошуковий бот: бан прибирає сайт із пошуку — лише з явним підтвердженням.
        $bot = $this->botName($ip);
        if ($bot !== null && !$this->request->request->get('confirm_bot')) {
            $this->pendingBotBan = ['ip' => $ip, 'bot' => $bot];
            $this->flash('error', t('%s belongs to the search engine crawler %s. Confirm the ban explicitly below.', $ip, $bot));

            return false;
        }
        $seconds = null;
        if ($duration !== 'escalation' && $duration !== '') {
            if (!preg_match('/^\d{1,9}$/', $duration)) {
                $this->flash('error', t('Invalid block duration.'));

                return false;
            }
            $seconds = (int) $duration;
        }
        $ok = $this->safe(function () use ($ip, $reason, $category, $seconds) {
            $this->service(BlockServiceInterface::class)->block($ip, $reason, $category, $seconds, true, []);

            return true;
        }, false, t('Blocks'));
        if ($ok) {
            $this->flash('success', $seconds === 0
                ? t('%s is blocked permanently.', $ip)
                : t('%s is blocked.', $ip));
        } else {
            $this->flash('error', t('Could not block %s.', $ip));
        }

        return (bool) $ok;
    }

    /**
     * Назва пошукового бота для IP або null: верифікований запис у
     * SecurityGuardBotCache (rDNS + прямий DNS, за 90 днів) або позначка bot
     * у топах логів хостингу за 30 днів. Відсутні поля/таблиці — не бот.
     */
    protected function botName(string $ip): ?string
    {
        $name = $this->safe(function () use ($ip) {
            $db = $this->app->make(\Concrete\Core\Database\Connection\Connection::class);
            $row = $db->fetchAssociative(
                'SELECT botName FROM SecurityGuardBotCache WHERE ip = ? AND isBot = 1 AND verifiedAt >= ?',
                [$ip, time() - 90 * 86400]
            );

            return $row ? ((string) ($row['botName'] ?? '') ?: 'search bot') : null;
        }, null, '');
        if ($name !== null) {
            return $name;
        }

        return $this->safe(function () use ($ip) {
            $p = \Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Period::lastDays(30);
            $sum = $this->service(\PasichDev\SecurityGuard\Contract\StatsRepositoryInterface::class)->summarize($p->fromDay, $p->toDay);
            foreach (['topAttackIps', 'topIps'] as $k) {
                foreach ((array) ($sum['breakdown'][$k] ?? []) as $row) {
                    if (is_array($row) && ($row['ip'] ?? null) === $ip && !empty($row['bot'])) {
                        return (string) $row['bot'];
                    }
                }
            }

            return null;
        }, null, '');
    }

    /**
     * Відповідь після спроби бану: якщо це бот без підтвердження — на сторінку
     * банів із заповненою формою й обов'язковим чекбоксом, інакше — $default.
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    protected function afterBan($default)
    {
        if ($this->pendingBotBan === null) {
            return $default;
        }
        $url = (string) $this->app->make(ResolverManagerInterface::class)->resolve(['/dashboard/security_guard/blocks']);

        return $this->app->make(ResponseFactoryInterface::class)->redirect(
            $url . '?' . http_build_query(['ban_ip' => $this->pendingBotBan['ip'], 'bot' => $this->pendingBotBan['bot']]),
            302
        );
    }

    protected function runIngest(): void
    {
        $budget = (int) $this->safe(function () {
            return $this->settings()->get('log_ingest_time_budget');
        }, 20, '');
        $budget = max(1, min(120, $budget));
        if (function_exists('set_time_limit')) {
            @set_time_limit($budget + 30);
        }
        $result = $this->safe(function () use ($budget) {
            return $this->service(LogIngestInterface::class)->ingest($budget);
        }, null, t('Hosting log import'));
        if (!is_array($result)) {
            $this->flash('error', t('Could not read the hosting logs.') . ($this->serviceErrors ? ' ' . implode(' ', $this->serviceErrors) : ''));

            return;
        }
        $msg = t('Read %s lines from %s files; days recalculated: %s.',
            number_format((int) ($result['lines'] ?? 0), 0, ',', ' '),
            (int) ($result['files'] ?? 0),
            count((array) ($result['days'] ?? [])));
        $files = (int) ($result['files'] ?? 0);
        if (empty($result['finished']) && $files > 0) {
            $msg .= ' ' . t('Not all data was read within the time limit — press the button again to continue.');
        }
        $errors = array_slice(array_map('strval', (array) ($result['errors'] ?? [])), 0, 5);
        if ($errors) {
            $this->flash('error', t('Some log files could not be read:') . ' ' . implode('; ', $errors));
        }
        // Нічого не прочитано через помилку — «успіх» лише заплутав би.
        if (!$errors || $files > 0) {
            $this->flash('success', $msg);
        }
    }

    /** Пагінація для елемента pagination. */
    protected function setPagination(int $total, int $perPage, int $page, array $query = []): void
    {
        $this->set('pagination', [
            'total' => $total,
            'perPage' => $perPage,
            'page' => $page,
            'pages' => max(1, (int) ceil($total / max(1, $perPage))),
            'query' => $query,
        ]);
    }
}
