<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Login;

use Concrete\Core\Application\Application;
use Concrete\Core\Http\Request;
use Concrete\Core\User\User;
use PasichDev\SecurityGuard\Contract\AlertServiceInterface;
use PasichDev\SecurityGuard\Contract\BlockServiceInterface;
use PasichDev\SecurityGuard\Contract\StateCacheInterface;
use PasichDev\SecurityGuard\Contract\WhitelistInterface;
use PasichDev\SecurityGuard\Ip\ClientIp;
use PasichDev\SecurityGuard\Ip\IpRange;
use PasichDev\SecurityGuard\State\Counters;
use PasichDev\SecurityGuard\Waf\Whitelist;
use Throwable;

/**
 * Події входу. Невдалі входи ядро подією не повідомляє — їх рахує
 * GuardMiddleware за відповіддю на POST /login/authenticate/concrete.
 * Тут — успішний вхід адміністратора: автодовіра IP на trust_admin_days,
 * зняття бану з цієї IP і сповіщення про вхід із нової IP.
 */
final class LoginGuard
{
    /** @var Application */
    private $app;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    public function subscribe(): void
    {
        $this->app->make('director')->addListener('on_user_login', [$this, 'onUserLogin']);
    }

    /** @param \Concrete\Core\User\Event\User $event */
    public function onUserLogin($event): void
    {
        try {
            $user = is_object($event) && method_exists($event, 'getUserObject') ? $event->getUserObject() : null;
            if (!$user instanceof User || !self::isAdministrator($user)) {
                return;
            }
            $settings = $this->app->make(StateCacheInterface::class)->load()['settings'];
            if (empty($settings['enabled'])) {
                return;
            }
            $ip = ClientIp::fromRequest($this->app->make(Request::class), !empty($settings['trust_cloudflare']));
            if ($ip === '0.0.0.0' || IpRange::isLoopback($ip)) {
                return;
            }
            $name = (string) $user->getUserName();

            /** @var WhitelistInterface $whitelist */
            $whitelist = $this->app->make(WhitelistInterface::class);
            $known = $whitelist instanceof Whitelist ? $whitelist->contains($ip) : false;

            if (!empty($settings['trust_admin_ip'])) {
                $days = max(1, (int) ($settings['trust_admin_days'] ?? 7));
                $whitelist->add($ip, t('Administrator sign-in: %s', $name), time() + $days * 86400, true);
                $this->app->make(BlockServiceInterface::class)->unblock($ip);
                Counters::store()->delete('bf:' . $ip);
            }

            if (!empty($settings['notify_admin_new_ip']) && !$known) {
                $this->app->make(AlertServiceInterface::class)->raise(
                    'admin_new_ip',
                    'info',
                    t('Administrator %s signed in from a new IP address %s.', $name, $ip),
                    ['ip' => $ip]
                );
            }
        } catch (Throwable $e) {
            try {
                $this->app->make('log')->warning('Security Guard: login hook failed: ' . $e->getMessage());
            } catch (Throwable $ignored) {
            }
        }
    }

    /** Суперкористувач або учасник групи Administrators. */
    public static function isAdministrator(User $user): bool
    {
        if (!$user->isRegistered()) {
            return false;
        }
        if ($user->isSuperUser()) {
            return true;
        }
        $groups = (array) $user->getUserGroups();

        return in_array(ADMIN_GROUP_ID, $groups) || isset($groups[ADMIN_GROUP_ID]);
    }

    /**
     * Стан вбудованого захисту ядра (Dashboard → System → Permissions →
     * Deny IPs → failed_login) для показу на панелі: ми його не дублюємо і з ним
     * не боремося — наш лічильник доповнює його ескалацією й сповіщеннями.
     *
     * @return array{enabled: bool, maxEvents: int, timeWindow: int, banDuration: int|null, denylisted: bool}
     */
    public function coreFailedLoginStatus(?string $ip = null): array
    {
        $out = ['enabled' => false, 'maxEvents' => 0, 'timeWindow' => 0, 'banDuration' => null, 'denylisted' => false];
        try {
            /** @var \Concrete\Core\Permission\IpAccessControlService $service */
            $service = $this->app->make('failed_login');
            $category = $service->getCategory();
            $out['enabled'] = (bool) $category->isEnabled();
            $out['maxEvents'] = (int) $category->getMaxEvents();
            $out['timeWindow'] = (int) $category->getTimeWindow();
            $duration = $category->getBanDuration();
            $out['banDuration'] = $duration === null ? null : (int) $duration;
            if ($ip !== null && $ip !== '') {
                $out['denylisted'] = (bool) $service->isDenylisted(\IPLib\Factory::parseAddressString($ip));
            } else {
                $out['denylisted'] = (bool) $service->isDenylisted();
            }
        } catch (Throwable $e) {
        }

        return $out;
    }
}
