<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Http;

use Concrete\Core\Application\Application;
use Concrete\Core\Http\Middleware\DelegateInterface;
use Concrete\Core\Http\Middleware\MiddlewareInterface;
use Concrete\Core\User\User;
use PasichDev\SecurityGuard\Contract\AlertServiceInterface;
use PasichDev\SecurityGuard\Contract\BlockServiceInterface;
use PasichDev\SecurityGuard\Contract\EventLogInterface;
use PasichDev\SecurityGuard\Contract\HoneypotRepositoryInterface;
use PasichDev\SecurityGuard\Contract\ScoreServiceInterface;
use PasichDev\SecurityGuard\Contract\StateCacheInterface;
use PasichDev\SecurityGuard\Ip\ClientIp;
use PasichDev\SecurityGuard\Rules\Paths;
use PasichDev\SecurityGuard\Rules\RuleSet;
use PasichDev\SecurityGuard\State\Counters;
use PasichDev\SecurityGuard\Waf\BotVerifier;
use PasichDev\SecurityGuard\Waf\Decision;
use PasichDev\SecurityGuard\Waf\Firewall;
use PasichDev\SecurityGuard\Waf\Maintenance;
use PasichDev\SecurityGuard\Waf\RequestInfo;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * WAF як HTTP middleware Concrete (priority 1 — одразу після
 * ApplicationMiddleware ядра). Бачить запит до диспетчеризації і відповідь
 * після неї (так ловимо невдалий вхід: події ядро не має).
 *
 * Fail-open: будь-яка помилка в наших перевірках пишеться в лог і запит
 * іде далі. Винятки самого сайту з $frame->next() ми не чіпаємо.
 */
final class GuardMiddleware implements MiddlewareInterface
{
    private const SESSION_TRUST_KEY = 'security_guard.trusted_user';
    private const TRUST_RECHECK = 300;

    /** @var Application */
    private $app;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    public function process(Request $request, DelegateInterface $frame)
    {
        $firewall = null;
        $info = null;
        // Підписаний запит «Перевірки безпеки» з самого сервера — без перевірок WAF.
        if ($request->headers->has(SelfProbe::HEADER) && SelfProbe::isValid($request, null, Counters::store())) {
            return $frame->next($request);
        }
        try {
            $firewall = $this->firewall();
            if ($firewall->isEnabled()) {
                $info = $this->describe($request, $firewall->settings());
                $decision = $firewall->inspect($info, function () use ($request, $info): bool {
                    return $this->isTrustedUser($request, $info);
                }, function () use ($request, $info): bool {
                    // Звичайним зареєстрованим довіряємо на службових шляхах, лише коли
                    // публічна реєстрація вимкнена: інакше будь-хто отримав би обхід
                    // перевірок для /ccm/ (IDOR на зразок CVE-2026-8237) просто зареєструвавшись.
                    return !$this->publicRegistrationOpen() && $this->sessionUserId($request, $info) > 0;
                }, function () use ($request, $info): bool {
                    return $this->sessionUserId($request, $info) > 0;
                });
                if ($decision !== null) {
                    return $this->deny($decision);
                }
            }
        } catch (Throwable $e) {
            $this->log($e);
            $firewall = null;
        }

        $response = $frame->next($request);

        if ($firewall !== null && $info !== null) {
            try {
                if ($info->isLoginAttempt) {
                    $decision = $firewall->afterLogin($info, $this->loginFailed($info, $response));
                    if ($decision !== null) {
                        $response = $this->deny($decision);
                    }
                }
                if ($firewall->maintenanceFallbackDue()) {
                    $this->scheduleMaintenance();
                }
            } catch (Throwable $e) {
                $this->log($e);
            }
        }

        return $response;
    }

    /** Невдалий вхід: форма показана знову (успіх — redirect) або OAuth2 відповів invalid_grant. */
    private function loginFailed(RequestInfo $info, Response $response): bool
    {
        if (Paths::isOauthToken($info->pathInfo) || Paths::isOauthToken(Paths::normalize($info->path()))) {
            $code = $response->getStatusCode();
            if ($code !== 400 && $code !== 401) {
                return false;
            }
            $content = (string) $response->getContent();

            return $code === 401 || stripos($content, 'invalid_grant') !== false || stripos($content, 'invalid_credentials') !== false;
        }

        return !($response instanceof RedirectResponse) && !$response->isRedirection();
    }

    /**
     * Запасне очищення, коли cron не працює: після відправки відповіді
     * (fastcgi/litespeed finish), з жорстким лімітом часу. Відвідувач не чекає.
     */
    private function scheduleMaintenance(): void
    {
        $app = $this->app;
        register_shutdown_function(static function () use ($app): void {
            try {
                if (function_exists('fastcgi_finish_request')) {
                    @fastcgi_finish_request();
                } elseif (function_exists('litespeed_finish_request')) {
                    @litespeed_finish_request();
                }
                @set_time_limit(30);
                (new Maintenance($app))->run(5.0);
            } catch (Throwable $e) {
            }
        });
    }

    private function firewall(): Firewall
    {
        $state = $this->app->make(StateCacheInterface::class)->load();
        $counters = Counters::store();
        $map = [
            'block' => BlockServiceInterface::class,
            'events' => EventLogInterface::class,
            'honeypot' => HoneypotRepositoryInterface::class,
            'scores' => ScoreServiceInterface::class,
            'alerts' => AlertServiceInterface::class,
        ];
        $app = $this->app;
        $bots = null;
        $services = static function (string $id) use ($app, $map, $counters, &$bots) {
            if ($id === 'bots') {
                if ($bots === null) {
                    $cache = $app->make(StateCacheInterface::class);
                    $ranges = method_exists($cache, 'botRanges') ? $cache->botRanges() : [];
                    $bots = new BotVerifier($app, $counters, null, null, null, $ranges);
                }

                return $bots;
            }

            return $app->make($map[$id]);
        };

        return new Firewall($state, $counters, $services, function (string $message): void {
            try {
                $this->app->make('log')->warning($message);
            } catch (Throwable $ignored) {
            }
        });
    }

    private function describe(Request $request, array $settings): RequestInfo
    {
        $info = new RequestInfo();
        $info->now = time();
        $info->ip = ClientIp::fromRequest($request, !empty($settings['trust_cloudflare']));
        $info->method = strtoupper($request->getMethod());
        $info->uri = (string) $request->getRequestUri();
        $info->pathInfo = (string) $request->getPathInfo();
        $info->userAgent = (string) $request->headers->get('User-Agent', '');
        $info->referer = (string) $request->headers->get('Referer', '');
        $info->hasAccept = trim((string) $request->headers->get('Accept', '')) !== '';
        $info->hasAcceptLanguage = trim((string) $request->headers->get('Accept-Language', '')) !== '';
        $query = $request->query->all();
        $bypass = $query['sg_pass'] ?? null;
        $info->bypass = is_string($bypass) ? $bypass : null;

        $path = Paths::normalize($info->path());
        $info->cookies = $this->cookies($request);
        $info->fetchSite = strtolower(trim((string) $request->headers->get('Sec-Fetch-Site', '')));
        $info->fetchDest = strtolower(trim((string) $request->headers->get('Sec-Fetch-Dest', '')));
        if ($info->method === 'POST'
            && (Paths::isLoginAuthenticate($info->pathInfo) || Paths::isLoginAuthenticate($path))) {
            $post = $request->request->all();
            $name = $post['uName'] ?? null;
            $password = $post['uPassword'] ?? null;
            // Порожня форма — помилка введення, а не підбір пароля. Пароль не скануємо.
            $info->isLoginAttempt = is_string($name) && trim($name) !== '' && is_string($password) && $password !== '';
            $info->loginUser = is_string($name) ? strtolower(trim($name)) : '';
        } elseif ($info->method === 'POST'
            && (Paths::isOauthToken($info->pathInfo) || Paths::isOauthToken($path))) {
            $post = $request->request->all();
            $grant = $post['grant_type'] ?? null;
            $name = $post['username'] ?? null;
            $info->isLoginAttempt = $grant === 'password' && is_string($name) && trim($name) !== '';
            $info->loginUser = is_string($name) ? strtolower(trim($name)) : '';
        } elseif (in_array($info->method, ['POST', 'PUT', 'PATCH', 'DELETE'], true) && !empty($settings['scan_post_body'])) {
            // На службових шляхах Firewall не дивиться в тіло, якщо користувач увійшов.
            $info->body = $this->body($request);
        }

        return $info;
    }

    /**
     * Значення cookie для сигнатур (серіалізовані об'єкти, XXE, SSRF), крім
     * cookie сесії/входу Concrete — їх ядро перевіряє само.
     */
    private function cookies(Request $request): string
    {
        $all = $request->cookies->all();
        if ($all === []) {
            return '';
        }
        $session = (string) $this->app->make('config')->get('concrete.session.name', 'CONCRETE');
        $out = '';
        foreach ($all as $name => $value) {
            $name = (string) $name;
            if (!is_string($value) || $value === '' || $name === $session
                || stripos($name, 'concrete') === 0 || stripos($name, 'ccm') === 0) {
                continue;
            }
            $out .= $name . '=' . substr($value, 0, 4096) . "\n";
            if (strlen($out) > 16384) {
                break;
            }
        }

        return $out;
    }

    /**
     * Текст тіла для сигнатур: поля multipart без файлів; інакше перші
     * MAX_BODY_BYTES сирого вмісту (JSON/urlencoded/текст), навіть якщо тіло більше.
     */
    private function body(Request $request): string
    {
        $type = strtolower((string) $request->headers->get('Content-Type', ''));
        if (strpos($type, 'multipart/') === 0) {
            $fields = $request->request->all();

            return $fields ? substr(http_build_query($fields), 0, RuleSet::MAX_BODY_BYTES) : '';
        }
        $length = (int) $request->headers->get('Content-Length', '0');
        if ($length > RuleSet::MAX_BODY_BYTES) {
            $stream = @fopen('php://input', 'rb');
            if ($stream !== false) {
                $head = (string) stream_get_contents($stream, RuleSet::MAX_BODY_BYTES);
                fclose($stream);
                if ($head !== '') {
                    return $head;
                }
            }
            $fields = $request->request->all();

            return $fields ? substr(http_build_query($fields), 0, RuleSet::MAX_BODY_BYTES) : '';
        }
        $content = $request->getContent();

        return is_string($content) ? substr($content, 0, RuleSet::MAX_BODY_BYTES) : '';
    }

    /**
     * Увійшов користувач із доступом до дашборду? Сесію не створюємо: лише
     * якщо браузер уже має cookie сесії Concrete і в ній є uID. На POST входу
     * користувача не будуємо (щоб не закешувати гостя до автентифікації).
     */
    private function isTrustedUser(Request $request, RequestInfo $info): bool
    {
        if ($info->isLoginAttempt || Paths::isLoginAuthenticate($info->pathInfo)) {
            return false;
        }
        $uID = $this->sessionUserId($request, $info);
        if ($uID <= 0) {
            return false;
        }
        $session = $this->app->make('session');
        $cached = $session->get(self::SESSION_TRUST_KEY);
        // Кеш у сесії — на 5 хв: зняті права адміністратора перестають діяти швидко.
        if (is_array($cached) && (int) ($cached[0] ?? 0) === $uID && (int) ($cached[2] ?? 0) > time() - self::TRUST_RECHECK) {
            return (bool) ($cached[1] ?? false);
        }
        $trusted = false;
        $user = $this->app->make(User::class);
        if ($user->isRegistered()) {
            $groups = (array) $user->getUserGroups();
            $trusted = $user->isSuperUser()
                || in_array(ADMIN_GROUP_ID, $groups) || isset($groups[ADMIN_GROUP_ID])
                || (bool) $this->app->make('helper/concrete/dashboard')->canRead();
        }
        $session->set(self::SESSION_TRUST_KEY, [$uID, $trusted, time()]);

        return $trusted;
    }

    private function publicRegistrationOpen(): bool
    {
        $config = $this->app->make('config');
        $type = (string) $config->get('concrete.user.registration.type', 'disabled');

        return (bool) $config->get('concrete.user.registration.enabled', false) || ($type !== '' && $type !== 'disabled');
    }

    /** uID із наявної сесії Concrete або 0. Нову сесію не створює. */
    private function sessionUserId(Request $request, RequestInfo $info): int
    {
        if ($info->isLoginAttempt || Paths::isLoginAuthenticate($info->pathInfo)) {
            return 0;
        }
        $cookieName = (string) $this->app->make('config')->get('concrete.session.name', 'CONCRETE');
        if ($cookieName === '' || !$request->cookies->has($cookieName)) {
            return 0;
        }

        return (int) $this->app->make('session')->get('uID', 0);
    }

    private function deny(Decision $decision): Response
    {
        if ($decision->isRedirect()) {
            return new RedirectResponse($decision->location, 302, ['Cache-Control' => 'no-store, private', 'Referrer-Policy' => 'no-referrer']);
        }
        $code = $decision->status;
        if ($decision->isBruteforce()) {
            $title = t('Too Many Requests');
            $text = t('Too many failed sign-in attempts from your IP address. Please try again later.');
        } elseif ($code === 404) {
            $title = t('Not Found');
            $text = t('The page you are looking for cannot be found.');
        } elseif ($code === 410) {
            $title = t('Gone');
            $text = t('The page you are looking for cannot be found.');
        } else {
            $title = t('Access Denied');
            $text = t('Access to this page from your network is not allowed.');
        }
        $html = '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex">'
            . '<title>' . htmlspecialchars($code . ' ' . $title, ENT_QUOTES, 'UTF-8') . '</title></head>'
            . '<body><h1>' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '</h1>'
            . '<p>' . htmlspecialchars($text, ENT_QUOTES, 'UTF-8') . '</p></body></html>';
        $headers = [
            'Content-Type' => 'text/html; charset=UTF-8',
            'Cache-Control' => 'no-store, private',
            'X-Robots-Tag' => 'noindex',
        ];
        if ($code === 429 && $decision->retryAfter > 0) {
            $headers['Retry-After'] = (string) min($decision->retryAfter, 86400);
        }

        return new Response($html, $code, $headers);
    }

    private function log(Throwable $e): void
    {
        try {
            $this->app->make('log')->error('Security Guard: ' . get_class($e) . ': ' . $e->getMessage());
        } catch (Throwable $ignored) {
        }
    }
}
