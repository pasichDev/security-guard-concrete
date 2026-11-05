<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Audit;

use Concrete\Core\Application\Application;
use Concrete\Core\Package\PackageService;
use PasichDev\SecurityGuard\Config\Settings;
use RecursiveCallbackFilterIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Throwable;

/**
 * Перевірка середовища для сторінки «Перевірка безпеки». Запускається лише
 * кнопкою (не на кожному відкритті сторінки): сканування файлів і HTTP-проби
 * обмежені за кількістю й часом. Результат зберігається в конфігу пакета.
 *
 * Кожен пункт: id, title, status (ok|warn|fail|unknown), finding, advice, details[].
 */
final class Checklist
{
    public const STATUS_OK = 'ok';
    public const STATUS_WARN = 'warn';
    public const STATUS_FAIL = 'fail';
    public const STATUS_UNKNOWN = 'unknown';

    private const CONFIG_KEY = 'audit.last_result';
    private const SCAN_MAX_ENTRIES = 60000;
    private const SCAN_SECONDS = 8.0;
    private const HTTP_TIMEOUT = 4.0;

    /** Дати кінця підтримки безпеки гілок PHP. */
    private const PHP_EOL = [
        '7.4' => '2022-11-28',
        '8.0' => '2023-11-26',
        '8.1' => '2025-12-31',
        '8.2' => '2026-12-31',
        '8.3' => '2027-12-31',
        '8.4' => '2028-12-31',
        '8.5' => '2029-12-31',
    ];

    /** @var Application */
    private $app;

    /** @var string */
    private $baseUrl;

    /** @var string */
    private $webRoot;

    /** @var string */
    private $appDir;

    /** @var string IP адміністратора, як її бачить сайт (для перевірки проксі) */
    private $clientIp = '';

    /**
     * @param string $baseUrl адреса сайту (схема + хост [+ шлях]); проби — лише на неї
     */
    public function __construct(Application $app, string $baseUrl = '', string $webRoot = '', string $appDir = '')
    {
        $this->app = $app;
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->webRoot = rtrim($webRoot !== '' ? $webRoot : (defined('DIR_BASE') ? DIR_BASE : ''), '/');
        $this->appDir = rtrim($appDir !== '' ? $appDir : (defined('DIR_APPLICATION') ? DIR_APPLICATION : ''), '/');
    }

    public function setClientIp(string $ip): self
    {
        $this->clientIp = $ip;

        return $this;
    }

    /** @return array{ranAt: int, duration: float, items: array, counts: array} */
    public function run(): array
    {
        $started = microtime(true);
        $items = [];
        $checks = [
            'checkPackageMode',
            'checkConfigPermissions',
            'checkPhpInUploads',
            'checkWorldWritable',
            'checkHttpProbes',
            'checkSecurityHeaders',
            'checkHttps',
            'checkConcreteVersion',
            'checkPhpVersion',
            'checkErrorDisplay',
            'checkFailedLoginBan',
            'checkPageCache',
            'checkPanelAccess',
            'checkClientIp',
            'checkPcreJit',
            'checkApcu',
            'checkRegistration',
        ];
        foreach ($checks as $method) {
            try {
                foreach ($this->{$method}() as $item) {
                    $items[] = $item;
                }
            } catch (Throwable $e) {
                $items[] = $this->item($method, $method, self::STATUS_UNKNOWN, t('The check failed: %s', $e->getMessage()), '');
            }
        }
        $counts = [self::STATUS_OK => 0, self::STATUS_WARN => 0, self::STATUS_FAIL => 0, self::STATUS_UNKNOWN => 0];
        foreach ($items as $it) {
            ++$counts[$it['status']];
        }

        return [
            'ranAt' => time(),
            'duration' => round(microtime(true) - $started, 1),
            'items' => $items,
            'counts' => $counts,
        ];
    }

    public function save(array $result): void
    {
        $this->config()->save(self::CONFIG_KEY, json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    /** Останній збережений результат або null. */
    public static function lastResult(Application $app): ?array
    {
        try {
            $raw = $app->make(PackageService::class)->getClass('security_guard')->getConfig()->get(self::CONFIG_KEY);
            if (!is_string($raw) || $raw === '') {
                return null;
            }
            $data = json_decode($raw, true);

            return is_array($data) && isset($data['items']) ? $data : null;
        } catch (Throwable $e) {
            return null;
        }
    }

    /** @return object */
    private function config()
    {
        return $this->app->make(PackageService::class)->getClass('security_guard')->getConfig();
    }

    private function item(string $id, string $title, string $status, string $finding, string $advice, array $details = []): array
    {
        return [
            'id' => $id,
            'title' => $title,
            'status' => $status,
            'finding' => $finding,
            'advice' => $advice,
            'details' => array_values(array_map('strval', $details)),
        ];
    }

    // ---------------------------------------------------------------- пункти

    private function checkPackageMode(): array
    {
        $s = $this->app->make(Settings::class);
        $title = t('Firewall mode');
        if (!$s->get('enabled')) {
            return [$this->item('mode', $title, self::STATUS_FAIL, t('The firewall is disabled.'), t('Enable it in Security Guard → Settings.'))];
        }
        if ($s->get('mode') !== Settings::MODE_ENFORCE) {
            return [$this->item('mode', $title, self::STATUS_WARN, t('Monitor mode: attacks are logged but not blocked.'),
                t('Review the event log for false positives for a few days, then switch to enforce mode.'))];
        }

        return [$this->item('mode', $title, self::STATUS_OK, t('Enforce mode: attacks are blocked.'), '')];
    }

    private function checkConfigPermissions(): array
    {
        $title = t('Permissions of application/config');
        $dir = $this->appDir . '/config';
        if (!is_dir($dir)) {
            return [$this->item('config_perms', $title, self::STATUS_UNKNOWN, t('The directory %s was not found.', 'application/config'), '')];
        }
        $problems = [];
        $status = self::STATUS_OK;
        $targets = [$dir => true];
        foreach (@scandir($dir) ?: [] as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            $path = $dir . '/' . $f;
            if (is_file($path) && preg_match('/\.php$/i', $f)) {
                $targets[$path] = false;
            }
        }
        foreach ($targets as $path => $isDir) {
            $perms = @fileperms($path);
            if ($perms === false) {
                continue;
            }
            $mode = $perms & 0777;
            $rel = $this->relative($path);
            if ($mode & 0002) {
                $status = self::STATUS_FAIL;
                $problems[] = t('%s is writable by everyone (%s)', $rel, sprintf('%04o', $mode));
            } elseif ($mode & 0004) {
                if ($status !== self::STATUS_FAIL) {
                    $status = self::STATUS_WARN;
                }
                $problems[] = t('%s is readable by everyone (%s)', $rel, sprintf('%04o', $mode));
            }
        }
        if ($status === self::STATUS_OK) {
            return [$this->item('config_perms', $title, self::STATUS_OK, t('Configuration files are not accessible to other system users.'), '')];
        }

        return [$this->item('config_perms', $title, $status,
            t('Configuration files (database password) are accessible to other users of the server.'),
            t('Set 0750 on the directory and 0640 on the files (cPanel → File Manager → Permissions).'),
            array_slice($problems, 0, 20))];
    }

    private function checkPhpInUploads(): array
    {
        $title = t('PHP files in application/files');
        $root = $this->appDir . '/files';
        if (!is_dir($root)) {
            return [$this->item('php_uploads', $title, self::STATUS_UNKNOWN, t('The directory %s was not found.', 'application/files'), '')];
        }
        // cache — службові файли Concrete; security_guard — наш кеш стану (state.php).
        $skip = [$root . '/cache', $root . '/security_guard'];
        $found = [];
        $scan = $this->scan($root, $skip, function (string $path, \SplFileInfo $f) use (&$found) {
            $name = $f->getFilename();
            if (preg_match('/\.(php\d?|phtml|phar|pht|phps)$/i', $name) || preg_match('/\.(php\d?|phtml|phar)\./i', $name)) {
                $found[] = $this->relative($path);
            }
        });
        $note = $scan['complete'] ? '' : ' ' . t('(partial scan: %s files checked before the time limit)', number_format($scan['entries'], 0, ',', ' '));
        if (!$found) {
            return [$this->item('php_uploads', $title, self::STATUS_OK,
                t('No PHP files found among %s uploaded files.', number_format($scan['entries'], 0, ',', ' ')) . $note, '')];
        }

        return [$this->item('php_uploads', $title, self::STATUS_FAIL,
            t('%s PHP files found in the uploads directory. Uploads must never contain executable code — this is a typical sign of a web shell.', count($found)) . $note,
            t('Download the files for analysis, then delete them, change the passwords and check the access logs for requests to them.'),
            array_slice($found, 0, 25))];
    }

    private function checkWorldWritable(): array
    {
        $title = t('Files writable by everyone');
        if ($this->webRoot === '' || !is_dir($this->webRoot)) {
            return [$this->item('world_writable', $title, self::STATUS_UNKNOWN, t('The web root was not found.'), '')];
        }
        // Завантаження (application/files, десятки тисяч файлів) перевіряє окремий пункт;
        // тут — код і конфігурація сайту.
        $skip = [$this->webRoot . '/application/files', $this->webRoot . '/.git', $this->webRoot . '/node_modules'];
        $found = [];
        $scan = $this->scan($this->webRoot, $skip, function (string $path, \SplFileInfo $f) use (&$found) {
            $perms = @fileperms($path);
            if ($perms !== false && ($perms & 0002) && !is_link($path)) {
                $found[] = $this->relative($path) . ' (' . sprintf('%04o', $perms & 0777) . ')';
            }
        }, true);
        $note = $scan['complete'] ? '' : ' ' . t('(partial scan: %s files checked before the time limit)', number_format($scan['entries'], 0, ',', ' '));
        if (!$found) {
            return [$this->item('world_writable', $title, self::STATUS_OK,
                t('No files or directories with write permission for everyone.') . $note, '',
                $scan['complete'] ? [] : [t('Checked: %s files and directories (application/files excluded).', number_format($scan['entries'], 0, ',', ' '))])];
        }

        return [$this->item('world_writable', $title, self::STATUS_WARN,
            t('%s files or directories can be modified by any user of the server.', count($found)) . $note,
            t('Use 0644 for files and 0755 for directories (0777 is never needed with PHP running as your account).'),
            array_slice($found, 0, 25))];
    }

    private function checkHttpProbes(): array
    {
        $title = t('Sensitive files reachable from the internet');
        if ($this->baseUrl === '') {
            return [$this->item('http_probe', $title, self::STATUS_UNKNOWN, t('The site URL is unknown.'), '')];
        }
        $paths = [
            '/.env' => true,
            '/.git/config' => true,
            '/composer.json' => true,
            '/application/config/database.php' => false,
        ];
        $exposed = [];
        $details = [];
        $unknown = 0;
        $status = self::STATUS_OK;
        foreach ($paths as $path => $bodyMatters) {
            $r = $this->httpGet($this->baseUrl . $path);
            if ($r === null) {
                ++$unknown;
                $details[] = $path . ' — ' . t('no response');
                continue;
            }
            $code = $r['status'];
            $details[] = $path . ' — HTTP ' . $code;
            if ($code === 200) {
                // database.php виконується як PHP і нічого не друкує — порожня відповідь не витік.
                if ($bodyMatters || trim($r['body']) !== '') {
                    $exposed[] = $path;
                    $status = self::STATUS_FAIL;
                } elseif ($status === self::STATUS_OK) {
                    $status = self::STATUS_WARN;
                }
            } elseif ($code >= 300 && $code < 400 && $status === self::STATUS_OK) {
                $status = self::STATUS_WARN;
            }
        }
        if ($unknown === count($paths)) {
            return [$this->item('http_probe', $title, self::STATUS_UNKNOWN,
                t('The server could not reach its own address (%s). Check these URLs from a browser.', $this->baseUrl), '', $details)];
        }
        if ($status === self::STATUS_FAIL) {
            return [$this->item('http_probe', $title, self::STATUS_FAIL,
                t('These files are publicly downloadable: %s', implode(', ', $exposed)),
                t('Delete the files from the web root or deny access in .htaccess (for example: RedirectMatch 404 /\.(env|git)).'), $details)];
        }
        if ($status === self::STATUS_WARN) {
            return [$this->item('http_probe', $title, self::STATUS_WARN,
                t('No content was leaked, but some URLs did not answer 403/404 (redirect or empty 200).'),
                t('Deny direct access to application/config and dot-files in .htaccess so that they answer 403/404.'), $details)];
        }

        return [$this->item('http_probe', $title, self::STATUS_OK, t('All probed files answer 403/404.'), '', $details)];
    }

    private function checkSecurityHeaders(): array
    {
        $title = t('Security headers on the home page');
        if ($this->baseUrl === '') {
            return [$this->item('headers', $title, self::STATUS_UNKNOWN, t('The site URL is unknown.'), '')];
        }
        $r = $this->httpGet($this->baseUrl . '/');
        if ($r === null) {
            return [$this->item('headers', $title, self::STATUS_UNKNOWN, t('The server could not reach its own address (%s).', $this->baseUrl), '')];
        }
        $h = $r['headers'];
        $isHttps = stripos($this->baseUrl, 'https://') === 0;
        $csp = $h['content-security-policy'] ?? '';
        $want = [
            'X-Content-Type-Options' => isset($h['x-content-type-options']) && stripos($h['x-content-type-options'], 'nosniff') !== false,
            'X-Frame-Options' => isset($h['x-frame-options']) || stripos($csp, 'frame-ancestors') !== false,
            'Referrer-Policy' => isset($h['referrer-policy']),
            'Content-Security-Policy' => $csp !== '',
        ];
        if ($isHttps) {
            $want['Strict-Transport-Security'] = isset($h['strict-transport-security']);
        }
        $missing = array_keys(array_filter($want, static function ($ok) {
            return !$ok;
        }));
        $details = [];
        foreach ($want as $name => $ok) {
            $details[] = $name . ': ' . ($ok ? t('present') : t('missing'));
        }
        if (!$missing) {
            return [$this->item('headers', $title, self::STATUS_OK, t('All recommended headers are sent.'), '', $details)];
        }
        $critical = array_intersect($missing, ['X-Content-Type-Options', 'X-Frame-Options', 'Strict-Transport-Security']);

        return [$this->item('headers', $title, $critical ? self::STATUS_WARN : self::STATUS_OK,
            t('Missing: %s', implode(', ', $missing)),
            t('Add the headers in .htaccess with "Header always set …" (mod_headers). Introduce Content-Security-Policy carefully: first as Content-Security-Policy-Report-Only.'),
            $details)];
    }

    private function checkHttps(): array
    {
        $title = t('HTTPS');
        if ($this->baseUrl === '') {
            return [];
        }
        if (stripos($this->baseUrl, 'https://') === 0) {
            return [$this->item('https', $title, self::STATUS_OK, t('The site address uses HTTPS.'), '')];
        }

        return [$this->item('https', $title, self::STATUS_WARN, t('The site address uses plain HTTP: passwords are sent unencrypted.'),
            t('Enable a certificate (cPanel → SSL/TLS Status, AutoSSL) and set the canonical URL to https:// in Dashboard → System & Settings → URLs and Redirection.'))];
    }

    private function checkConcreteVersion(): array
    {
        $config = $this->app->make('config');
        $version = (string) $config->get('concrete.version');
        $installed = (string) $config->get('concrete.version_installed');
        $finding = t('Concrete CMS %s.', $version !== '' ? $version : '?');
        if ($installed !== '' && $version !== '' && version_compare($installed, $version, '<')) {
            return [$this->item('concrete_version', t('Concrete CMS version'), self::STATUS_WARN,
                $finding . ' ' . t('The database is still at %s: the upgrade was not finished.', $installed),
                t('Finish the upgrade in Dashboard → System & Settings → Update Concrete.'))];
        }

        return [$this->item('concrete_version', t('Concrete CMS version'), self::STATUS_OK, $finding,
            t('Check for security releases regularly in Dashboard → System & Settings → Update Concrete.'))];
    }

    private function checkPhpVersion(): array
    {
        $title = t('PHP version');
        $branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
        $eol = self::PHP_EOL[$branch] ?? null;
        $finding = t('PHP %s.', PHP_VERSION);
        if ($eol === null) {
            return [$this->item('php_version', $title, version_compare($branch, '8.0', '<') ? self::STATUS_FAIL : self::STATUS_OK, $finding, '')];
        }
        $eolTs = (int) strtotime($eol . ' 23:59:59');
        if ($eolTs < time()) {
            return [$this->item('php_version', $title, self::STATUS_FAIL,
                $finding . ' ' . t('Security support for PHP %s ended on %s.', $branch, $eol),
                t('Switch to a supported PHP version in cPanel → Select PHP Version (test the site on a copy first).'))];
        }
        if ($eolTs - time() < 120 * 86400) {
            return [$this->item('php_version', $title, self::STATUS_WARN,
                $finding . ' ' . t('Security support for PHP %s ends on %s.', $branch, $eol),
                t('Plan the switch to a newer PHP version (test the site on a copy first).'))];
        }

        return [$this->item('php_version', $title, self::STATUS_OK, $finding . ' ' . t('Supported until %s.', $eol), '')];
    }

    private function checkErrorDisplay(): array
    {
        $title = t('Error details shown to visitors');
        $mode = (string) $this->app->make('config')->get('concrete.error.display.guests');
        if ($mode === 'debug') {
            return [$this->item('debug', $title, self::STATUS_FAIL, t('Visitors see full debug output (paths, code, configuration).'),
                t('Set "Show generic message" for guests in Dashboard → System & Settings → Error Handling.'))];
        }
        if ($mode === 'message' || $mode === '') {
            return [$this->item('debug', $title, self::STATUS_WARN, t('Visitors see the text of error messages, which may reveal internal details.'),
                t('Set "Show generic message" for guests in Dashboard → System & Settings → Error Handling.'))];
        }

        return [$this->item('debug', $title, self::STATUS_OK, t('Visitors see only a generic error message.'), '')];
    }

    private function checkFailedLoginBan(): array
    {
        $title = t('Concrete failed-login IP ban');
        $service = $this->app->make('failed_login');
        $category = $service->getCategory();
        if (!$category->isEnabled()) {
            return [$this->item('failed_login', $title, self::STATUS_WARN, t('The built-in ban after failed logins is disabled.'),
                t('Enable it in Dashboard → System & Settings → Permissions & Access → IP Deny List. Security Guard adds escalation and alerts on top of it.'))];
        }
        $window = (int) $category->getTimeWindow();
        $duration = $category->getBanDuration();

        return [$this->item('failed_login', $title, self::STATUS_OK,
            t('Enabled: %s failed logins within %s s → ban for %s.', (int) $category->getMaxEvents(), $window,
                $duration === null ? t('unlimited time') : t('%s s', (int) $duration)), '')];
    }

    private function checkPageCache(): array
    {
        $title = t('Full page cache');
        $mode = $this->app->make('config')->get('concrete.cache.pages');
        if ($mode === 'all') {
            return [$this->item('page_cache', $title, self::STATUS_OK, t('Enabled for all pages.'), '')];
        }
        if ($mode === 'blocks') {
            return [$this->item('page_cache', $title, self::STATUS_OK, t('Enabled for pages whose blocks allow it.'), '')];
        }

        return [$this->item('page_cache', $title, self::STATUS_WARN,
            t('Disabled: every visit runs PHP and the database, which makes overload (508) under bot traffic more likely.'),
            t('Enable it in Dashboard → System & Settings → Optimization → Cache & Speed Settings.'))];
    }

    /**
     * Хто може відкрити панель: /dashboard/security_guard має перекривати права
     * /dashboard і давати view_page лише адміністраторам (дочірні — успадковувати).
     */
    private function checkPanelAccess(): array
    {
        $title = t('Access to Security Guard pages');
        $root = \Concrete\Core\Page\Page::getByPath('/dashboard/security_guard');
        if (!is_object($root) || $root->isError()) {
            return [$this->item('panel_access', $title, self::STATUS_UNKNOWN, t('The page /dashboard/security_guard was not found.'), '')];
        }
        $problems = [];
        if ($root->getCollectionInheritance() !== 'OVERRIDE') {
            $problems[] = t('/dashboard/security_guard inherits permissions instead of overriding them.');
        }
        $pages = [$root];
        foreach ((array) $root->getCollectionChildren() as $child) {
            if (is_object($child) && !$child->isError() && $child->getCollectionInheritance() === 'OVERRIDE') {
                $pages[] = $child;
            }
        }
        $adminGroup = defined('ADMIN_GROUP_ID') ? (int) ADMIN_GROUP_ID : 3;
        foreach ($pages as $page) {
            foreach ($this->viewPageEntities($page) as [$type, $id, $label]) {
                if ($type === 'group' && $id === $adminGroup) {
                    continue;
                }
                $problems[] = t('%s: view access for %s', (string) $page->getCollectionPath(), $label);
            }
        }
        if (!$problems) {
            return [$this->item('panel_access', $title, self::STATUS_OK, t('Only the Administrators group can open the panel.'), '')];
        }

        return [$this->item('panel_access', $title, self::STATUS_FAIL,
            t('People other than administrators may be able to open the panel (the panel itself still denies them, but the page permissions should be fixed).'),
            t('In Dashboard → Sitemap → /dashboard/security_guard → Permissions, override the parent permissions and give "View" only to Administrators. Reinstalling or upgrading the package does this automatically.'),
            array_slice($problems, 0, 20))];
    }

    /** @return array<int, array{0: string, 1: int, 2: string}> тип сутності, id групи (0 — не група), назва */
    private function viewPageEntities($page): array
    {
        $out = [];
        $pk = \Concrete\Core\Permission\Key\Key::getByHandle('view_page');
        if (!is_object($pk)) {
            return $out;
        }
        $pk->setPermissionObject($page);
        $pa = $pk->getPermissionAccessObject();
        if (!is_object($pa)) {
            return $out;
        }
        foreach ((array) $pa->getAccessListItems(\Concrete\Core\Permission\Key\Key::ACCESS_TYPE_INCLUDE) as $item) {
            $e = $item->getAccessEntityObject();
            if (!is_object($e)) {
                continue;
            }
            $type = (string) $e->getAccessEntityTypeHandle();
            $gid = 0;
            if ($type === 'group' && method_exists($e, 'getGroupObject') && is_object($e->getGroupObject())) {
                $gid = (int) $e->getGroupObject()->getGroupID();
            }
            $out[] = [$type, $gid, strip_tags((string) $e->getAccessEntityLabel())];
        }

        return $out;
    }

    private function checkClientIp(): array
    {
        $title = t('Visitor IP detection');
        $ip = $this->clientIp;
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return [$this->item('client_ip', $title, self::STATUS_UNKNOWN, t('The IP address of this request is unknown.'), '')];
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return [$this->item('client_ip', $title, self::STATUS_WARN,
                t('Your request arrived from %s, a loopback or private address. If visitors also appear with such addresses, a proxy or load balancer hides their real IP: loopback is always trusted and every visitor would share one IP, so the firewall is effectively off.', $ip),
                t('On a real hosting set the proxy addresses in Dashboard → System & Settings → Permissions & Access → Trusted Proxies (or enable the Cloudflare option). On a local copy this warning is expected.'))];
        }

        return [$this->item('client_ip', $title, self::STATUS_OK, t('Your request arrived from the public address %s.', $ip), '')];
    }

    private function checkPcreJit(): array
    {
        $title = t('PCRE JIT for the attack signatures');
        $jit = ini_get('pcre.jit');
        $ok = @preg_match('/(?:union\s+select|<script)/i', str_repeat('a', 20000) . ' union  select');
        $err = preg_last_error();
        if ($ok === false || $err !== PREG_NO_ERROR) {
            return [$this->item('pcre_jit', $title, self::STATUS_WARN,
                t('A test regular expression failed (%s): signature checks may silently skip long requests.', function_exists('preg_last_error_msg') ? preg_last_error_msg() : (string) $err),
                t('Ask the hosting to enable pcre.jit and raise pcre.backtrack_limit, or select a newer PHP version.'))];
        }
        if ($jit === '0' || $jit === '' || $jit === false) {
            return [$this->item('pcre_jit', $title, self::STATUS_WARN, t('pcre.jit is disabled: signatures run several times slower.'),
                t('Enable pcre.jit in cPanel → Select PHP Version → Options (or ask the hosting).'))];
        }

        return [$this->item('pcre_jit', $title, self::STATUS_OK, t('pcre.jit is enabled.'), '')];
    }

    private function checkApcu(): array
    {
        $title = t('APCu for rate counters');
        $on = function_exists('apcu_enabled') ? (bool) @apcu_enabled() : false;
        if ($on) {
            return [$this->item('apcu', $title, self::STATUS_OK, t('APCu is available: request counters are kept in memory.'), '')];
        }

        return [$this->item('apcu', $title, self::STATUS_WARN,
            t('APCu is not available: rate limits and spike detection use file counters, which is slower under heavy traffic.'),
            t('Enable the apcu extension in cPanel → Select PHP Version → Extensions, if the hosting offers it.'))];
    }

    private function checkRegistration(): array
    {
        $title = t('Public registration');
        $config = $this->app->make('config');
        $enabled = (bool) $config->get('concrete.user.registration.enabled');
        $type = (string) $config->get('concrete.user.registration.type');
        // Так само, як вирішує WAF (GuardMiddleware::publicRegistrationOpen()).
        if (!$enabled && ($type === 'disabled' || $type === '')) {
            return [$this->item('registration', $title, self::STATUS_OK, t('Public registration is disabled.'), '')];
        }

        return [$this->item('registration', $title, self::STATUS_WARN,
            t('Anyone can create an account (%s). Because of that Security Guard does not trust ordinary signed-in users on Concrete service paths (/ccm/): otherwise registering would be enough to skip the checks. Only administrators keep the bypass, so editors without the Administrators group may see false positives there.', $type !== '' ? $type : 'enabled'),
            t('If the site does not need visitor accounts, disable registration in Dashboard → System & Settings → Login & Registration → Public Registration; otherwise require e-mail validation or manual approval.'))];
    }

    // ------------------------------------------------------------- допоміжні

    /**
     * Обмежений обхід каталогу (без символьних посилань).
     *
     * @return array{entries: int, complete: bool}
     */
    private function scan(string $root, array $skip, callable $visit, bool $includeDirs = false): array
    {
        $deadline = microtime(true) + self::SCAN_SECONDS;
        $entries = 0;
        $complete = true;
        try {
            $dirIt = new RecursiveDirectoryIterator($root, RecursiveDirectoryIterator::SKIP_DOTS);
            $filter = new RecursiveCallbackFilterIterator($dirIt, static function (\SplFileInfo $f) use ($skip) {
                if ($f->isLink()) {
                    return false;
                }
                $p = $f->getPathname();
                foreach ($skip as $s) {
                    if ($p === $s || strpos($p, $s . '/') === 0) {
                        return false;
                    }
                }

                return true;
            });
            $it = new RecursiveIteratorIterator($filter, $includeDirs ? RecursiveIteratorIterator::SELF_FIRST : RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD);
            foreach ($it as $path => $f) {
                ++$entries;
                $visit((string) $path, $f);
                if ($entries >= self::SCAN_MAX_ENTRIES || ($entries % 500 === 0 && microtime(true) > $deadline)) {
                    $complete = false;
                    break;
                }
            }
        } catch (Throwable $e) {
            $complete = false;
        }

        return ['entries' => $entries, 'complete' => $complete];
    }

    /**
     * GET на власну адресу сайту (лише цей хост, без переходів за редиректами).
     *
     * @return array{status: int, headers: array<string,string>, body: string}|null
     */
    private function httpGet(string $url): ?array
    {
        $baseHost = parse_url($this->baseUrl, PHP_URL_HOST);
        if (!$baseHost || parse_url($url, PHP_URL_HOST) !== $baseHost) {
            return null;
        }
        try {
            $client = $this->app->make('http/client');
            $response = $client->request('GET', $url, [
                'timeout' => self::HTTP_TIMEOUT,
                'connect_timeout' => 3,
                'http_errors' => false,
                'allow_redirects' => false,
                'headers' => [
                    'User-Agent' => 'Mozilla/5.0 (compatible; SecurityGuardSelfCheck/1.0)',
                    \PasichDev\SecurityGuard\Http\SelfProbe::HEADER => \PasichDev\SecurityGuard\Http\SelfProbe::headerFor('GET', $url),
                ],
            ]);
            $headers = [];
            foreach ($response->getHeaders() as $name => $values) {
                $headers[strtolower((string) $name)] = implode(', ', $values);
            }
            $body = (string) $response->getBody()->read(2048);

            return ['status' => (int) $response->getStatusCode(), 'headers' => $headers, 'body' => $body];
        } catch (Throwable $e) {
            return null;
        }
    }

    private function relative(string $path): string
    {
        if ($this->webRoot !== '' && strpos($path, $this->webRoot . '/') === 0) {
            return substr($path, strlen($this->webRoot) + 1);
        }

        return $path;
    }
}
