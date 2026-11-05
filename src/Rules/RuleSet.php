<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Rules;

use PasichDev\SecurityGuard\Config\Settings;

/**
 * Сигнатури атак. Чистий PHP без залежностей від Concrete: його використовують
 * і WAF на запиті, і розбір логів хостингу. СИГНАТУРИ ПУБЛІЧНИХ МЕТОДІВ — КОНТРАКТ
 * (не змінювати); тіла реалізує частина «engine».
 *
 * Результат класифікації: ['rule' => 'SQL_UNION', 'category' => 'injection', 'strength' => 'strong'|'weak'].
 * 'weak' — слабка ознака (буває і в звичайному тексті): WAF лише журналює її
 * й додає бали поведінки, без відмови; аналітика логів може її пропускати.
 * Категорії — див. EventLogInterface.
 */
final class RuleSet
{
    /** Скільки байтів тіла POST максимум скануємо (ліміти CPU на хостингу). */
    public const MAX_BODY_BYTES = 65536;

    /** Розширення, які PHP виконує. */
    private const PHP_EXT = '(?:php[0-9]?|phtml|phar|pht|phps)';

    /**
     * Правила за шляхом: [налаштування-перемикач, код, категорія, regex].
     * Шлях уже декодований і в нижньому регістрі.
     */
    private const PATH_RULES = [
        // Concrete: внутрішні файли ядра, старі /tools/, установник, файли версії.
        ['rules_concrete', 'CONCRETE_TOOLS', 'concrete', '#^/(?:index\.php/)?tools/(?:required|packages|blocks)(?:/|$)|^/index\.php/tools/|^/(?:updates/[^/]+/)?concrete/tools/#'],
        ['rules_concrete', 'CONCRETE_INTERNALS', 'concrete', '#^/(?:updates/[^/]+/)?concrete/(?:src|vendor|bootstrap|config|controllers|jobs|bin|routes|single_pages|views|mail|geolocation)(?:/|$)|^/(?:updates/[^/]+/)?concrete/.*\.' . self::PHP_EXT . '(?:/|$)|^/updates(?:/[^/]*)?/?$|^/updates/.*\.(?:php\d?|json|lock|md|txt|xml|ya?ml|sql|log|dist)$#'],
        ['rules_concrete', 'CONCRETE_APP_INTERNALS', 'concrete', '#^/application/(?:src|bootstrap|controllers|jobs)(?:/|$)|^/application/(?:elements|blocks|single_pages|views|authentication|attributes|mail|languages|themes|page_templates|tools)/.*\.' . self::PHP_EXT . '(?:/|$)#'],
        ['rules_concrete', 'CONCRETE_INSTALL', 'concrete', '#^/(?:index\.php/)?install(?:/|$)#'],
        ['rules_concrete', 'CONCRETE_FINGERPRINT', 'concrete', '#^/(?:updates/[^/]+/)?concrete/(?:composer\.(?:json|lock)|package(?:-lock)?\.json|(?:.*/)?(?:changelog|readme|license|upgrade)(?:\.[a-z]+)?|.*\.md)$|^/(?:readme|changelog)(?:\.[a-z]+)?$#'],

        // WordPress-пробінг: на цьому сайті WordPress немає.
        ['rules_wordpress_probes', 'WP_LOGIN', 'wordpress', '#/wp-login\.php#'],
        ['rules_wordpress_probes', 'WP_XMLRPC', 'wordpress', '#/xmlrpc\.php#'],
        ['rules_wordpress_probes', 'WP_CONFIG', 'wordpress', '#/wp-config#'],
        ['rules_wordpress_probes', 'WP_ADMIN', 'wordpress', '#/wp-admin(?:/|\.php|$)#'],
        ['rules_wordpress_probes', 'WP_PATH', 'wordpress', '#/wp-(?:content|includes|json|cron\.php|signup\.php|trackback|links-opml\.php|load\.php|mail\.php|settings\.php|activate\.php|blog-header\.php)#'],
        ['rules_wordpress_probes', 'WP_DIR', 'wordpress', '#^/wordpress(?:/|$)#'],

        // Чутливі файли.
        ['rules_sensitive_files', 'ENV_FILE', 'secrets', '#/\.env(?:[./_-]|$)#'],
        ['rules_sensitive_files', 'VCS_DIR', 'secrets', '#/\.(?:git|svn|hg|bzr)(?:/|$)#'],
        ['rules_sensitive_files', 'DOTFILE', 'secrets', '#/\.(?:htpasswd|htaccess|ds_store|aws|ssh|bash_history|npmrc|dockerenv|vscode|idea|ftpconfig|user\.ini)(?:/|$)|/(?:sftp-config|\.remote-sync)\.json$#'],
        ['rules_sensitive_files', 'MANIFEST_FILE', 'secrets', '#/(?:composer\.(?:json|lock)|package(?:-lock)?\.json|yarn\.lock|docker-compose\.ya?ml|dockerfile)$#'],
        ['rules_sensitive_files', 'CONFIG_BACKUP', 'secrets', '#/(?:configuration|config|settings|database|db|wp-config|local)\.php(?:[.~_-]\w*|~)$#'],
        ['rules_sensitive_files', 'CONCRETE_CONFIG', 'secrets', '#^/application/(?:config|logs)/#'],
        ['rules_sensitive_files', 'LOG_FILE', 'secrets', '#/(?:error_log|php_errors?\.log|debug\.log)$#'],
        ['rules_sensitive_files', 'DB_ADMIN', 'secrets', '#^/(?:phpmyadmin[\w.-]*|pma|myadmin|dbadmin|mysqladmin|sqladmin|db/phpmyadmin)(?:/|$|\.php)|/adminer[\w.-]*\.php#'],

        // Joomla: лише точкові експлойт-шляхи, не звичайні /index.php?option=...
        ['rules_joomla_exploits', 'JOOMLA_ADMIN_PROBE', 'joomla', '#^/administrator(?:/|$)#'],
        ['rules_joomla_exploits', 'JOOMLA_API_LEAK', 'joomla', '#^/api/(?:index\.php/)?v1/(?:config|users)#'],
        ['rules_joomla_exploits', 'JOOMLA_DIRECT_PHP', 'joomla', '#^/(?:components|modules|plugins|libraries|templates)/.+\.' . self::PHP_EXT . '(?:/|$)#'],
        ['rules_joomla_exploits', 'JOOMLA_FINGERPRINT', 'joomla', '#^/(?:language/en-gb/en-gb\.xml|htaccess\.txt|web\.config\.txt|joomla\.xml)$#'],

        // Веб-шелли.
        ['rules_webshells', 'PHPUNIT_RCE', 'shells', '#/vendor/phpunit/|/eval-stdin\.php#'],
        ['rules_webshells', 'WEBSHELL_NAME', 'shells', '#/(?:zwso|wso\d*|xxx|alfa[\w-]*|c99|c100|r57|shell\w*|webshell|cmd|up|upl|uploader|bypass|backdoor|b374k|indoxploit|marijuana|mini|tiny|zoro|cxs|asdf|bajah|coffexium|wm|ss|jga|177|crelm|gel|colorpicker|leaf|leaves|woolen|smtp|admin0|administrar|payload|xstelth|lock360|chosen|gecko|moon|radio|inputs|sx|ws|xl|ty|wp|about|0|1|404|403|x|ok|lol)\.' . self::PHP_EXT . '$#'],
        ['rules_webshells', 'KNOWN_SHELL', 'shells', '#/(?:acac513|filefuls|toggige|950950|452452)#'],
        ['rules_webshells', 'HEX_PHP', 'shells', '#/[a-f0-9]{8,}\.' . self::PHP_EXT . '$#'],
        ['rules_webshells', 'PHP_IN_UPLOADS', 'shells', '#^/(?:application/files|files|uploads|images|media|tmp|cache|logs)/.*\.' . self::PHP_EXT . '(?:/|$)#'],
        ['rules_webshells', 'DOUBLE_EXTENSION', 'shells', '#\.(?:jpe?g|png|gif|webp|pdf|txt|docx?|zip)\.' . self::PHP_EXT . '$#'],
        ['rules_webshells', 'PHP_ALT_EXT', 'shells', '#\.(?:phtml|phar|pht|phps|php[3-8])$#'],

        // Обхід каталогів у шляху (браузер нормалізує ../ сам, тож це завжди скрипт).
        ['rules_path_traversal', 'PATH_TRAVERSAL', 'traversal', '#\.\./#'],
        ['rules_path_traversal', 'ETC_PASSWD', 'traversal', '#/etc/(?:passwd|shadow|hosts)|/proc/self/|win\.ini|boot\.ini#'],

        // Інші відомі сканерні адреси.
        ['rules_code_exec', 'CGI_PROBE', 'scanner', '#^/cgi-bin/#'],
        ['rules_code_exec', 'APP_PROBE', 'scanner', '#^/(?:boaform|hnap1|actuator|solr|druid|telescope|_ignition|manager/html|geoserver|owa/auth|remote/login|vpn/|dana-na|global-protect|sslvpn)(?:/|$)#'],
        ['rules_code_exec', 'PHPINFO_PROBE', 'scanner', '#^/(?:phpinfo|info|test|i|php_info|pinfo)\.php$#'],
    ];

    /**
     * Правила для декодованого query, тіла і сегментів шляху:
     * [перемикач, код, категорія, regex, сила в query, сила в тілі].
     * Сила: 'S' — справжній синтаксис атаки (бан), 'W' — слабка ознака (лише
     * журнал і бали поведінки, без відмови), null — не перевіряти.
     * Усі квантифікатори обмежені ({0,N}) — без катастрофічного backtracking
     * навіть без PCRE JIT.
     */
    private const PAYLOAD_RULES = [
        ['rules_sql_injection', 'SQL_UNION', 'injection', '#\bunion(?:\s|\(|\)){1,20}(?:(?:all|distinct)(?:\s|\(){1,20})?select\b(?:\s|\(){1,20}(?:null\b|\d|0x|@@|\*|[\'"`]|concat|char\s{0,3}\(|[a-z_][\w.]{0,40}(?:\s{0,5},|\s{1,5}from\b))#i', 'S', 'S'],
        ['rules_sql_injection', 'SQL_UNION', 'injection', '#\bunion\s{1,10}(?:all\s{1,10})?select\b#i', 'W', 'W'],
        ['rules_sql_injection', 'SQL_SLEEP', 'injection', '#(?:[\'"`)]|\b(?:and|or|xor|select|where|if|case|when|then)\b|[;|&])\s{0,10}\(?\s{0,10}(?:sleep|benchmark|pg_sleep)\s{0,10}\(\s{0,10}\d{1,9}(?:\.\d{1,6})?\s{0,10}[,)]|\bwaitfor\s{1,10}delay\s{1,10}\'#i', 'S', 'S'],
        ['rules_sql_injection', 'SQL_TAUTOLOGY', 'injection', '#[\'"`)]\s{0,10}(?:or|and|\|\||&&)\s{1,10}[\'"(]?(\w{1,20})[\'"]?\s{0,10}=\s{0,10}[\'"(]?\1\b|\b(?:or|and)\s{1,10}\d{1,10}\s{0,10}=\s{0,10}\d{1,10}\s{0,10}(?:--|\#|/\*)#i', 'S', 'W'],
        ['rules_sql_injection', 'SQL_SCHEMA', 'injection', '#\binformation_schema\b|@@version\b|\bload_file\s{0,5}\(|\binto\s{1,10}(?:out|dump)file\b|\b(?:extractvalue|updatexml)\s{0,5}\(|\bgroup_concat\s{0,5}\(|\bconcat(?:_ws)?\s{0,5}\(\s{0,5}0x#i', 'S', 'S'],

        ['rules_xss', 'XSS_SCRIPT', 'xss', '#<\s{0,5}/?\s{0,5}script\b#i', 'S', 'W'],
        ['rules_xss', 'XSS_HANDLER', 'xss', '#<[a-z][a-z0-9]{0,15}\b[^>]{0,300}?[\s/"\']on[a-z]{3,25}\s{0,5}=#i', 'S', 'S'],
        ['rules_xss', 'XSS_TAG', 'xss', '#<\s{0,5}(?:iframe|svg|object|embed|math|base|meta)\b#i', 'S', null],
        ['rules_xss', 'XSS_JS_URI', 'xss', '#(?:^|[=\'"(\s])(?:java|vb)script\s{0,5}:#i', 'W', null],
        ['rules_xss', 'XSS_DOM', 'xss', '#\bdocument\.(?:cookie|domain|write)\b|\bstring\.fromcharcode\s{0,5}\(|\b(?:alert|prompt|confirm)\s{0,5}\(\s{0,5}(?:\d|document|[\'"`])#i', 'W', null],

        ['rules_path_traversal', 'PATH_TRAVERSAL', 'traversal', '#(?:\.\.[/\\\\]){2,}#', 'S', 'S'],
        ['rules_path_traversal', 'PATH_TRAVERSAL', 'traversal', '#\.\.[/\\\\]#', 'W', null],
        ['rules_path_traversal', 'ETC_PASSWD', 'traversal', '#/etc/(?:passwd|shadow)|/proc/self/(?:environ|cmdline)|c:\\\\windows\\\\|win\.ini|boot\.ini#i', 'S', 'S'],

        ['rules_code_exec', 'CODE_EXEC', 'injection', '#\b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|base64_decode|gzinflate|gzuncompress|str_rot13|create_function|call_user_func(?:_array)?|file_put_contents|file_get_contents|fwrite|include|require)\s{0,5}\(\s{0,5}(?:[\'"`$]|chr\s{0,3}\(|base64_decode|gzinflate|str_rot13)|\bphpinfo\s{0,5}\(\s{0,5}\)#i', 'S', 'S'],
        ['rules_code_exec', 'PHP_TAG', 'injection', '#<\?(?:php\b|=)#i', 'S', 'W'],
        ['rules_code_exec', 'PHP_WRAPPER', 'injection', '#\b(?:php://(?:input|filter|fd|memory|temp|stdin)|expect://|phar://|zip://|glob://|data://(?:text|application|image)/[\w+.-]{1,40}[;,])#i', 'S', null],
        ['rules_code_exec', 'PHP_INI_INJECTION', 'injection', '#\b(?:allow_url_include|auto_prepend_file|auto_append_file)\s{0,3}=#i', 'S', null],
        ['rules_code_exec', 'LOG4SHELL', 'injection', '#\$\{\s{0,5}(?:jndi|\$\{|lower:|upper:|env:)#i', 'S', 'S'],
        ['rules_code_exec', 'PHP_OBJECT_INJECTION', 'injection', Signatures::PHP_OBJECT, 'S', 'S'],
        ['rules_code_exec', 'XXE', 'injection', Signatures::XXE, 'S', 'S'],
        ['rules_code_exec', 'SSRF_TARGET', 'injection', Signatures::SSRF_PARAM, 'S', 'W'],
        ['rules_code_exec', 'SSRF_TARGET', 'injection', Signatures::SSRF, 'W', 'W'],
        ['rules_code_exec', 'CMD_INJECTION', 'injection', '#(?:[;|`]|&&|\$\()\s{0,5}(?:cat\s{1,5}/|id\s{0,5}(?:[;|`&)]|$)|uname\s{1,5}-|whoami\b|(?:wget|curl)\s{1,5}(?:-[\w-]{1,20}\s{1,5}){0,5}(?:https?|ftp)://|(?:ba)?sh\s{1,5}-c\b|nc(?:at)?\s{1,5}-[elvnp]|chmod\s{1,5}[0-7+]|rm\s{1,5}-rf)#i', 'S', 'W'],
    ];

    private const UA_SCANNERS = '#sqlmap|nikto|nmap|masscan|nessus|whatweb|skipfish|acunetix|netsparker|qualys|w3af|zgrab|nuclei|wpscan|joomscan|dirbuster|gobuster|\bffuf\b|feroxbuster|wfuzz|hydra|jaeles|zmeu|morfeus|absinthe|jaascois|jcefilebrowser|joomla-scanner|commix|xsstrike|openvas|arachni|\blmao\b|mozlila|mozila/|mozzila|\(\)\s*\{|\$\{jndi#i';

    private const UA_HTTP_LIBS = '#^(?:curl|wget|python-requests|python-urllib\d?|python-httpx|python/|go-http-client|java|okhttp|apache-httpclient|node-fetch|axios|aiohttp|guzzlehttp|guzzle|php|libwww-perl|lwp-\w+|ruby|perl|winhttp|powershell|httpie|undici|reqwest|http\.rb)(?:[/ ]|$)#i';

    private const UA_AI_CRAWLERS = '#GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-User|Claude-SearchBot|anthropic-ai|CCBot|PerplexityBot|Perplexity-User|Bytespider|Amazonbot|meta-externalagent|meta-externalfetcher|FacebookBot|Diffbot|cohere-ai|cohere-training-data-crawler|YouBot|Timpibot|omgili|ImagesiftBot|PetalBot|DeepSeekBot|AI2Bot|MistralAI-User|DuckAssistBot|Kangaroo Bot|Webzio-Extended|Scrapy#i';

    /** Joomla-компоненти, для яких БУДЬ-ЯКЕ task/plugin — експлойт (на сайті їх не було й немає). */
    private const JOOMLA_EXPLOIT_COMPONENTS = [
        'com_jce' => 'JOOMLA_JCE',
        'com_sppagebuilder' => 'JOOMLA_SPPAGEBUILDER',
        'com_rsfiles' => 'JOOMLA_RSFILES',
        'com_gridbox' => 'JOOMLA_GRIDBOX',
        'com_fabrik' => 'JOOMLA_FABRIK',
        'com_media' => 'JOOMLA_MEDIA',
        'com_installer' => 'JOOMLA_INSTALLER',
        'com_config' => 'JOOMLA_CONFIG',
        'com_joomlaupdate' => 'JOOMLA_UPDATE',
        'com_akeeba' => 'JOOMLA_AKEEBA',
        'com_adsmanager' => 'JOOMLA_ADSMANAGER',
        'com_hdflvplayer' => 'JOOMLA_HDFLV',
        'com_jdownloads' => 'JOOMLA_JDOWNLOADS',
        'com_foxcontact' => 'JOOMLA_FOXCONTACT',
    ];

    /** @var array<string, mixed> */
    private $settings;

    /** @param array<string, mixed> $settings Settings::all() або Settings::DEFAULTS */
    public function __construct(array $settings = Settings::DEFAULTS)
    {
        $this->settings = $settings + Settings::DEFAULTS;
    }

    /**
     * Класифікує запит за URI (шлях + query, як у рядку запиту), User-Agent і,
     * опційно, тілом POST. null — запит не схожий на атаку.
     *
     * Тіло: сирий application/x-www-form-urlencoded або текст (декодується один
     * раз). Чи сканувати тіло на службових шляхах (дашборд, /ccm/), вирішує
     * той, хто викликає: WAF не передає тіло від тих, хто увійшов.
     */
    public function classifyRequest(string $method, string $uri, string $userAgent, string $body = ''): ?array
    {
        [$rawPath, $rawQuery] = Paths::split($uri);
        $path = Paths::normalize($rawPath);
        $weak = null;

        foreach (self::PATH_RULES as [$toggle, $rule, $category, $regex]) {
            if ($this->on($toggle) && preg_match($regex, $path)) {
                return ['rule' => $rule, 'category' => $category, 'strength' => 'strong'];
            }
        }
        // Сегменти шляху: Concrete передає їх у дії контролерів як параметри
        // (/novyny/1' union select…). Лише сильні сигнатури — щоб не чіпати слаги.
        if (strpbrk($path, "'\"<>()$;|`{") !== false) {
            $hit = $this->payload($this->prepare($path), 0);
            if ($hit !== null && $hit['strength'] === 'strong') {
                return $hit;
            }
        }

        if ($rawQuery !== '') {
            if ($this->on('rules_joomla_exploits') && ($hit = $this->joomlaQuery($rawQuery)) !== null) {
                return $hit + ['strength' => 'strong'];
            }
            if ($this->on('rules_wordpress_probes') && preg_match('#(?:^|&)rest_route=(?:%2f|/)wp/#i', $rawQuery)) {
                return ['rule' => 'WP_REST', 'category' => 'wordpress', 'strength' => 'strong'];
            }
            $hit = $this->payload($this->prepare(Paths::decode($rawQuery, true)), 0);
            if ($hit !== null && $hit['strength'] === 'strong') {
                return $hit;
            }
            $weak = $weak ?? $hit;
        }

        if ($body !== '' && $this->on('scan_post_body')) {
            $hit = $this->payload($this->prepare(self::decodeBody(substr($body, 0, self::MAX_BODY_BYTES))), 1);
            if ($hit !== null && $hit['strength'] === 'strong') {
                return $hit;
            }
            $weak = $weak ?? $hit;
        }

        if ($userAgent !== '' && ($hit = $this->classifyUserAgent($userAgent)) !== null) {
            return $hit + ['strength' => 'strong'];
        }

        return $weak;
    }

    /** urlencoded → текст; у JSON розкриває \uXXXX і \/ (інакше \u003cscript обходить правила). */
    public static function decodeBody(string $body): string
    {
        if (strpos($body, '%') !== false || strpos($body, '+') !== false) {
            $body = urldecode($body);
        }
        if (strpos($body, '\\') !== false) {
            $decoded = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/', static function (array $m): string {
                $code = hexdec($m[1]);

                return $code < 0x80 ? chr($code) : (string) mb_chr($code, 'UTF-8');
            }, $body);
            if (is_string($decoded)) {
                $body = str_replace(['\\/', '\\"'], ['/', '"'], $decoded);
            }
        }

        return $body;
    }

    /** Лише за User-Agent (сканери, HTTP-бібліотеки, AI-краулери). */
    public function classifyUserAgent(string $userAgent): ?array
    {
        $userAgent = trim($userAgent);
        if ($userAgent === '') {
            return null;
        }
        if ($this->on('rules_bad_user_agents') && preg_match(self::UA_SCANNERS, $userAgent)) {
            return ['rule' => 'BAD_USER_AGENT', 'category' => 'scanner'];
        }
        if ($this->on('rules_ai_crawlers') && preg_match(self::UA_AI_CRAWLERS, $userAgent)) {
            return ['rule' => 'AI_CRAWLER', 'category' => 'ai_crawler'];
        }
        if ($this->on('rules_http_libraries') && preg_match(self::UA_HTTP_LIBS, $userAgent)) {
            return ['rule' => 'HTTP_LIBRARY', 'category' => 'scanner'];
        }

        return null;
    }

    /** Чи є шлях пасткою honeypot (вбудовані + $customUrls). */
    public function isHoneypot(string $path, array $customUrls = []): bool
    {
        [$path] = Paths::split($path);
        $path = Paths::normalize($path);
        foreach (array_merge(HoneypotList::BUILTIN, $customUrls) as $trap) {
            if (is_string($trap) && HoneypotList::matches($path, $trap)) {
                return true;
            }
        }

        return false;
    }

    /** Чи це статичний ресурс (css/js/зображення/шрифти) — без ліміту частоти й скорингу. */
    public static function isStaticPath(string $path): bool
    {
        return (bool) preg_match('/\.(css|js|mjs|map|jpe?g|png|gif|svg|webp|avif|ico|woff2?|ttf|eot|otf|mp4|webm|mp3|pdf|zip)$/i', $path);
    }

    /** Пошукові боти, яких ми перевіряємо rDNS: назва => [regex UA, суфікси хостів]. */
    public static function searchBots(): array
    {
        return [
            'Googlebot' => ['/Googlebot|Google-InspectionTool|AdsBot-Google|Mediapartners-Google/i', ['.googlebot.com', '.google.com', '.googleusercontent.com']],
            'Bingbot' => ['/bingbot|msnbot|BingPreview/i', ['.search.msn.com']],
            'YandexBot' => ['/YandexBot|YandexImages|YandexMobileBot/i', ['.yandex.ru', '.yandex.net', '.yandex.com']],
            'DuckDuckBot' => ['/DuckDuckBot/i', ['.duckduckgo.com']],
            'Applebot' => ['/Applebot/i', ['.applebot.apple.com']],
            'Baiduspider' => ['/Baiduspider/i', ['.baidu.com', '.baidu.jp']],
        ];
    }

    private function on(string $toggle): bool
    {
        // Нові перемикачі, яких ще може не бути в збережених налаштуваннях, — увімкнені.
        if (!array_key_exists($toggle, $this->settings)) {
            return $toggle === 'rules_concrete';
        }

        return !empty($this->settings[$toggle]);
    }

    /**
     * Прибирає SQL-коментарі (інакше union/**\/select обходить regex) і
     * нульові байти. Лінійно (strpos), без regex: '/*a/*a…' не дає
     * квадратичного часу. Вміст «виконуваних» коментарів MySQL /*!…*\/ лишається.
     */
    private function prepare(string $value): string
    {
        $value = str_replace("\0", '', $value);
        if (strpos($value, '/*') === false) {
            return $value;
        }
        $out = '';
        $pos = 0;
        $len = strlen($value);
        while ($pos < $len && ($start = strpos($value, '/*', $pos)) !== false) {
            $out .= substr($value, $pos, $start - $pos) . ' ';
            if (isset($value[$start + 2]) && $value[$start + 2] === '!') {
                $pos = $start + 3;
                while ($pos < $len && ctype_digit($value[$pos])) {
                    $pos++;
                }
                continue; // вміст /*!…*/ — частина запиту
            }
            $end = strpos($value, '*/', $start + 2);
            if ($end === false) {
                // Незакритий коментар: залишок теж перевіряємо (безпечніше для виявлення).
                $pos = $start + 2;
                break;
            }
            $pos = $end + 2;
        }
        $out .= (string) substr($value, $pos);

        return str_replace('*/', ' ', $out);
    }

    /**
     * Перший сильний збіг, інакше перший слабкий. $context: 0 — query/шлях, 1 — тіло.
     * Помилка PCRE в одному правилі не вимикає решту.
     */
    private function payload(string $value, int $context): ?array
    {
        if ($value === '') {
            return null;
        }
        $weak = null;
        foreach (self::PAYLOAD_RULES as $row) {
            [$toggle, $rule, $category, $regex] = $row;
            $strength = $row[4 + $context];
            if ($strength === null || ($strength === 'W' && $weak !== null) || !$this->on($toggle)) {
                continue;
            }
            if (preg_match($regex, $value) === 1) {
                $hit = ['rule' => $rule, 'category' => $category, 'strength' => $strength === 'S' ? 'strong' : 'weak'];
                if ($strength === 'S') {
                    return $hit;
                }
                $weak = $hit;
            }
        }

        return $weak;
    }

    /**
     * Joomla-експлойти — за парами параметрів, а не regex по рядку: порядок
     * параметрів не важить, а option=com_content/com_contact лишаються чистими.
     */
    private function joomlaQuery(string $rawQuery): ?array
    {
        if (stripos($rawQuery, 'com_') === false && stripos($rawQuery, 'task=') === false) {
            return null;
        }
        $params = [];
        parse_str($rawQuery, $params);
        $lower = [];
        foreach ($params as $k => $v) {
            if (is_string($k) && is_scalar($v)) {
                $lower[strtolower($k)] = strtolower(trim((string) $v));
            }
        }
        $option = $lower['option'] ?? '';
        $task = $lower['task'] ?? '';
        $has = static function (string $key) use ($lower): bool {
            return ($lower[$key] ?? '') !== '';
        };
        $hit = static function (string $rule): array {
            return ['rule' => $rule, 'category' => 'joomla'];
        };

        // Імпорт профілю JCE працює й без option.
        if ($task === 'profiles.import') {
            return $hit('JOOMLA_JCE');
        }
        if (strncmp($option, 'com_', 4) !== 0) {
            return null;
        }
        if (isset(self::JOOMLA_EXPLOIT_COMPONENTS[$option])
            && ($task !== '' || $has('plugin') || $has('controller') || ($lower['view'] ?? '') === 'upload')) {
            return $hit(self::JOOMLA_EXPLOIT_COMPONENTS[$option]);
        }
        if ($option === 'com_ajax' && ($has('plugin') || $has('module') || $has('action') || $has('astroid') || $task !== '')) {
            return $hit('JOOMLA_COM_AJAX');
        }
        if ($option === 'com_users' && preg_match('#^(?:user|registration)\.(?:register|activate)$#', $task)) {
            return $hit('JOOMLA_USER_REGISTER');
        }
        // Будь-який інший компонент із «небезпечним» task (завантаження, імпорт, встановлення, RPC).
        if ($task !== '' && preg_match('#upload|import|install|\brpc\b|\.rpc|unzip|extract#', $task)) {
            return $hit('JOOMLA_EXPLOIT_TASK');
        }

        return null;
    }
}
