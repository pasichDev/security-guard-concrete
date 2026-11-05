<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace PasichDev\SecurityGuard\Config;

use Concrete\Core\Package\PackageService;

/**
 * Єдине джерело правди про налаштування пакета: ключі, типи й значення
 * за замовчуванням. Зберігаються в БД-конфігу пакета (namespace
 * security_guard, група "settings"). Гарячий шлях НЕ читає їх звідси —
 * вони потрапляють у файл-кеш стану (StateCacheInterface::rebuild()).
 *
 * Додаючи ключ: додайте його в DEFAULTS і в GROUPS (для сторінки налаштувань).
 */
final class Settings
{
    public const MODE_MONITOR = 'monitor';
    public const MODE_ENFORCE = 'enforce';

    public const DEFAULTS = [
        // Загальне
        'enabled' => true,
        'mode' => self::MODE_MONITOR,          // monitor | enforce
        'response_code' => 403,                 // 403 | 404 | 410
        'bypass_token' => '',                   // ?sg_pass=<token>; порожнє = вимкнено
        'log_events' => true,
        'event_retention_days' => 90,
        'event_log_throttle_seconds' => 60,     // однакові (ip+rule) події не частіше
        'notify_emails' => '',                  // через кому
        'notify_throttle_minutes' => 15,

        // Довіра
        'whitelist_ranges' => '',               // рядки: IP, префікс "1.2.3." або CIDR
        'trust_admin_ip' => true,
        'trust_admin_days' => 7,
        'trust_cloudflare' => false,

        // Блокування
        'block_duration' => 3600,               // перший бан, секунд
        'escalation' => [3600, 86400, 604800, 2592000],

        // Сигнатури
        'rules_sql_injection' => true,
        'rules_xss' => true,
        'rules_path_traversal' => true,
        'rules_code_exec' => true,
        'rules_joomla_exploits' => true,
        'rules_wordpress_probes' => true,
        'rules_webshells' => true,
        'rules_sensitive_files' => true,
        'rules_bad_user_agents' => true,
        'rules_http_libraries' => false,        // curl/wget/python-requests (може зачепити моніторинги)
        'rules_ai_crawlers' => true,
        'rules_concrete' => true,               // експлойти й пробінг Concrete CMS (анонімний доступ до /ccm/system, /tools, ін'єкції об'єктів, XXE, SSRF)
        'scan_post_body' => true,               // лише фронтенд, не дашборд

        // Боти
        'verify_search_bots' => true,           // rDNS + прямий DNS
        'block_fake_bots' => true,

        // Honeypot
        'honeypot_enabled' => true,
        'honeypot_custom_urls' => '',

        // Частота / сплески
        'rate_limit_enabled' => true,
        'rate_limit_requests' => 120,
        'rate_limit_window' => 60,
        'php_probe_enabled' => true,
        'php_probe_threshold' => 5,
        'php_probe_window' => 10,

        // Поведінка
        'behavior_scoring' => true,
        'behavior_threshold' => 25,
        'behavior_ttl' => 3600,

        // Вхід
        'bruteforce_enabled' => true,
        'bruteforce_threshold' => 5,
        'bruteforce_window' => 900,
        'notify_admin_new_ip' => true,

        // DDoS
        'ddos_enabled' => true,
        'ddos_multiplier' => 5,
        'ddos_min_requests' => 300,             // за хвилину
        'ddos_auto_block' => false,

        // Гео
        'geo_lookup' => true,
        'geo_block_countries' => '',            // ISO-коди через кому

        // Логи хостингу
        'log_root' => '',                       // корінь акаунта хостингу (де access-logs/ і logs/); порожнє = автовизначення
        'log_sources' => '',                    // рядки шляхів/глобів; порожнє = автовизначення
        'log_exclude_ips' => '',                // IP адміністраторів, які не рахувати в статистиці
        'log_ingest_time_budget' => 20,         // секунд на один запуск із браузера
        'host_waf_detect' => true,              // розпізнавати 403 фаєрвола хостингу в логах
        'host_waf_sizes' => '',                 // розміри відповіді 403 хостингу через кому; порожнє = визначати автоматично

        // Оновлення
        'bot_ranges_auto_update' => true,       // security-guard:update-ranges тягне офіційні діапазони ботів
    ];

    /** Групи для сторінки налаштувань: назва групи => ключі. */
    public const GROUPS = [
        'General' => ['enabled', 'mode', 'response_code', 'bypass_token', 'log_events', 'event_retention_days', 'event_log_throttle_seconds', 'notify_emails', 'notify_throttle_minutes'],
        'Trust' => ['whitelist_ranges', 'trust_admin_ip', 'trust_admin_days', 'trust_cloudflare'],
        'Blocking' => ['block_duration', 'escalation'],
        'Signatures' => ['rules_sql_injection', 'rules_xss', 'rules_path_traversal', 'rules_code_exec', 'rules_joomla_exploits', 'rules_wordpress_probes', 'rules_webshells', 'rules_sensitive_files', 'rules_bad_user_agents', 'rules_http_libraries', 'rules_ai_crawlers', 'rules_concrete', 'scan_post_body'],
        'Bots' => ['verify_search_bots', 'block_fake_bots'],
        'Honeypot' => ['honeypot_enabled', 'honeypot_custom_urls'],
        'Rate limiting' => ['rate_limit_enabled', 'rate_limit_requests', 'rate_limit_window', 'php_probe_enabled', 'php_probe_threshold', 'php_probe_window'],
        'Behaviour' => ['behavior_scoring', 'behavior_threshold', 'behavior_ttl'],
        'Login' => ['bruteforce_enabled', 'bruteforce_threshold', 'bruteforce_window', 'notify_admin_new_ip'],
        'DDoS' => ['ddos_enabled', 'ddos_multiplier', 'ddos_min_requests', 'ddos_auto_block'],
        'Geo' => ['geo_lookup', 'geo_block_countries'],
        'Hosting logs' => ['log_root', 'log_sources', 'log_exclude_ips', 'log_ingest_time_budget', 'host_waf_detect', 'host_waf_sizes'],
        'Updates' => ['bot_ranges_auto_update'],
    ];

    private $config;

    public function __construct(PackageService $packages)
    {
        $pkg = $packages->getClass('security_guard');
        $this->config = $pkg->getConfig();
    }

    /** @return mixed */
    public function get(string $key)
    {
        if (!array_key_exists($key, self::DEFAULTS)) {
            throw new \InvalidArgumentException('Unknown Security Guard setting: ' . $key);
        }
        $value = $this->config->get('settings.' . $key);

        return $value === null ? self::DEFAULTS[$key] : $value;
    }

    public function all(): array
    {
        $out = [];
        foreach (array_keys(self::DEFAULTS) as $key) {
            $out[$key] = $this->get($key);
        }

        return $out;
    }

    /** Зберігає значення, приводячи до типу значення за замовчуванням. */
    public function set(string $key, $value): void
    {
        if (!array_key_exists($key, self::DEFAULTS)) {
            throw new \InvalidArgumentException('Unknown Security Guard setting: ' . $key);
        }
        $default = self::DEFAULTS[$key];
        if (is_bool($default)) {
            $value = (bool) $value;
        } elseif (is_int($default)) {
            $value = (int) $value;
        } elseif (is_array($default)) {
            $value = array_values(array_map('intval', (array) $value));
        } else {
            $value = trim((string) $value);
        }
        if ($key === 'mode' && !in_array($value, [self::MODE_MONITOR, self::MODE_ENFORCE], true)) {
            $value = self::MODE_MONITOR;
        }
        $this->config->save('settings.' . $key, $value);
    }

    public function isEnforcing(): bool
    {
        return $this->get('enabled') && $this->get('mode') === self::MODE_ENFORCE;
    }
}
