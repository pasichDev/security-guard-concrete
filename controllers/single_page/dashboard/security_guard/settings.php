<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard;

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\BaseController;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\IpRange;
use PasichDev\SecurityGuard\Config\Settings as SettingsStore;
use PasichDev\SecurityGuard\Contract\LogIngestInterface;

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * Форма налаштувань будується з Settings::GROUPS; тип поля — з типу значення
 * за замовчуванням, з уточненнями для окремих ключів (FIELD_TYPES).
 */
class Settings extends BaseController
{
    /** Ключі з особливим полем. Решта: bool → перемикач, int → число, string → рядок. */
    private const FIELD_TYPES = [
        'mode' => 'mode',
        'response_code' => 'response_code',
        'escalation' => 'escalation',
        'bypass_token' => 'token',
        'whitelist_ranges' => 'ranges',
        'log_exclude_ips' => 'ranges',
        'honeypot_custom_urls' => 'paths',
        'log_sources' => 'sources',
        'notify_emails' => 'emails',
        'geo_block_countries' => 'countries',
    ];

    /** Межі для цілих: [min, max]. */
    private const INT_LIMITS = [
        'event_retention_days' => [1, 3650],
        'event_log_throttle_seconds' => [0, 86400],
        'notify_throttle_minutes' => [1, 1440],
        'trust_admin_days' => [1, 365],
        'block_duration' => [60, 31536000],
        'rate_limit_requests' => [10, 100000],
        'rate_limit_window' => [1, 3600],
        'php_probe_threshold' => [1, 1000],
        'php_probe_window' => [1, 3600],
        'behavior_threshold' => [1, 1000],
        'behavior_ttl' => [60, 604800],
        'bruteforce_threshold' => [1, 1000],
        'bruteforce_window' => [60, 86400],
        'ddos_multiplier' => [2, 1000],
        'ddos_min_requests' => [10, 1000000],
        'log_ingest_time_budget' => [1, 120],
    ];

    public const RESPONSE_CODES = [403, 404, 410];

    public function view()
    {
        $values = $this->get('values');
        if (!is_array($values)) {
            $values = $this->safe(function () {
                return $this->settings()->all();
            }, SettingsStore::DEFAULTS, t('Settings'));
        }
        $this->set('values', $values);
        $this->set('groups', SettingsStore::GROUPS);
        $this->set('fields', $this->fieldDefinitions());
        $this->set('clientIps', $this->clientIps());
        $this->set('siteUrl', rtrim($this->request->getSchemeAndHttpHost() . $this->request->getBasePath(), '/'));
        $this->set('sources', $this->safe(function () {
            return $this->service(LogIngestInterface::class)->discoverSources();
        }, [], ''));
    }

    public function save()
    {
        if (!$this->isValidPost('sg_settings_save')) {
            return $this->back();
        }
        $post = $this->request->request;
        // Лише ключі, які форма справді показує (GROUPS): ключ без поля не має
        // тихо ставати false чи блокувати збереження.
        $formKeys = array_values(array_intersect(array_merge(...array_values(SettingsStore::GROUPS)), array_keys(SettingsStore::DEFAULTS)));
        $values = $this->safe(function () {
            return $this->settings()->all();
        }, SettingsStore::DEFAULTS, '');
        foreach ($formKeys as $key) {
            $type = $this->fieldType($key);
            $raw = $post->get('s_' . $key);
            switch ($type) {
                case 'bool':
                    $values[$key] = (bool) $raw;
                    break;
                case 'int':
                    $str = is_string($raw) ? trim($raw) : '';
                    [$min, $max] = self::INT_LIMITS[$key] ?? [0, PHP_INT_MAX];
                    if (!preg_match('/^\d{1,10}$/', $str) || (int) $str < $min || (int) $str > $max) {
                        $this->error->add(t('%s: enter a whole number from %s to %s.', $this->label($key), $min, $max));
                        $values[$key] = $str;
                    } else {
                        $values[$key] = (int) $str;
                    }
                    break;
                case 'mode':
                    $values[$key] = $raw === SettingsStore::MODE_ENFORCE ? SettingsStore::MODE_ENFORCE : SettingsStore::MODE_MONITOR;
                    break;
                case 'response_code':
                    $values[$key] = in_array((int) $raw, self::RESPONSE_CODES, true) ? (int) $raw : 403;
                    break;
                case 'escalation':
                    $before = count($this->error->getList());
                    $parsed = $this->parseEscalation(is_string($raw) ? $raw : '', $key);
                    $values[$key] = count($this->error->getList()) > $before ? (string) $raw : $parsed;
                    break;
                default:
                    $values[$key] = $this->cleanText($key, $type, is_string($raw) ? $raw : '');
            }
        }

        $generated = false;
        if ($post->get('generate_token')) {
            $values['bypass_token'] = rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
            $generated = true;
        }

        if ($this->error->has()) {
            $this->set('values', $values);
            $this->view();

            return null;
        }

        $ok = $this->safe(function () use ($values, $formKeys) {
            foreach ($formKeys as $key) {
                $value = $values[$key];
                $this->settings()->set($key, $value);
            }

            return true;
        }, false, t('Settings'));
        if (!$ok) {
            $this->error->add(t('The settings could not be saved.'));
            $this->set('values', $values);
            $this->view();

            return null;
        }
        $this->rebuildState();
        $this->flash('success', $generated
            ? t('Settings saved. A new emergency bypass token was generated — save the bypass link in a safe place.')
            : t('Settings saved.'));

        return $this->back();
    }

    // ----------------------------------------------------------- допоміжні

    protected function fieldType(string $key): string
    {
        if (isset(self::FIELD_TYPES[$key])) {
            return self::FIELD_TYPES[$key];
        }
        $d = SettingsStore::DEFAULTS[$key] ?? '';
        if (is_bool($d)) {
            return 'bool';
        }
        if (is_int($d)) {
            return 'int';
        }
        if (is_array($d)) {
            return 'escalation';
        }

        return 'string';
    }

    /** @return array<int,int> */
    protected function parseEscalation(string $raw, string $key): array
    {
        $out = [];
        foreach (preg_split('/[\s,;]+/', trim($raw)) ?: [] as $part) {
            if ($part === '') {
                continue;
            }
            if (!preg_match('/^(\d{1,9})([smhdw]?)$/i', $part, $m)) {
                $this->error->add(t('%s: "%s" is not a duration. Use seconds or a number with s, m, h, d or w (for example 1h, 24h, 7d).', $this->label($key), $part));

                return [];
            }
            $mult = ['' => 1, 's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86400, 'w' => 604800][strtolower($m[2])];
            $sec = (int) $m[1] * $mult;
            if ($sec < 60 || $sec > 315360000) {
                $this->error->add(t('%s: each step must be between 1 minute and 10 years.', $this->label($key)));

                return [];
            }
            $out[] = $sec;
        }
        if (!$out || count($out) > 10) {
            $this->error->add(t('%s: enter from 1 to 10 durations.', $this->label($key)));
        }

        return $out;
    }

    protected function cleanText(string $key, string $type, string $raw): string
    {
        $raw = str_replace("\0", '', $raw);
        $label = $this->label($key);
        switch ($type) {
            case 'token':
                $raw = trim($raw);
                if ($raw !== '' && !preg_match('/^[A-Za-z0-9_\-]{16,128}$/', $raw)) {
                    $this->error->add(t('%s: use 16–128 Latin letters, digits, "-" or "_", or leave it empty.', $label));
                }

                return $raw;
            case 'ranges':
                $parsed = IpRange::parseList($raw);
                foreach (array_slice($parsed['errors'], 0, 5) as $err) {
                    $this->error->add($label . ': ' . $err);
                }

                return $parsed['errors'] ? trim($raw) : implode("\n", $parsed['valid']);
            case 'paths':
                $lines = $this->lines($raw, 100);
                foreach ($lines as $l) {
                    if ($l[0] !== '/' || preg_match('/\s/', $l) || strlen($l) > 200) {
                        $this->error->add(t('%s: "%s" must be a path starting with "/" without spaces.', $label, mb_substr($l, 0, 60)));
                        break;
                    }
                }

                return implode("\n", $lines);
            case 'sources':
                $lines = $this->lines($raw, 20);
                foreach ($lines as $l) {
                    if (strlen($l) > 255 || preg_match('#(^|/)\.\.(/|$)#', $l) || preg_match('/^[a-z][a-z0-9+.-]*:\/\//i', $l)) {
                        $this->error->add(t('%s: "%s" is not a local file path.', $label, mb_substr($l, 0, 60)));
                        break;
                    }
                }

                return implode("\n", $lines);
            case 'emails':
                $emails = array_values(array_filter(array_map('trim', preg_split('/[\s,;]+/', $raw) ?: []), 'strlen'));
                foreach ($emails as $e) {
                    if (!filter_var($e, FILTER_VALIDATE_EMAIL)) {
                        $this->error->add(t('%s: "%s" is not a valid e-mail address.', $label, mb_substr($e, 0, 60)));
                        break;
                    }
                }

                return implode(', ', array_slice($emails, 0, 20));
            case 'countries':
                $codes = array_values(array_unique(array_filter(array_map(static function ($c) {
                    return strtoupper(trim($c));
                }, preg_split('/[\s,;]+/', $raw) ?: []), 'strlen')));
                foreach ($codes as $c) {
                    if (!preg_match('/^[A-Z]{2}$/', $c)) {
                        $this->error->add(t('%s: "%s" is not a two-letter country code.', $label, mb_substr($c, 0, 10)));
                        break;
                    }
                }
                if (in_array('UA', $codes, true)) {
                    $this->error->add(t('%s: blocking UA would block your own visitors.', $label));
                }

                return implode(', ', $codes);
            default:
                return mb_substr(trim($raw), 0, 1000);
        }
    }

    /** @return string[] */
    protected function lines(string $raw, int $max): array
    {
        $lines = array_values(array_filter(array_map('trim', preg_split('/\R/', $raw) ?: []), 'strlen'));
        if (count($lines) > $max) {
            $this->error->add(t('No more than %s lines are allowed.', $max));
            $lines = array_slice($lines, 0, $max);
        }

        return $lines;
    }

    protected function label(string $key): string
    {
        $f = $this->fieldDefinitions();

        return $f[$key]['label'] ?? $key;
    }

    /**
     * Підписи й пояснення полів.
     *
     * @return array<string, array{label: string, help: string, type: string, min?: int, max?: int}>
     */
    protected function fieldDefinitions(): array
    {
        $d = [
            'enabled' => [t('Firewall enabled'), t('When off, requests are not checked at all.')],
            'mode' => [t('Mode'), t('Monitor: only log attacks. Enforce: block them. Start with monitor and switch after reviewing the event log.')],
            'response_code' => [t('Response to blocked requests'), t('403 is the standard answer; 404 or 410 hides the fact that a firewall is present.')],
            'bypass_token' => [t('Emergency bypass token'), t('Opening any page with ?sg_pass=<token> unblocks the current IP. Empty = disabled. Keep the link in a safe place.')],
            'log_events' => [t('Write events to the log'), t('Attacks and bans are saved to the event log.')],
            'event_retention_days' => [t('Keep events, days'), t('Older events are deleted automatically.')],
            'event_log_throttle_seconds' => [t('Throttle identical events, seconds'), t('The same IP and rule are logged no more often than this.')],
            'notify_emails' => [t('Alert e-mails'), t('Comma-separated. Leave empty to disable e-mail alerts.')],
            'notify_throttle_minutes' => [t('Alerts of one type no more often than, minutes'), ''],
            'whitelist_ranges' => [t('Trusted addresses'), t('One per line: an IP, a prefix such as 203.0.113. or a CIDR range. These visitors skip all checks.')],
            'trust_admin_ip' => [t('Trust the IP of an administrator after login'), t('Prevents locking yourself out after a successful login.')],
            'trust_admin_days' => [t('Trust the administrator IP for, days'), ''],
            'trust_cloudflare' => [t('The site is behind Cloudflare'), t('Read the visitor IP from Cloudflare headers, but only for requests coming from Cloudflare networks.')],
            'block_duration' => [t('First ban, seconds'), t('3600 = 1 hour.')],
            'escalation' => [t('Escalation of repeated bans'), t('Comma-separated durations for the 1st, 2nd, 3rd… ban: seconds or 1h, 24h, 7d, 30d.')],
            'rules_sql_injection' => [t('SQL injection'), ''],
            'rules_xss' => [t('Cross-site scripting (XSS)'), ''],
            'rules_path_traversal' => [t('Path traversal (../, /etc/passwd)'), ''],
            'rules_code_exec' => [t('Code execution attempts'), ''],
            'rules_joomla_exploits' => [t('Old Joomla exploits'), t('Only specific known exploits; old Joomla article links keep working.')],
            'rules_wordpress_probes' => [t('WordPress probing (wp-login, xmlrpc)'), ''],
            'rules_webshells' => [t('Web shells'), ''],
            'rules_sensitive_files' => [t('Sensitive files (.env, .git, backups)'), ''],
            'rules_bad_user_agents' => [t('Known scanners (by user agent)'), ''],
            'rules_http_libraries' => [t('HTTP libraries (curl, wget, python-requests)'), t('May block uptime monitors and integrations.')],
            'rules_ai_crawlers' => [t('AI crawlers'), ''],
            'scan_post_body' => [t('Check POST data'), t('Public pages only; the dashboard is never checked.')],
            'verify_search_bots' => [t('Verify search bots'), t('Confirms Googlebot, Bingbot and others by reverse and forward DNS.')],
            'block_fake_bots' => [t('Block fake search bots'), ''],
            'honeypot_enabled' => [t('Honeypot traps'), ''],
            'honeypot_custom_urls' => [t('Own trap URLs'), t('One path per line, for example /old-admin.php. Never link to them.')],
            'rate_limit_enabled' => [t('Rate limit'), ''],
            'rate_limit_requests' => [t('Requests per window'), t('Static files are not counted.')],
            'rate_limit_window' => [t('Window, seconds'), ''],
            'php_probe_enabled' => [t('Detect bursts of .php requests'), ''],
            'php_probe_threshold' => [t('.php requests'), ''],
            'php_probe_window' => [t('Within, seconds'), ''],
            'behavior_scoring' => [t('Behaviour scoring'), ''],
            'behavior_threshold' => [t('Points before a ban'), ''],
            'behavior_ttl' => [t('Points expire after, seconds'), ''],
            'bruteforce_enabled' => [t('Password guessing protection'), ''],
            'bruteforce_threshold' => [t('Failed logins'), ''],
            'bruteforce_window' => [t('Within, seconds'), ''],
            'notify_admin_new_ip' => [t('Alert about an administrator login from a new IP'), ''],
            'ddos_enabled' => [t('Detect traffic spikes'), ''],
            'ddos_multiplier' => [t('Spike: times above normal'), ''],
            'ddos_min_requests' => [t('Spike: at least requests per minute'), ''],
            'ddos_auto_block' => [t('Block the top IPs of a spike automatically'), ''],
            'geo_lookup' => [t('Detect the country of an IP'), t('Offline, without external services.')],
            'geo_block_countries' => [t('Block countries'), t('Two-letter codes, comma-separated, for example RU, BY. Empty = no geo block.')],
            'log_sources' => [t('Access log files'), t('One path or pattern per line. Empty = detect automatically (~/access-logs, ~/logs).')],
            'log_exclude_ips' => [t('Do not count these IPs in statistics'), t('For example your own address, one per line.')],
            'log_ingest_time_budget' => [t('Time limit for "Update from hosting logs", seconds'), t('The cron command has no limit.')],
        ];
        $out = [];
        foreach (array_keys(SettingsStore::DEFAULTS) as $key) {
            $type = $this->fieldType($key);
            $out[$key] = [
                'label' => $d[$key][0] ?? $key,
                'help' => $d[$key][1] ?? '',
                'type' => $type,
            ];
            if ($type === 'int' && isset(self::INT_LIMITS[$key])) {
                [$out[$key]['min'], $out[$key]['max']] = self::INT_LIMITS[$key];
            }
        }

        return $out;
    }
}
