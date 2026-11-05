<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Notify;

use Concrete\Core\Application\Application;
use Concrete\Core\Database\Connection\Connection;
use PasichDev\SecurityGuard\Contract\AlertServiceInterface;
use PasichDev\SecurityGuard\Contract\StateCacheInterface;
use PasichDev\SecurityGuard\Ip\IpRange;
use PasichDev\SecurityGuard\State\Counters;
use PasichDev\SecurityGuard\Waf\Text;
use Throwable;

/**
 * Сповіщення: рядок у SecurityGuardAlerts (той самий тип+IP — не частіше
 * разу на 5 хв) і лист на notify_emails (той самий тип — не частіше
 * notify_throttle_minutes). Типи: bruteforce, ddos, admin_new_ip.
 */
final class AlertService implements AlertServiceInterface
{
    private const ROW_THROTTLE = 300;

    /** @var Application */
    private $app;

    /** @var StateCacheInterface */
    private $state;

    /** @var Connection|null */
    private $db;

    public function __construct(Application $app, StateCacheInterface $state)
    {
        $this->app = $app;
        $this->state = $state;
    }

    public function raise(string $type, string $severity, string $message, array $context = []): void
    {
        $severity = in_array($severity, ['info', 'warning', 'critical'], true) ? $severity : 'info';
        $ip = isset($context['ip']) ? (IpRange::normalize((string) $context['ip']) ?: '') : '';
        $counters = Counters::store();
        if (!$counters->add('al:' . md5($type . '|' . $ip), 1, self::ROW_THROTTLE)) {
            return;
        }
        $this->db()->insert('SecurityGuardAlerts', [
            'type' => Text::cut($type, 32),
            'severity' => $severity,
            'message' => Text::cut($message, 500),
            'value' => isset($context['value']) ? (int) $context['value'] : null,
            'baseline' => isset($context['baseline']) ? (int) round((float) $context['baseline']) : null,
            'ip' => $ip !== '' ? $ip : null,
            'url' => isset($context['url']) ? Text::url((string) $context['url'], 500) : null,
            'isRead' => 0,
            'createdAt' => time(),
        ]);

        $settings = $this->state->load()['settings'];
        $emails = self::parseEmails((string) ($settings['notify_emails'] ?? ''));
        $minutes = max(1, (int) ($settings['notify_throttle_minutes'] ?? 15));
        if ($emails !== [] && $counters->add('alm:' . $type, 1, $minutes * 60)) {
            $this->mail($emails, $type, $severity, $message, $context + ['ip' => $ip]);
        }
    }

    public function recent(int $limit = 20, bool $unreadOnly = false): array
    {
        $where = $unreadOnly ? ' WHERE isRead = 0' : '';
        $db = $this->db();
        $total = (int) $db->fetchOne('SELECT COUNT(*) FROM SecurityGuardAlerts' . $where);
        $rows = $db->fetchAllAssociative('SELECT * FROM SecurityGuardAlerts' . $where . ' ORDER BY id DESC LIMIT ' . max(1, $limit));
        foreach ($rows as &$row) {
            $row['id'] = (int) $row['id'];
            $row['createdAt'] = (int) $row['createdAt'];
            $row['isRead'] = (bool) $row['isRead'];
            $row['value'] = $row['value'] === null ? null : (int) $row['value'];
            $row['baseline'] = $row['baseline'] === null ? null : (int) $row['baseline'];
        }
        unset($row);

        return ['rows' => $rows, 'total' => $total];
    }

    public function markAllRead(): void
    {
        $this->db()->executeStatement('UPDATE SecurityGuardAlerts SET isRead = 1 WHERE isRead = 0');
    }

    public function purgeOlderThan(int $days): int
    {
        return (int) $this->db()->executeStatement('DELETE FROM SecurityGuardAlerts WHERE createdAt < ?', [time() - max(1, $days) * 86400]);
    }

    /** @return string[] */
    public static function parseEmails(string $value): array
    {
        $out = [];
        foreach (preg_split('/[\s,;]+/', $value) ?: [] as $email) {
            $email = trim($email);
            if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $out[strtolower($email)] = $email;
            }
        }

        return array_values($out);
    }

    private function mail(array $emails, string $type, string $severity, string $message, array $context): void
    {
        try {
            $site = '';
            try {
                $site = (string) $this->app->make('site')->getSite()->getSiteName();
            } catch (Throwable $e) {
            }
            $titles = [
                'bruteforce' => t('Password brute-force attempt blocked'),
                'ddos' => t('Traffic spike detected'),
                'admin_new_ip' => t('Administrator signed in from a new IP address'),
            ];
            $title = $titles[$type] ?? t('Security alert');
            $lines = [Text::cleanUrl($message), ''];
            if (!empty($context['ip'])) {
                $lines[] = t('IP address: %s', $context['ip']);
            }
            if (!empty($context['url'])) {
                $lines[] = t('URL: %s', Text::cleanUrl((string) $context['url']));
            }
            $lines[] = t('Severity: %s', $severity);
            $lines[] = t('Time: %s', date('Y-m-d H:i:s T'));
            $lines[] = '';
            $lines[] = t('This message was sent by the Security Guard package. Similar alerts are not repeated more often than the throttle set in its settings.');

            /** @var \Concrete\Core\Mail\Service $mail */
            $mail = $this->app->make('mail');
            foreach ($emails as $email) {
                $mail->to($email);
            }
            $mail->setSubject(($site !== '' ? '[' . $site . '] ' : '') . $title);
            $mail->setBody(implode("\n", $lines));
            $mail->sendMail();
        } catch (Throwable $e) {
            try {
                $this->app->make('log')->warning('Security Guard: alert e-mail failed: ' . $e->getMessage());
            } catch (Throwable $ignored) {
            }
        }
    }

    private function db(): Connection
    {
        return $this->db ?? ($this->db = $this->app->make(Connection::class));
    }
}
