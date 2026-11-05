<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard;

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\BaseController;
use PasichDev\SecurityGuard\Contract\BlockServiceInterface;
use PasichDev\SecurityGuard\Contract\ScoreServiceInterface;

defined('C5_EXECUTE') or die('Access Denied.');

class Blocks extends BaseController
{
    private const PER_PAGE = 50;

    public function view()
    {
        $tab = $this->queryString('tab', 10) === 'history' ? 'history' : 'active';
        $search = $this->queryString('q', 64);
        if ($search !== '' && !preg_match('/^[0-9a-zA-Z:._\- ]{1,64}$/', $search)) {
            $search = '';
        }
        $page = $this->currentPage();
        $blocks = $this->lazy(BlockServiceInterface::class);
        $result = $this->safe(function () use ($blocks, $tab, $page, $search) {
            return $tab === 'history'
                ? $blocks->listHistory(self::PER_PAGE, ($page - 1) * self::PER_PAGE, $search)
                : $blocks->listActive(self::PER_PAGE, ($page - 1) * self::PER_PAGE, $search);
        }, ['rows' => [], 'total' => 0], t('Blocks'));

        $ips = $this->clientIps();
        $myBans = [];
        foreach ($ips['all'] as $ip) {
            $ban = $this->safe(function () use ($blocks, $ip) {
                return $blocks->find($ip);
            }, null, '');
            if ($ban) {
                $myBans[$ip] = $ban;
            }
        }

        $this->set('tab', $tab);
        $this->set('search', $search);
        $this->set('rows', (array) ($result['rows'] ?? []));
        $this->set('activeCount', (int) $this->safe(function () use ($blocks) {
            return $blocks->countActive();
        }, 0, ''));
        $this->set('clientIps', $ips);
        $this->set('myBans', $myBans);
        $this->set('durations', $this->durations());
        // Після спроби забанити бота: форма заповнена, чекбокс підтвердження обов'язковий.
        $prefill = $this->queryString('ban_ip', 45);
        $this->set('prefillIp', filter_var($prefill, FILTER_VALIDATE_IP) ? $prefill : '');
        $this->set('prefillBot', $this->prefillBotName($prefill));
        $this->setPagination((int) ($result['total'] ?? 0), self::PER_PAGE, $page, ['tab' => $tab, 'q' => $search]);
    }

    public function unblock()
    {
        if (!$this->isValidPost('sg_unblock')) {
            return $this->back();
        }
        $ip = $this->postString('ip', 45);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->flash('error', t('"%s" is not a valid IP address.', $ip));

            return $this->back();
        }
        $ok = $this->safe(function () use ($ip) {
            $this->service(BlockServiceInterface::class)->unblock($ip);

            return true;
        }, false, t('Blocks'));
        $ok ? $this->flash('success', t('%s is unblocked.', $ip)) : $this->flash('error', t('Could not unblock %s.', $ip));

        return $this->back(['tab' => $this->postString('tab', 10)]);
    }

    /** «Розблокувати мою IP»: обидві адреси (з урахуванням проксі і REMOTE_ADDR) + скидання балу. */
    public function unblock_me()
    {
        if (!$this->isValidPost('sg_unblock_me')) {
            return $this->back();
        }
        $done = [];
        foreach ($this->clientIps()['all'] as $ip) {
            $ok = $this->safe(function () use ($ip) {
                $this->service(BlockServiceInterface::class)->unblock($ip);
                try {
                    $this->service(ScoreServiceInterface::class)->reset($ip);
                } catch (\Throwable $e) {
                }

                return true;
            }, false, t('Blocks'));
            if ($ok) {
                $done[] = $ip;
            }
        }
        $done
            ? $this->flash('success', t('Unblocked: %s. The behaviour score was reset as well.', implode(', ', $done)))
            : $this->flash('error', t('Could not determine or unblock your IP address.'));

        return $this->back();
    }

    public function block()
    {
        if (!$this->isValidPost('sg_block')) {
            return $this->back();
        }
        $duration = $this->postString('duration', 16);
        if (!array_key_exists($duration, $this->durations())) {
            $this->flash('error', t('Invalid block duration.'));

            return $this->back();
        }
        $reason = strtoupper(preg_replace('/[^A-Za-z0-9_]/', '_', $this->postString('reason', 40)) ?? '');
        $this->doBan($this->postString('ip', 64), $duration, $reason !== '' ? 'MANUAL_' . $reason : 'MANUAL', 'manual');

        return $this->afterBan($this->back());
    }

    protected function prefillBotName(string $ip): string
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return '';
        }
        // Назву беремо з перевірки, а не з URL (у URL — лише підказка).
        return (string) $this->botName($ip);
    }

    /** @return array<string,string> */
    protected function durations(): array
    {
        return [
            'escalation' => t('By escalation rules'),
            '3600' => t('1 hour'),
            '86400' => t('24 hours'),
            '604800' => t('7 days'),
            '2592000' => t('30 days'),
            '31536000' => t('1 year'),
            '0' => t('Permanent'),
        ];
    }
}
