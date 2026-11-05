<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard;

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\BaseController;
use PasichDev\SecurityGuard\Contract\BlockServiceInterface;
use PasichDev\SecurityGuard\Contract\ScoreServiceInterface;

defined('C5_EXECUTE') or die('Access Denied.');

class Scores extends BaseController
{
    private const PER_PAGE = 50;

    public function view()
    {
        $page = $this->currentPage();
        $result = $this->safe(function () use ($page) {
            return $this->service(ScoreServiceInterface::class)->list(self::PER_PAGE, ($page - 1) * self::PER_PAGE);
        }, ['rows' => [], 'total' => 0], t('Behaviour scores'));
        $rows = (array) ($result['rows'] ?? []);
        $blocks = $this->lazy(BlockServiceInterface::class);
        foreach ($rows as $i => $r) {
            $ev = $r['events'] ?? [];
            if (is_string($ev)) {
                $ev = json_decode($ev, true);
            }
            $rows[$i]['events'] = is_array($ev) ? $ev : [];
            $ip = (string) ($r['ip'] ?? '');
            $rows[$i]['banned'] = $ip !== '' && $this->safe(function () use ($blocks, $ip) {
                return $blocks->find($ip) !== null;
            }, false, '');
        }
        $s = $this->safe(function () {
            return ['threshold' => (int) $this->settings()->get('behavior_threshold'), 'ttl' => (int) $this->settings()->get('behavior_ttl'), 'on' => (bool) $this->settings()->get('behavior_scoring')];
        }, ['threshold' => 25, 'ttl' => 3600, 'on' => true], '');

        $this->set('rows', $rows);
        $this->set('threshold', max(1, $s['threshold']));
        $this->set('ttl', $s['ttl']);
        $this->set('scoringOn', $s['on']);
        $this->set('clientIps', $this->clientIps());
        $this->setPagination((int) ($result['total'] ?? 0), self::PER_PAGE, $page);
    }

    public function reset()
    {
        if (!$this->isValidPost('sg_score_reset')) {
            return $this->back();
        }
        $ip = $this->postString('ip', 45);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->flash('error', t('"%s" is not a valid IP address.', $ip));

            return $this->back();
        }
        $ok = $this->safe(function () use ($ip) {
            $this->service(ScoreServiceInterface::class)->reset($ip);

            return true;
        }, false, t('Behaviour scores'));
        if ($ok) {
            $this->flash('success', t('The score of %s is reset.', $ip));
        }

        return $this->back(['page' => (string) (int) $this->request->request->get('page', 1)]);
    }

    public function ban()
    {
        if (!$this->isValidPost('sg_score_ban')) {
            return $this->back();
        }
        $this->doBan($this->postString('ip', 45), 'escalation', 'BEHAVIOR_MANUAL', 'behavior');

        return $this->afterBan($this->back(['page' => (string) (int) $this->request->request->get('page', 1)]));
    }
}
