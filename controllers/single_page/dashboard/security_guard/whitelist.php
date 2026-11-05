<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard;

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\BaseController;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\IpRange;
use PasichDev\SecurityGuard\Contract\WhitelistInterface;

defined('C5_EXECUTE') or die('Access Denied.');

class Whitelist extends BaseController
{
    public function view()
    {
        $entries = (array) $this->safe(function () {
            return $this->service(WhitelistInterface::class)->all();
        }, [], t('Whitelist'));
        $manual = [];
        $auto = [];
        foreach ($entries as $e) {
            if (!empty($e['auto'])) {
                $auto[] = $e;
            } else {
                $manual[] = $e;
            }
        }
        $fromSettings = IpRange::parseList((string) $this->safe(function () {
            return $this->settings()->get('whitelist_ranges');
        }, '', ''))['valid'];

        $this->set('manual', $manual);
        $this->set('auto', $auto);
        $this->set('fromSettings', $fromSettings);
        $this->set('clientIps', $this->clientIps());
        $this->set('trustAdmin', (bool) $this->safe(function () {
            return $this->settings()->get('trust_admin_ip');
        }, false, ''));
        $this->set('trustDays', (int) $this->safe(function () {
            return $this->settings()->get('trust_admin_days');
        }, 0, ''));
        $this->set('expiries', $this->expiries());
    }

    public function add()
    {
        if (!$this->isValidPost('sg_whitelist_add')) {
            return $this->back();
        }
        $range = $this->postString('range', 64);
        $error = IpRange::validate($range);
        if ($error !== null) {
            $this->flash('error', $error);

            return $this->back();
        }
        $expiry = $this->postString('expires', 12);
        if (!array_key_exists($expiry, $this->expiries())) {
            $expiry = '0';
        }
        $description = $this->postString('description', 255);
        $wl = $this->lazy(WhitelistInterface::class);
        $exists = $this->safe(function () use ($wl, $range) {
            foreach ($wl->all() as $e) {
                if (strcasecmp((string) ($e['ipRange'] ?? ''), $range) === 0) {
                    return true;
                }
            }

            return false;
        }, false, '');
        if ($exists) {
            $this->flash('error', t('%s is already in the whitelist.', $range));

            return $this->back();
        }
        $ok = $this->safe(function () use ($wl, $range, $description, $expiry) {
            $wl->add($range, $description, $expiry === '0' ? 0 : time() + (int) $expiry, false);

            return true;
        }, false, t('Whitelist'));
        if ($ok) {
            $this->rebuildState();
            $this->flash('success', t('%s is added to the whitelist.', $range));
        } else {
            $this->flash('error', t('Could not add %s to the whitelist.', $range));
        }

        return $this->back();
    }

    public function remove()
    {
        if (!$this->isValidPost('sg_whitelist_remove')) {
            return $this->back();
        }
        $id = (int) $this->request->request->get('id', 0);
        if ($id <= 0) {
            return $this->back();
        }
        $ok = $this->safe(function () use ($id) {
            $this->service(WhitelistInterface::class)->remove($id);

            return true;
        }, false, t('Whitelist'));
        if ($ok) {
            $this->rebuildState();
            $this->flash('success', t('The entry is removed from the whitelist.'));
        }

        return $this->back();
    }

    /** @return array<string,string> */
    protected function expiries(): array
    {
        return [
            '0' => t('Never expires'),
            '86400' => t('24 hours'),
            '604800' => t('7 days'),
            '2592000' => t('30 days'),
            '7776000' => t('90 days'),
        ];
    }
}
