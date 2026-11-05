<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard;

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\BaseController;
use PasichDev\SecurityGuard\Contract\HoneypotRepositoryInterface;

defined('C5_EXECUTE') or die('Access Denied.');

class Honeypot extends BaseController
{
    private const PER_PAGE = 50;

    public function view()
    {
        $repo = $this->lazy(HoneypotRepositoryInterface::class);
        $page = $this->currentPage();
        $hits = $this->safe(function () use ($repo, $page) {
            return $repo->list(self::PER_PAGE, ($page - 1) * self::PER_PAGE);
        }, ['rows' => [], 'total' => 0], t('Honeypot'));
        $traps = (array) $this->safe(function () use ($repo) {
            return $repo->trapUrls();
        }, [], '');
        $custom = preg_split('/\r\n|\r|\n/', (string) $this->safe(function () {
            return $this->settings()->get('honeypot_custom_urls');
        }, '', '')) ?: [];
        $custom = array_values(array_filter(array_map('trim', $custom), 'strlen'));

        $this->set('traps', array_values(array_map('strval', $traps)));
        $this->set('customTraps', $custom);
        $this->set('enabled', (bool) $this->safe(function () {
            return $this->settings()->get('honeypot_enabled');
        }, false, ''));
        $this->set('rows', (array) ($hits['rows'] ?? []));
        $this->setPagination((int) ($hits['total'] ?? 0), self::PER_PAGE, $page);
    }
}
