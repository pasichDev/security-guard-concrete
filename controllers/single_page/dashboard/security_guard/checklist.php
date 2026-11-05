<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard;

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\BaseController;
use PasichDev\SecurityGuard\Audit\Checklist as Audit;
use PasichDev\SecurityGuard\Config\Settings;

defined('C5_EXECUTE') or die('Access Denied.');

class Checklist extends BaseController
{
    public function view()
    {
        $this->set('audit', Audit::lastResult($this->app));
        $this->set('enforcing', (bool) $this->safe(function () {
            return $this->settings()->get('enabled') && $this->settings()->get('mode') === Settings::MODE_ENFORCE;
        }, false, ''));
        $this->set('baseUrl', $this->siteUrl());
    }

    /** Запуск перевірки (лише кнопкою: сканування файлів і самоперевірка по HTTP недешеві). */
    public function run()
    {
        if (!$this->isValidPost('sg_audit_run')) {
            return $this->back();
        }
        if (function_exists('set_time_limit')) {
            @set_time_limit(120);
        }
        $result = $this->safe(function () {
            $audit = new Audit($this->app, $this->siteUrl());
            $audit->setClientIp((string) ($this->clientIps()['resolved'] ?? ''));
            $result = $audit->run();
            $audit->save($result);

            return $result;
        }, null, t('Security check'));
        if (is_array($result)) {
            $this->notify('success', t('The security check is finished in %s s.', (string) ($result['duration'] ?? '?')));
        } else {
            $this->notify('error', t('The security check could not run.') . ' ' . implode(' ', $this->serviceErrors));
        }

        return $this->back();
    }

    /** Канонічна адреса сайту, якщо задана; інакше — адреса поточного запиту. */
    protected function siteUrl(): string
    {
        $url = '';
        try {
            $url = (string) $this->app->make('url/canonical');
        } catch (\Throwable $e) {
        }
        if ($url === '' || !preg_match('#^https?://#i', $url)) {
            $url = $this->request->getSchemeAndHttpHost() . $this->request->getBasePath();
        }

        return rtrim($url, '/');
    }
}
