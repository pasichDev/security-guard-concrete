<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard;

use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\BaseController;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Format;
use Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support\Period;
use DateTimeImmutable;
use PasichDev\SecurityGuard\Contract\EventLogInterface;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Throwable;

defined('C5_EXECUTE') or die('Access Denied.');

class Events extends BaseController
{
    private const PER_PAGE = 50;
    private const EXPORT_CHUNK = 500;
    private const EXPORT_MAX = 50000;

    public function view()
    {
        $input = $this->readFilters();
        $page = $this->currentPage();
        $result = $this->safe(function () use ($input, $page) {
            return $this->service(EventLogInterface::class)->query($input['filters'], self::PER_PAGE, ($page - 1) * self::PER_PAGE);
        }, ['rows' => [], 'total' => 0], t('Event log'));

        $this->set('rows', (array) ($result['rows'] ?? []));
        $this->set('total', (int) ($result['total'] ?? 0));
        $this->set('filters', $input['form']);
        $this->set('categories', Format::categoryLabels());
        $this->set('actions', Format::actionLabels());
        $this->setPagination((int) ($result['total'] ?? 0), self::PER_PAGE, $page, $input['form']);
        $this->set('exportUrl', (string) $this->action('export') . '?' . http_build_query(array_filter($input['form'], 'strlen') + ['ccm_token' => $this->token->generate('sg_export')]));
    }

    /**
     * Експорт у CSV з тими самими фільтрами. Лише читання, але з токеном —
     * щоб сторонній сайт не міг змусити браузер адміністратора вивантажити журнал.
     */
    public function export()
    {
        if (!$this->token->validate('sg_export', (string) $this->request->query->get('ccm_token', ''))) {
            $this->flash('error', $this->token->getErrorMessage());

            return $this->back();
        }
        $filters = $this->readFilters()['filters'];
        $service = $this->safe(function () {
            return $this->service(EventLogInterface::class);
        }, null, t('Event log'));
        if ($service === null) {
            $this->flash('error', t('The event log is unavailable.'));

            return $this->back();
        }
        $labels = [t('Time'), t('IP address'), t('Country'), t('Category'), t('Rule'), t('Action'), t('Method'), t('URL'), t('User agent'), t('Referrer')];
        $tz = Period::timezone();

        $response = new StreamedResponse(static function () use ($service, $filters, $labels, $tz) {
            $out = fopen('php://output', 'wb');
            // BOM — щоб Excel правильно показав кирилицю.
            fwrite($out, "\xEF\xBB\xBF");
            fputcsv($out, $labels, ';');
            $offset = 0;
            while ($offset < self::EXPORT_MAX) {
                try {
                    $chunk = $service->query($filters, self::EXPORT_CHUNK, $offset);
                } catch (Throwable $e) {
                    fputcsv($out, ['# ' . $e->getMessage()], ';');
                    break;
                }
                $rows = (array) ($chunk['rows'] ?? []);
                foreach ($rows as $r) {
                    $ts = (int) ($r['createdAt'] ?? 0);
                    fputcsv($out, array_map(static function ($v) {
                        return self::csvCell($v);
                    }, [
                        $ts > 0 ? (new DateTimeImmutable('@' . $ts))->setTimezone($tz)->format('Y-m-d H:i:s') : '',
                        $r['ip'] ?? '',
                        $r['country'] ?? '',
                        $r['category'] ?? '',
                        $r['rule'] ?? '',
                        $r['action'] ?? '',
                        $r['method'] ?? '',
                        $r['url'] ?? '',
                        $r['userAgent'] ?? '',
                        $r['referrer'] ?? '',
                    ]), ';');
                }
                if (count($rows) < self::EXPORT_CHUNK) {
                    break;
                }
                $offset += self::EXPORT_CHUNK;
                flush();
            }
            fclose($out);
        });
        $name = 'security-guard-events-' . date('Y-m-d') . '.csv';
        $response->headers->set('Content-Type', 'text/csv; charset=UTF-8');
        $response->headers->set('Content-Disposition', 'attachment; filename="' . $name . '"');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('Cache-Control', 'no-store, private');

        return $response;
    }

    /**
     * Захист від CSV-ін'єкції: значення, що починаються з = + - @ або
     * табуляції/повернення каретки, Excel виконає як формулу.
     */
    private static function csvCell($v): string
    {
        $v = (string) $v;
        $v = str_replace(["\r\n", "\r", "\n"], ' ', $v);
        if ($v !== '' && strpbrk($v[0], "=+-@\t\r") !== false) {
            $v = "'" . $v;
        }

        return $v;
    }

    /** @return array{filters: array, form: array} */
    private function readFilters(): array
    {
        $form = [
            'category' => $this->queryString('category', 32),
            'outcome' => $this->queryString('outcome', 16),
            'ip' => $this->queryString('ip', 45),
            'from' => $this->queryString('from', 10),
            'to' => $this->queryString('to', 10),
            'search' => $this->queryString('search', 200),
        ];
        if ($form['category'] !== '' && !preg_match('/^[a-z_]{1,32}$/', $form['category'])) {
            $form['category'] = '';
        }
        if ($form['outcome'] !== '' && !array_key_exists($form['outcome'], Format::actionLabels())) {
            $form['outcome'] = '';
        }
        // IP — точна адреса або її початок (цифри, крапки, двокрапки, hex).
        if ($form['ip'] !== '' && !preg_match('/^[0-9a-fA-F:.]{1,45}$/', $form['ip'])) {
            $form['ip'] = '';
        }
        $filters = [];
        foreach (['category' => 'category', 'outcome' => 'action', 'ip' => 'ip', 'search' => 'search'] as $k => $filterKey) {
            if ($form[$k] !== '') {
                $filters[$filterKey] = $form[$k];
            }
        }
        $tz = Period::timezone();
        foreach (['from' => 0, 'to' => 1] as $k => $addDay) {
            if ($form[$k] === '') {
                continue;
            }
            $d = DateTimeImmutable::createFromFormat('!Y-m-d', $form[$k], $tz);
            if (!$d || $d->format('Y-m-d') !== $form[$k]) {
                $form[$k] = '';
                continue;
            }
            $filters[$k] = $addDay ? $d->modify('+1 day')->getTimestamp() : $d->getTimestamp();
        }
        return ['filters' => $filters, 'form' => $form];
    }
}
