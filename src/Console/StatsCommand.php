<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Console;

use Concrete\Core\Console\Command;
use Concrete\Core\Support\Facade\Application as AppFacade;
use DateTimeImmutable;
use PasichDev\SecurityGuard\Contract\LogIngestInterface;
use PasichDev\SecurityGuard\Contract\StatsRepositoryInterface;
use PasichDev\SecurityGuard\Logs\LogIngest;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Helper\TableSeparator;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Таблиця денної статистики з бази — для звірки з ручними підрахунками.
 * --report-compat показує цифри за спрощеною методикою ручних підрахунків (регекс по URL,
 * «login» у POST-запиті з відповіддю 200/400), які зберігаються в breakdown.report.
 */
final class StatsCommand extends Command
{
    protected function configure()
    {
        $this
            ->setName('security-guard:stats')
            ->setAliases(['c5:security-guard:stats'])
            ->setDescription('Print the Security Guard daily statistics imported from the hosting logs')
            ->addOption('from', null, InputOption::VALUE_REQUIRED, 'First day, YYYY-MM-DD (default: 30 days ago)')
            ->addOption('to', null, InputOption::VALUE_REQUIRED, 'Last day, YYYY-MM-DD (default: today)')
            ->addOption('report-compat', null, InputOption::VALUE_NONE, 'Also show attack and failed-login figures counted with the simple URL-regex method (report compatibility)')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Print the range summary as JSON');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $app = AppFacade::getFacadeApplication();
        $ingest = $app->make(LogIngestInterface::class);
        $tz = $ingest instanceof LogIngest ? $ingest->timezone() : new \DateTimeZone(date_default_timezone_get());
        $today = new DateTimeImmutable('now', $tz);
        $to = (string) ($input->getOption('to') ?: $today->format('Y-m-d'));
        $from = (string) ($input->getOption('from') ?: $today->modify('-29 days')->format('Y-m-d'));
        foreach ([$from, $to] as $d) {
            if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $d)) {
                $output->writeln('<error>Invalid date: ' . $d . ' (expected YYYY-MM-DD)</error>');

                return static::INVALID;
            }
        }
        $repo = $app->make(StatsRepositoryInterface::class);
        $days = $repo->getDays($from, $to);
        $sum = $repo->summarize($from, $to);
        if ($input->getOption('json')) {
            $output->writeln((string) json_encode($sum, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

            return static::SUCCESS;
        }
        $compat = (bool) $input->getOption('report-compat');

        $table = new Table($output);
        if ($compat) {
            $table->setHeaders(['Day', 'Requests', 'Attacks', 'Attack IPs', 'Login failed', '403', '508']);
            foreach ($days as $r) {
                $rep = $r['breakdown']['report'] ?? [];
                $table->addRow([$r['day'], $r['totalRequests'], (int) ($rep['attackRequests'] ?? 0), (int) ($rep['attackIps'] ?? 0),
                    (int) ($rep['loginFailed'] ?? 0), $r['blocked403'], $r['overload508']]);
            }
            $rep = $sum['breakdown']['report'];
            $table->addRow(new TableSeparator());
            $table->addRow(['Total', $sum['totalRequests'], $rep['attackRequests'], $rep['attackIps'] . ($rep['attackIpsApprox'] ? ' ~' : ''),
                $rep['loginFailed'], $sum['blocked403'], $sum['overload508']]);
        } else {
            $table->setHeaders(['Day', 'Requests', 'IPs', 'Attacks', 'Attack IPs', 'Login failed', '403', '404', '5xx', '508', 'Bots', 'MB']);
            foreach ($days as $r) {
                $table->addRow([$r['day'], $r['totalRequests'], $r['uniqueIps'], $r['attackRequests'], $r['attackIps'], $r['loginFailed'],
                    $r['blocked403'], $r['errors404'], $r['errors5xx'], $r['overload508'], $r['botRequests'], round($r['bytes'] / 1048576, 1)]);
            }
            $table->addRow(new TableSeparator());
            $table->addRow(['Total', $sum['totalRequests'], $sum['uniqueIps'] . ($sum['uniqueIpsApprox'] ? ' ~' : ''), $sum['attackRequests'],
                $sum['attackIps'] . ($sum['attackIpsApprox'] ? ' ~' : ''), $sum['loginFailed'], $sum['blocked403'], $sum['errors404'],
                $sum['errors5xx'], $sum['overload508'], $sum['botRequests'], round($sum['bytes'] / 1048576, 1)]);
        }
        $table->render();
        $output->writeln(sprintf('%d day(s) %s..%s; "~" = estimate. Last import: %s', count($days), $from, $to,
            ($t = $repo->lastIngestAt()) ? (new DateTimeImmutable('@' . $t))->setTimezone($tz)->format('Y-m-d H:i:s') : 'never'));
        if (!$compat && $sum['breakdown']['categories']) {
            $parts = [];
            foreach ($sum['breakdown']['categories'] as $c => $n) {
                $parts[] = $c . ' ' . $n;
            }
            $output->writeln('Attack categories: ' . implode(', ', $parts));
        }

        return static::SUCCESS;
    }
}
