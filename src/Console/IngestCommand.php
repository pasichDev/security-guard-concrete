<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Console;

use Concrete\Core\Console\Command;
use Concrete\Core\Support\Facade\Application as AppFacade;
use PasichDev\SecurityGuard\Contract\LogIngestInterface;
use PasichDev\SecurityGuard\Logs\LogIngest;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class IngestCommand extends Command
{
    protected function configure()
    {
        $this
            ->setName('security-guard:ingest')
            ->setAliases(['c5:security-guard:ingest'])
            ->setDescription('Import the hosting access logs into the Security Guard daily statistics')
            ->addOption('days', null, InputOption::VALUE_REQUIRED, 'Only recompute days within the last N days (0 = all)', '0')
            ->addOption('rebuild', null, InputOption::VALUE_NONE, 'Forget file positions and recompute every day found in the logs')
            ->addOption('time-budget', null, InputOption::VALUE_REQUIRED, 'Stop after about S seconds (0 = no limit); run again to continue', '0')
            ->addOption('log-root', null, InputOption::VALUE_REQUIRED, 'Account home directory that contains access-logs/ and logs/ (default: detected)')
            ->addOption('domain', null, InputOption::VALUE_REQUIRED, 'Domain whose logs to read (default: the site canonical URL host)')
            ->addOption('exclude-ip', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Extra IP, prefix or CIDR to leave out of the statistics')
            ->setHelp(<<<'EOT'
Reads new lines from the hosting access logs (live files and monthly .gz archives),
then fully recomputes every day those lines belong to. Safe to run repeatedly, e.g. from cron:

  0 * * * * php concrete/bin/concrete5 security-guard:ingest

Returns 0 when everything was imported, 1 on errors, 2 when stopped by --time-budget (run again).
EOT
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $app = AppFacade::getFacadeApplication();
        $svc = $app->make(LogIngestInterface::class);
        $options = [
            'days' => max(0, (int) $input->getOption('days')),
            'rebuild' => (bool) $input->getOption('rebuild'),
            'timeBudget' => max(0, (int) $input->getOption('time-budget')),
            'logRoot' => (string) $input->getOption('log-root'),
            'domain' => (string) $input->getOption('domain'),
            'excludeIps' => implode("\n", (array) $input->getOption('exclude-ip')),
        ];
        if ($svc instanceof LogIngest) {
            if ($output->isVerbose()) {
                foreach ($svc->locator($options)->discover() as $path => $meta) {
                    $output->writeln(sprintf('  %s (%d bytes, stream %s)', $path, $meta['size'], $meta['stream']));
                }
            }
            $r = $svc->run($options);
        } else {
            $r = $svc->ingest($options['timeBudget']);
        }

        $output->writeln(sprintf(
            'Files: %d, new lines: %d, days recomputed: %d, pending: %d, duplicate lines skipped: %d, malformed lines: %d',
            $r['files'], $r['lines'], count($r['days']), $r['pending'] ?? 0, $r['deduplicated'] ?? 0, $r['malformed'] ?? 0
        ));
        if (!empty($r['hostWafSizes'])) {
            $output->writeln('Hosting server 403 page sizes: ' . implode(', ', $r['hostWafSizes']));
        }
        if ($r['days'] && $output->isVerbose()) {
            $output->writeln('Days: ' . implode(', ', $r['days']));
        }
        foreach ($r['errors'] as $err) {
            $output->writeln('<error>' . $err . '</error>');
        }
        if ($r['errors']) {
            return static::FAILURE;
        }
        if (!$r['finished']) {
            $output->writeln('Not finished: run the command again to continue.');

            return static::INVALID;
        }

        return static::SUCCESS;
    }
}
