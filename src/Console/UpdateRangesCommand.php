<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Console;

use Concrete\Core\Console\Command;
use Concrete\Core\Database\Connection\Connection;
use Concrete\Core\Support\Facade\Application as AppFacade;
use PasichDev\SecurityGuard\Config\Settings;
use PasichDev\SecurityGuard\Update\BotRangeStore;
use PasichDev\SecurityGuard\Update\BotRangeUpdater;
use PasichDev\SecurityGuard\Update\HttpFetcher;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class UpdateRangesCommand extends Command
{
    protected function configure()
    {
        $this
            ->setName('security-guard:update-ranges')
            ->setAliases(['c5:security-guard:update-ranges'])
            ->setDescription('Download the official search-engine crawler IP ranges (Google, Bing, Apple, DuckDuckGo)')
            ->addOption('force', null, InputOption::VALUE_NONE, 'Run even when automatic range updates are switched off in the settings')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Download and validate, but do not save')
            ->setHelp(<<<'EOT'
Fetches the published crawler range lists over HTTPS, validates them strictly and stores them
in the database; the log statistics then use them instead of the ranges built into the package.
A list that fails to download, fails validation or shrinks by more than half is not saved.
Weekly cron example:

  30 4 * * 1 php concrete/bin/concrete5 security-guard:update-ranges

Returns 0 when every list was checked, 1 when none could be, 2 when some failed.
EOT
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $app = AppFacade::getFacadeApplication();
        if (!$input->getOption('force') && !$app->make(Settings::class)->get('bot_ranges_auto_update')) {
            $output->writeln('Automatic crawler range updates are switched off in the settings (use --force to run anyway).');

            return static::SUCCESS;
        }
        $store = new BotRangeStore($app->make(Connection::class));
        $updater = new BotRangeUpdater(new HttpFetcher($app), $store);
        $r = $updater->update((bool) $input->getOption('dry-run'));

        foreach ($r['updated'] as $bot => $n) {
            $output->writeln(sprintf('%s: updated, %d prefixes%s', $bot, $n, $input->getOption('dry-run') ? ' (dry run, not saved)' : ''));
        }
        foreach ($r['unchanged'] as $bot => $n) {
            $output->writeln(sprintf('%s: unchanged, %d prefixes', $bot, $n));
        }
        foreach ($r['errors'] as $bot => $msg) {
            $output->writeln(sprintf('<error>%s: %s</error>', $bot, $msg));
        }
        $total = count(BotRangeUpdater::SOURCES);
        if (count($r['errors']) === $total) {
            return static::FAILURE;
        }

        return $r['errors'] ? static::INVALID : static::SUCCESS;
    }
}
