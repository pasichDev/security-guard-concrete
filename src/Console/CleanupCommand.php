<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Console;

use Concrete\Core\Console\Command;
use Concrete\Core\Support\Facade\Application as AppFacade;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class CleanupCommand extends Command
{
    protected function configure()
    {
        $this
            ->setName('security-guard:cleanup')
            ->setAliases(['c5:security-guard:cleanup'])
            ->setDescription('Delete old Security Guard events, expired blocks, stale scores and counter files');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        // Те саме очищення, що й щогодинне з гарячого шляху: події, бани, білий
        // список, бали, honeypot, сповіщення, кеш ботів, файли лічильників.
        $result = (new \PasichDev\SecurityGuard\Waf\Maintenance(AppFacade::getFacadeApplication()))->run();
        $failed = false;
        foreach ($result as $part => $value) {
            if (is_int($value)) {
                $output->writeln($part . ': ' . $value . ' deleted');
            } else {
                $output->writeln('<error>' . $part . ': ' . $value . '</error>');
                $failed = true;
            }
        }

        return $failed ? static::FAILURE : static::SUCCESS;
    }
}
