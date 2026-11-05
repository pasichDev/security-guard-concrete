<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/** Стан HostWafDetector між запусками. */
interface HostWafStateStoreInterface
{
    public function getHostWafState(): array;

    public function setHostWafState(array $state): void;
}
