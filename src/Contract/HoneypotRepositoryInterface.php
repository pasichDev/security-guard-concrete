<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace PasichDev\SecurityGuard\Contract;

interface HoneypotRepositoryInterface
{
    public function record(string $ip, string $url, string $userAgent): void;

    /** @return array{rows: array, total: int} */
    public function list(int $limit = 50, int $offset = 0): array;

    /** Активні URL-пастки (вбудовані + власні з налаштувань). */
    public function trapUrls(): array;
}
