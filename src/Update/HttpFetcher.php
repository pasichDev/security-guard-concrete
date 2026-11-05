<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Update;

use Concrete\Core\Application\Application;
use RuntimeException;

/**
 * Завантаження JSON через HTTP-клієнт Concrete (Guzzle; проксі з налаштувань сайту).
 * Лише https, перевірка TLS увімкнена примусово, короткі тайм-аути, ліміт розміру.
 */
final class HttpFetcher
{
    public const MAX_BYTES = 2097152;
    public const TIMEOUT = 15;

    /** @var Application */
    private $app;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    public function __invoke(string $url): string
    {
        if (stripos($url, 'https://') !== 0) {
            throw new RuntimeException('Only https URLs are allowed: ' . $url);
        }
        $client = $this->app->make('http/client');
        $response = $client->request('GET', $url, [
            'timeout' => self::TIMEOUT,
            'connect_timeout' => 5,
            'verify' => true,
            'http_errors' => false,
            'stream' => true,
            'allow_redirects' => ['max' => 3, 'protocols' => ['https'], 'strict' => true],
            'headers' => ['Accept' => 'application/json', 'User-Agent' => 'SecurityGuard-RangeUpdate/1.1'],
        ]);
        $status = $response->getStatusCode();
        if ($status !== 200) {
            throw new RuntimeException('HTTP ' . $status . ' from ' . $url);
        }
        $declared = (int) $response->getHeaderLine('Content-Length');
        if ($declared > self::MAX_BYTES) {
            throw new RuntimeException('Response too large from ' . $url);
        }
        $body = $response->getBody();
        $data = '';
        while (!$body->eof()) {
            $data .= $body->read(65536);
            if (strlen($data) > self::MAX_BYTES) {
                $body->close();
                throw new RuntimeException('Response too large from ' . $url);
            }
        }
        $body->close();

        return $data;
    }
}
