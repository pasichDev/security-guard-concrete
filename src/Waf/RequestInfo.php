<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Waf;

/** Те, що Firewall знає про запит. Без залежності від HTTP-об'єктів Concrete. */
final class RequestInfo
{
    /** @var string */
    public $ip = '0.0.0.0';
    /** @var string */
    public $method = 'GET';
    /** Рядок запиту як прийшов: шлях + ?query (може містити /index.php). @var string */
    public $uri = '/';
    /** Шлях маршрутизації Concrete (без /index.php). @var string */
    public $pathInfo = '/';
    /** @var string */
    public $userAgent = '';
    /** @var string */
    public $referer = '';
    /** @var bool */
    public $hasAccept = true;
    /** @var bool */
    public $hasAcceptLanguage = true;
    /** Значення ?sg_pass або null. @var string|null */
    public $bypass;
    /** Тіло POST для сканування ('' — не скануємо). @var string */
    public $body = '';
    /** Значення cookie («name=value» по рядку) без cookie сесії/входу Concrete. @var string */
    public $cookies = '';
    /** POST форми входу з непорожніми логіном і паролем. @var bool */
    public $isLoginAttempt = false;
    /** @var int */
    public $now = 0;

    public function path(): string
    {
        $pos = strpos($this->uri, '?');

        return $pos === false ? $this->uri : substr($this->uri, 0, $pos);
    }

    public function query(): string
    {
        $pos = strpos($this->uri, '?');

        return $pos === false ? '' : substr($this->uri, $pos + 1);
    }

    /** Контекст для журналу подій / бану. */
    public function context(): array
    {
        return [
            'method' => $this->method,
            'url' => $this->uri,
            'userAgent' => $this->userAgent,
            'referrer' => $this->referer,
        ];
    }
}
