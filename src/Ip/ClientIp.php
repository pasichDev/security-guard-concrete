<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Ip;

use Symfony\Component\HttpFoundation\Request;

/**
 * Справжня IP клієнта. Основа — Request::getClientIp(): Concrete налаштовує
 * довірені проксі з concrete.security.trusted_proxies (Dashboard → System →
 * Permissions → Trusted Proxies), тож X-Forwarded-For від чужих ми не читаємо.
 * Cloudflare — лише за опцією trust_cloudflare і лише коли REMOTE_ADDR сам
 * належить Cloudflare.
 */
final class ClientIp
{
    /** Опубліковані діапазони Cloudflare (cloudflare.com/ips). */
    public const CLOUDFLARE = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    ];

    public static function fromRequest(Request $request, bool $trustCloudflare): string
    {
        return self::resolve(
            (string) $request->getClientIp(),
            (string) $request->server->get('REMOTE_ADDR', ''),
            $request->headers->get('CF-Connecting-IP'),
            $trustCloudflare
        );
    }

    public static function resolve(string $clientIp, string $remoteAddr, ?string $cfHeader, bool $trustCloudflare): string
    {
        if ($trustCloudflare && $cfHeader !== null && $cfHeader !== '') {
            $remote = IpRange::normalize($remoteAddr);
            if ($remote !== '' && IpRange::matchesAny($remote, self::CLOUDFLARE)) {
                $cf = IpRange::normalize($cfHeader);
                if ($cf !== '') {
                    return $cf;
                }
            }
        }
        $ip = IpRange::normalize($clientIp);
        if ($ip === '') {
            $ip = IpRange::normalize($remoteAddr);
        }

        return $ip === '' ? '0.0.0.0' : $ip;
    }
}
