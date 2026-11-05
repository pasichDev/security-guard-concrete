<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use PasichDev\SecurityGuard\Geo\CountryGuesser;
use PasichDev\SecurityGuard\Ip\ClientIp;
use PasichDev\SecurityGuard\Ip\IpRange;
use PasichDev\SecurityGuard\Waf\Whitelist;

// Нормалізація.
T::eq('1.2.3.4', IpRange::normalize(' 1.2.3.4 '), 'normalize v4');
T::eq('1.2.3.4', IpRange::normalize('::ffff:1.2.3.4'), 'v4-mapped v6 → v4');
T::eq('1.2.3.4', IpRange::normalize('1.2.3.4:8080'), 'v4 з портом');
T::eq('2001:db8::1', IpRange::normalize('2001:0DB8:0000:0000:0000:0000:0000:0001'), 'v6 канонічний');
T::eq('2001:db8::1', IpRange::normalize('[2001:db8::1]:443'), 'v6 у дужках з портом');
T::eq('fe80::1', IpRange::normalize('fe80::1%eth0'), 'v6 із zone id');
T::eq('', IpRange::normalize('not-an-ip'), 'невалідний');
T::eq('', IpRange::normalize('999.1.1.1'), 'невалідний v4');

// Точний збіг, префікс, CIDR.
T::ok(IpRange::matches('1.2.3.4', '1.2.3.4'), 'точний v4');
T::ok(!IpRange::matches('1.2.3.10', '1.2.3.1'), '1.2.3.1 не збігається з 1.2.3.10');
T::ok(IpRange::matches('1.2.3.10', '1.2.3.'), 'префікс 1.2.3.');
T::ok(!IpRange::matches('1.2.30.1', '1.2.3.'), 'префікс 1.2.3. не ловить 1.2.30.1');
T::ok(IpRange::matches('10.20.30.40', '10.'), 'префікс 10.');
T::ok(IpRange::matches('192.168.1.77', '192.168.1.0/24'), 'CIDR /24');
T::ok(!IpRange::matches('192.168.2.1', '192.168.1.0/24'), 'поза CIDR /24');
T::ok(IpRange::matches('172.16.5.4', '172.16.0.0/12'), 'CIDR /12');
T::ok(!IpRange::matches('172.32.0.1', '172.16.0.0/12'), 'поза CIDR /12');
T::ok(IpRange::matches('8.8.8.8', '0.0.0.0/0'), 'CIDR /0');
T::ok(IpRange::matches('1.2.3.4', '1.2.3.4/32'), 'CIDR /32');
T::ok(!IpRange::matches('1.2.3.5', '1.2.3.4/32'), 'CIDR /32 інша IP');
T::ok(IpRange::matches('2001:db8:abcd::5', '2001:db8::/32'), 'v6 CIDR /32');
T::ok(!IpRange::matches('2001:db9::5', '2001:db8::/32'), 'v6 поза /32');
T::ok(IpRange::matches('2a06:98c1::1', '2a06:98c0::/29'), 'v6 CIDR /29');
T::ok(!IpRange::matches('2a06:98c8::1', '2a06:98c0::/29'), 'v6 поза /29');
T::ok(IpRange::matches('2001:db8::1', '2001:db8:'), 'v6 префікс');
T::ok(IpRange::matches('::1', '::1'), 'v6 loopback точний (а не префікс через «::»)');
T::ok(!IpRange::matches('1.2.3.4', '2001:db8::/32'), 'v4 проти v6 CIDR');
T::ok(!IpRange::matches('2001:db8::1', '1.2.3.0/24'), 'v6 проти v4 CIDR');
T::ok(IpRange::matches('::ffff:192.168.1.5', '192.168.1.0/24'), 'v4-mapped у v4 CIDR');
T::ok(!IpRange::matches('1.2.3.4', '1.2.3.0/40'), 'некоректна маска');
T::ok(!IpRange::matches('1.2.3.4', ''), 'порожній діапазон');
T::ok(IpRange::isLoopback('127.0.0.1') && IpRange::isLoopback('::1') && !IpRange::isLoopback('10.0.0.1'), 'loopback');

// Валідація діапазонів.
foreach (['1.2.3.4', '1.2.3.', '10.', '10.0.0.0/8', '2001:db8::/32', '2001:db8:', '::1'] as $ok) {
    T::ok(IpRange::isValidRange($ok), 'валідний діапазон ' . $ok);
}
foreach (['', 'abc', '1.2.3.0/33', '1.2.3.4.', '2001:db8::/129', '300.1.1.1'] as $bad) {
    T::ok(!IpRange::isValidRange($bad), 'невалідний діапазон ' . $bad);
}
T::eq(['1.2.3.4', '10.0.0.0/8', '2001:db8:'], IpRange::parseList("1.2.3.4 # офіс\n10.0.0.0/8, 2001:db8:\n\n# коментар"), 'parseList');

// Білий список за знімком стану.
$state = [
    'settings' => ['whitelist_ranges' => "203.0.113.\n198.51.100.0/24"],
    'whitelist' => [
        ['range' => '192.0.2.10', 'expires' => 0],
        ['range' => '192.0.2.20', 'expires' => 1000],
    ],
];
T::ok(Whitelist::isTrusted('203.0.113.9', $state, 500), 'білий список: префікс із налаштувань');
T::ok(Whitelist::isTrusted('198.51.100.200', $state, 500), 'білий список: CIDR із налаштувань');
T::ok(Whitelist::isTrusted('192.0.2.10', $state, 500), 'білий список: безстроковий запис');
T::ok(Whitelist::isTrusted('192.0.2.20', $state, 500), 'білий список: запис ще діє');
T::ok(!Whitelist::isTrusted('192.0.2.20', $state, 1500), 'білий список: запис прострочено');
T::ok(Whitelist::isTrusted('127.0.0.1', $state, 500), 'loopback завжди довірений');
T::ok(!Whitelist::isTrusted('8.8.8.8', $state, 500), 'чужа IP не довірена');
T::ok(Whitelist::matches('10.1.2.3', '10.0.0.0/8'), 'Whitelist::matches');

// IP клієнта.
T::eq('5.6.7.8', ClientIp::resolve('5.6.7.8', '5.6.7.8', null, false), 'звичайний клієнт');
T::eq('104.16.1.1', ClientIp::resolve('104.16.1.1', '104.16.1.1', '9.9.9.9', false), 'CF-заголовок ігнорується без trust_cloudflare');
T::eq('9.9.9.9', ClientIp::resolve('104.16.1.1', '104.16.1.1', '9.9.9.9', true), 'CF-заголовок від Cloudflare');
T::eq('5.6.7.8', ClientIp::resolve('5.6.7.8', '5.6.7.8', '9.9.9.9', true), 'CF-заголовок не від Cloudflare ігнорується');
T::eq('2001:db8::5', ClientIp::resolve('2606:4700::1', '2606:4700::1', '2001:db8::5', true), 'CF IPv6');
T::eq('104.16.1.1', ClientIp::resolve('104.16.1.1', '104.16.1.1', 'garbage', true), 'сміття в CF-заголовку');
T::eq('5.6.7.8', ClientIp::resolve('', '5.6.7.8', null, false), 'порожній getClientIp → REMOTE_ADDR');
T::eq('0.0.0.0', ClientIp::resolve('', '', null, false), 'нічого немає');

// Країна.
T::eq('UA', CountryGuesser::guess('31.43.10.1'), 'UA за префіксом /16');
T::eq('', CountryGuesser::guess('2001:db8::1'), 'IPv6 → невідомо');
T::eq('', CountryGuesser::guess('nope'), 'невалідна → невідомо');
T::eq('NL', CountryGuesser::guess('193.0.14.129'), 'найдовший префікс a.b.c. виграє');
T::eq(['RU', 'CN', 'BY'], CountryGuesser::parseCountries('ru, CN;by xx1 USA'), 'parseCountries');

// Суб'єкт для лічильників/банів: IPv6 → /64.
T::eq('1.2.3.4', IpRange::subject('1.2.3.4'), 'subject v4');
T::eq('1.2.3.4', IpRange::subject('::ffff:1.2.3.4'), 'subject v4-mapped');
T::eq('2001:db8:1:2::/64', IpRange::subject('2001:db8:1:2:aaaa:bbbb:cccc:dddd'), 'subject v6 → /64');
T::eq('2001:db8:1:2::/64', IpRange::subject('2001:db8:1:2::/64'), 'subject /64 ідемпотентний');
T::eq('', IpRange::subject('garbage'), 'subject невалідний');
T::ok(IpRange::matches('2001:db8:1:2::99', IpRange::subject('2001:db8:1:2::1')), 'адреса входить у свій /64');
T::eq('manual', Whitelist::trustLevel('127.0.0.1', [], 1), 'trustLevel loopback');
T::eq('auto', Whitelist::trustLevel('192.0.2.5', ['whitelist' => [['range' => '192.0.2.5', 'expires' => 100, 'auto' => true]]], 50), 'trustLevel auto');
T::eq('manual', Whitelist::trustLevel('192.0.2.5', ['whitelist' => [['range' => '192.0.2.5', 'expires' => 0, 'auto' => false]]], 50), 'trustLevel manual');
T::eq(null, Whitelist::trustLevel('192.0.2.5', ['whitelist' => [['range' => '192.0.2.5', 'expires' => 10, 'auto' => true]]], 50), 'trustLevel прострочено');

T::done('ip_test');
