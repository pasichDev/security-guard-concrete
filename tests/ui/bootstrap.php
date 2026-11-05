<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

/*
 * Мінімальні заглушки Concrete для перевірки шаблонів і допоміжних класів
 * інтерфейсу без встановленого CMS (чистий PHP 8.2).
 */

declare(strict_types=1);

namespace Concrete\Core\Application {
    class Application
    {
        /** @var array<string, mixed> */
        public $bindings = [];

        public function make($abstract, array $args = [])
        {
            if (!array_key_exists($abstract, $this->bindings)) {
                throw new \RuntimeException('No binding for ' . $abstract);
            }
            $b = $this->bindings[$abstract];

            return $b instanceof \Closure ? $b($args) : $b;
        }
    }
}

namespace {
    define('C5_EXECUTE', true);
    error_reporting(E_ALL);
    set_error_handler(static function (int $no, string $str, string $file, int $line) {
        throw new \ErrorException($str, 0, $no, $file, $line);
    });
    date_default_timezone_set('Europe/Kyiv');

    const SG_PKG = __DIR__ . '/../..';

    /** Переклади: якщо задано SG_LOCALE=uk_UA — з messages.po, інакше вихідний текст. */
    $GLOBALS['sg_translations'] = [];
    if (getenv('SG_LOCALE') === 'uk_UA') {
        $GLOBALS['sg_translations'] = sg_parse_po(SG_PKG . '/languages/uk_UA/LC_MESSAGES/messages.po');
    }

    function sg_parse_po(string $file): array
    {
        $out = [];
        if (!is_file($file)) {
            return $out;
        }
        $id = null;
        $str = null;
        $cur = null;
        $flush = static function () use (&$id, &$str, &$out) {
            if ($id !== null && $id !== '' && $str !== null && $str !== '') {
                $out[$id] = $str;
            }
        };
        foreach (file($file) as $line) {
            $line = rtrim($line, "\r\n");
            if (strpos($line, 'msgid ') === 0) {
                $flush();
                $id = stripcslashes(substr($line, 7, -1));
                $str = null;
                $cur = 'id';
            } elseif (strpos($line, 'msgstr ') === 0) {
                $str = stripcslashes(substr($line, 8, -1));
                $cur = 'str';
            } elseif ($line !== '' && $line[0] === '"') {
                $chunk = stripcslashes(substr($line, 1, -1));
                if ($cur === 'id') {
                    $id .= $chunk;
                } elseif ($cur === 'str') {
                    $str .= $chunk;
                }
            }
        }
        $flush();

        return $out;
    }

    /** @var array<string,bool> усі рядки, що пройшли через t() — для перевірки повноти перекладу */
    $GLOBALS['sg_used_strings'] = [];

    function t($text, ...$args)
    {
        $text = (string) $text;
        $GLOBALS['sg_used_strings'][$text] = true;
        $tr = $GLOBALS['sg_translations'][$text] ?? $text;

        return $args ? vsprintf($tr, $args) : $tr;
    }

    function h($s)
    {
        return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
    }

    function app($abstract = null)
    {
        $app = $GLOBALS['sg_app'];

        return $abstract === null ? $app : $app->make($abstract);
    }

    class URL
    {
        public static function to($path)
        {
            return is_object($path) ? '/dashboard/security_guard/overview' : '/index.php' . $path;
        }
    }

    class View
    {
        public static function element($name, $args = [], $pkg = null)
        {
            (static function () use ($name, $args) {
                extract($args);
                include SG_PKG . '/elements/' . $name . '.php';
            })();
        }
    }

    class SgFakeView
    {
        public $path;

        public function __construct(string $path)
        {
            $this->path = $path;
        }

        public function action($a)
        {
            return '/index.php' . $this->path . '/' . $a;
        }
    }

    class SgFakeToken
    {
        public function output($action = '', $return = false)
        {
            $s = '<input type="hidden" name="ccm_token" value="1:' . h(md5($action)) . '">';
            if ($return) {
                return $s;
            }
            echo $s;
        }

        public function generate($action = '')
        {
            return '1:' . md5($action);
        }
    }

    class SgFakeDate
    {
        public function formatDateTime($v)
        {
            return date('d.m.Y H:i', (int) $v);
        }

        public function getTimezone($tz)
        {
            return new DateTimeZone('Europe/Kyiv');
        }
    }

    $GLOBALS['sg_app'] = new \Concrete\Core\Application\Application();
    $GLOBALS['sg_app']->bindings['date'] = new SgFakeDate();

    foreach (['format', 'period', 'ip_range'] as $f) {
        require_once SG_PKG . '/controllers/single_page/dashboard/security_guard/support/' . $f . '.php';
    }
}
