<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard\SecurityGuard\Support;

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * Відкладене отримання сервісу з контейнера: якщо реалізації немає чи вона
 * падає в конструкторі, виняток виникне всередині BaseController::safe(),
 * а не зламає всю сторінку.
 */
final class LazyService
{
    private $app;
    private $abstract;
    private $instance;

    public function __construct($app, string $abstract)
    {
        $this->app = $app;
        $this->abstract = $abstract;
    }

    public function __call(string $method, array $args)
    {
        if ($this->instance === null) {
            $this->instance = $this->app->make($this->abstract);
        }

        return $this->instance->{$method}(...$args);
    }
}
