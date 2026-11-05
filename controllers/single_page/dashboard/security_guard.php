<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

namespace Concrete\Package\SecurityGuard\Controller\SinglePage\Dashboard;

use Concrete\Core\Page\Controller\DashboardPageController;

defined('C5_EXECUTE') or die('Access Denied.');

/** Батьківська сторінка: одразу веде на «Огляд». */
class SecurityGuard extends DashboardPageController
{
    public function view()
    {
        return $this->buildRedirect(['/dashboard/security_guard/overview']);
    }
}
