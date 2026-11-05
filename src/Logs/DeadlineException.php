<?php
// Copyright (c) 2026 Andrii Pasichnyk. All rights reserved. See LICENSE.

declare(strict_types=1);

namespace PasichDev\SecurityGuard\Logs;

/** Вичерпано ліміт часу посеред перерахунку групи днів (група не записується). */
final class DeadlineException extends \RuntimeException
{
}
