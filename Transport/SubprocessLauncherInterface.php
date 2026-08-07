<?php

declare(strict_types=1);

/**
 * This file is part of the Nexus MCP SDK package.
 *
 * (c) 2026 John Paul E. Balandan, CPA <paulbalandan@gmail.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Nexus\Mcp\Client\Transport;

use Amp\Process\ProcessException;

/**
 * Starts the MCP server subprocess a stdio transport speaks to.
 *
 * @internal
 */
interface SubprocessLauncherInterface
{
    /**
     * @param list<string>          $command     Subprocess argv (no shell interpretation).
     * @param array<string, string> $environment Subprocess environment, passed verbatim.
     *
     * @throws ProcessException
     */
    public function launch(array $command, ?string $workingDirectory, array $environment): SubprocessInterface;
}
