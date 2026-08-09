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

use Amp\Process\Process;

/**
 * Subprocess launcher backed by `Amp\Process\Process`.
 *
 * @internal
 */
final class AmpSubprocessLauncher implements SubprocessLauncherInterface
{
    #[\Override]
    public function launch(array $command, ?string $workingDirectory, array $environment): SubprocessInterface
    {
        return new AmpSubprocess(Process::start($command, $workingDirectory, $environment));
    }
}
