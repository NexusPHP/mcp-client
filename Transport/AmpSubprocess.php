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

use Amp\ByteStream\ReadableStream;
use Amp\ByteStream\WritableStream;
use Amp\Cancellation;
use Amp\Process\Process;

/**
 * Presents an `Amp\Process\Process` as a `SubprocessInterface`.
 *
 * @internal
 */
final readonly class AmpSubprocess implements SubprocessInterface
{
    public function __construct(private Process $process)
    {
    }

    #[\Override]
    public function getStdin(): WritableStream
    {
        return $this->process->getStdin();
    }

    #[\Override]
    public function getStdout(): ReadableStream
    {
        return $this->process->getStdout();
    }

    #[\Override]
    public function getStderr(): ReadableStream
    {
        return $this->process->getStderr();
    }

    #[\Override]
    public function getPid(): int
    {
        return $this->process->getPid();
    }

    #[\Override]
    public function join(?Cancellation $cancellation = null): int
    {
        return $this->process->join($cancellation);
    }

    #[\Override]
    public function kill(): void
    {
        $this->process->kill();
    }
}
