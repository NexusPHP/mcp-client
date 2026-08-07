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
use Amp\CancelledException;
use Amp\Process\ProcessException;

/**
 * A running MCP server subprocess: its three standard streams, its identifier, and the two
 * lifecycle operations a transport performs on it.
 *
 * @internal
 */
interface SubprocessInterface
{
    public function getStdin(): WritableStream;

    public function getStdout(): ReadableStream;

    public function getStderr(): ReadableStream;

    public function getPid(): int;

    /**
     * Awaits the exit and answers its status code.
     *
     * @throws CancelledException
     * @throws ProcessException
     */
    public function join(?Cancellation $cancellation = null): int;

    public function kill(): void;
}
