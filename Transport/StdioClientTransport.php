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
use Nexus\Assert\Assert;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcMessage;
use Nexus\Mcp\Core\Transport\LineDuplex;
use Nexus\Mcp\Core\Transport\LineReader;
use Nexus\Mcp\Core\Transport\SendContext;
use Nexus\Mcp\Core\Transport\SubscriptionInterface;
use Nexus\Mcp\Core\Transport\TransportInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Stdio MCP client transport. Launches an MCP server subprocess and exchanges
 * line-framed JSON-RPC envelopes over its STDIN/STDOUT.
 */
final class StdioClientTransport implements TransportInterface
{
    private readonly LineDuplex $duplex;
    private readonly LoggerInterface $logger;
    private ?Process $process = null;

    /**
     * @param list<string>          $command Subprocess argv (no shell interpretation).
     * @param array<string, string> $env     Empty inherits the parent process environment.
     */
    public function __construct(
        private readonly array $command,
        private readonly ?string $workingDirectory = null,
        private readonly array $env = [],
        LoggerInterface $logger = new NullLogger(),
        int $maxLineBytes = LineReader::DEFAULT_MAX_LINE_BYTES,
    ) {
        Assert::that($command)->isList('Stdio client command must be a list, {type} given.');
        Assert::that(\count($command))->isPositiveInt('Stdio client command must not be empty.');

        $this->logger = $logger;
        $this->duplex = new LineDuplex(
            hostTransport: self::class,
            label: 'Stdio client',
            logger: $logger,
            maxLineBytes: $maxLineBytes,
            onBeforeClose: function (): void {
                if (null === $this->process) {
                    return;
                }

                $this->process->getStdin()->close();

                if ($this->process->isRunning()) {
                    $this->process->signal(\SIGKILL);
                }
            },
        );
    }

    #[\Override]
    public function start(): void
    {
        $process = Process::start($this->command, $this->workingDirectory, $this->env);

        try {
            $this->duplex->start($process->getStdout(), $process->getStdin());
        } catch (\Throwable $e) {
            $process->getStdin()->close();

            if ($process->isRunning()) {
                $process->signal(\SIGKILL);
            }

            throw $e;
        }

        $this->process = $process;
        $this->logger->info(
            'Stdio client transport spawned subprocess. Command: {command} (PID {pid}).',
            ['command' => implode(' ', $this->command), 'pid' => $process->getPid()],
        );

        $this->duplex->forwardLines(
            $process->getStderr(),
            function (string $line): void {
                $this->logger->info('Subprocess stderr: {line}', ['line' => $line]);
            },
        );
    }

    #[\Override]
    public function send(JsonRpcMessage $message, ?SendContext $context = null): void
    {
        $this->duplex->send($message);
    }

    #[\Override]
    public function close(): void
    {
        $this->duplex->close();
    }

    #[\Override]
    public function sessionId(): ?string
    {
        return null;
    }

    #[\Override]
    public function onMessage(\Closure $listener): SubscriptionInterface
    {
        return $this->duplex->onMessage($listener);
    }

    #[\Override]
    public function onError(\Closure $listener): SubscriptionInterface
    {
        return $this->duplex->onError($listener);
    }

    #[\Override]
    public function onDrain(\Closure $listener): SubscriptionInterface
    {
        return $this->duplex->onDrain($listener);
    }

    #[\Override]
    public function onClose(\Closure $listener): SubscriptionInterface
    {
        return $this->duplex->onClose($listener);
    }
}
