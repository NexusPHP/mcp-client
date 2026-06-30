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
use Nexus\Mcp\Core\JsonRpc\SafeDisplay;
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
    private const string LABEL = 'Stdio client';

    /**
     * Environment variable names safe to inherit by default, across POSIX and Windows hosts.
     */
    private const array INHERITED_ENV_NAMES = [
        'APPDATA',
        'HOME',
        'HOMEDRIVE',
        'HOMEPATH',
        'LOCALAPPDATA',
        'LOGNAME',
        'PATH',
        'PROCESSOR_ARCHITECTURE',
        'SHELL',
        'SYSTEMDRIVE',
        'SYSTEMROOT',
        'TEMP',
        'TERM',
        'USER',
        'USERNAME',
        'USERPROFILE',
    ];

    private readonly LineDuplex $duplex;
    private readonly LoggerInterface $logger;
    private ?Process $process = null;

    /**
     * @param list<string>               $command Subprocess argv (no shell interpretation).
     * @param null|array<string, string> $env     Subprocess environment (`null` prunes to a safe allowlist).
     */
    public function __construct(
        private readonly array $command,
        private readonly ?string $workingDirectory = null,
        private readonly ?array $env = null,
        LoggerInterface $logger = new NullLogger(),
        int $maxLineBytes = LineReader::DEFAULT_MAX_LINE_BYTES,
    ) {
        Assert::that($command)->isList(\sprintf('%s command must be a list, {type} given.', self::LABEL));
        Assert::that(\count($command))->isPositiveInt(\sprintf('%s command must not be empty.', self::LABEL));

        $this->logger = $logger;
        $this->duplex = new LineDuplex(
            hostTransport: self::class,
            label: self::LABEL,
            logger: $logger,
            maxLineBytes: $maxLineBytes,
            onBeforeClose: function (): void {
                if (null === $this->process) {
                    return;
                }

                $this->process->getStdin()->close();
                $this->process->kill();
            },
        );
    }

    /**
     * Builds the pruned default subprocess environment: the inherited-name allowlist
     * populated from `$source`, skipping values that look like exported shell functions.
     *
     * @internal
     *
     * @param null|array<string, string> $source Defaults to the parent process environment.
     *
     * @return array<string, string>
     */
    public static function buildDefaultEnvironment(?array $source = null): array
    {
        $source ??= getenv();
        $environment = [];

        foreach (self::INHERITED_ENV_NAMES as $name) {
            $value = $source[$name] ?? null;

            if (null === $value) {
                continue;
            }

            if (str_starts_with($value, '()')) {
                // Skip exported shell-function definitions (Shellshock mitigation).
                continue;
            }

            $environment[$name] = $value;
        }

        return $environment;
    }

    #[\Override]
    public function start(): void
    {
        $process = Process::start($this->command, $this->workingDirectory, $this->env ?? self::buildDefaultEnvironment());

        try {
            $this->duplex->start($process->getStdout(), $process->getStdin());
        } catch (\Throwable $e) {
            $process->getStdin()->close();
            $process->kill();

            throw $e;
        }

        $this->process = $process;
        $this->logger->info(
            '{label} transport spawned subprocess. Command: {command} (PID {pid}).',
            ['label' => self::LABEL, 'command' => implode(' ', $this->command), 'pid' => $process->getPid()],
        );

        $this->duplex->forwardLines(
            $process->getStderr(),
            function (string $line): void {
                $this->logger->info('Subprocess stderr: {line}', ['line' => SafeDisplay::sanitise($line)]);
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
