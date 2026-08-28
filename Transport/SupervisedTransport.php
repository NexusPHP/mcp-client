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

use Nexus\Assert\Assert;
use Nexus\Clock\HighResolutionStopwatch;
use Nexus\Clock\Stopwatch;
use Nexus\Mcp\Core\Exception\SupervisionExhaustedException;
use Nexus\Mcp\Core\Exception\TransportAlreadyClosedException;
use Nexus\Mcp\Core\Exception\TransportAlreadyStartedException;
use Nexus\Mcp\Core\Exception\TransportNotStartedException;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcMessage;
use Nexus\Mcp\Core\Transport\ListenerHandle;
use Nexus\Mcp\Core\Transport\ListenerHandleInterface;
use Nexus\Mcp\Core\Transport\ReconnectingTransportInterface;
use Nexus\Mcp\Core\Transport\SendContext;
use Nexus\Mcp\Core\Transport\SupervisableTransportInterface;
use Nexus\Mcp\Core\Transport\TransportEvents;
use Nexus\Mcp\Core\Transport\TransportState;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Revolt\EventLoop;

/**
 * Transport that mints each connection from a factory and respawns the peer when one ends unasked.
 *
 * @see docs/transports/supervised.md for the close, budget and retry semantics.
 */
final class SupervisedTransport implements ReconnectingTransportInterface
{
    /**
     * Seconds the restart count is measured over.
     */
    public const float DEFAULT_RESTART_WINDOW = 60.0;

    private readonly TransportEvents $events;
    private TransportState $state = TransportState::Idle;
    private ?SupervisableTransportInterface $inner = null;
    private bool $connectionEnded = true;
    private int $restartsInWindow = 0;

    /**
     * A reading from `$stopwatch`, or zero until the first respawn.
     */
    private float $windowStartedAt = 0.0;

    /**
     * @var list<ListenerHandleInterface>
     */
    private array $subscriptions = [];

    /**
     * @var array<int, \Closure(): void>
     */
    private array $reconnectListeners = [];

    private ?string $respawnWatcher = null;

    /**
     * True from the moment a replacement is decided on until it is serving.
     */
    private bool $respawning = false;

    /**
     * @param \Closure(): SupervisableTransportInterface $factory       Mints one connection, called once per spawn.
     * @param int                                        $maxRestarts   Respawns allowed within one window before giving up.
     * @param float                                      $restartDelay  Seconds to wait before each respawn.
     * @param float                                      $restartWindow Seconds the restart count is measured over.
     */
    public function __construct(
        private readonly \Closure $factory,
        private readonly int $maxRestarts = 3,
        private readonly float $restartDelay = 0.1,
        private readonly LoggerInterface $logger = new NullLogger(),
        private readonly float $restartWindow = self::DEFAULT_RESTART_WINDOW,
        private readonly Stopwatch $stopwatch = new HighResolutionStopwatch(),
    ) {
        Assert::that($maxRestarts)->isPositiveInt('maxRestarts must be a positive integer, {value} given.');
        Assert::that($restartDelay)->isBetween(0.0, \PHP_FLOAT_MAX, message: 'restartDelay must not be negative, {value} given.');
        Assert::that($restartWindow)->isBetween(\PHP_FLOAT_EPSILON, \PHP_FLOAT_MAX, message: 'restartWindow must be positive, {value} given.');

        $this->events = TransportEvents::create($this->logger, 'Supervised client');
    }

    #[\Override]
    public function start(): void
    {
        match ($this->state) {
            TransportState::Running => throw new TransportAlreadyStartedException(transport: self::class),
            TransportState::Closed => throw new TransportAlreadyClosedException(operation: 'start'),
            TransportState::Idle => null,
        };

        $this->spawn();
        $this->state = TransportState::Running;
    }

    #[\Override]
    public function send(JsonRpcMessage $message, ?SendContext $context = null): void
    {
        if (TransportState::Idle === $this->state) {
            throw new TransportNotStartedException(operation: 'send');
        }

        if (null === $this->inner) {
            throw new TransportAlreadyClosedException(operation: 'send');
        }

        $this->inner->send($message, $context);
    }

    #[\Override]
    public function close(): void
    {
        $coldClose = TransportState::Idle === $this->state;
        $this->state = TransportState::Closed;

        $abandonsAReplacement = $this->respawning && $this->connectionEnded;
        $this->respawning = false;

        if (null !== $this->respawnWatcher) {
            EventLoop::cancel($this->respawnWatcher);
            $this->respawnWatcher = null;
        }

        try {
            // The inner's own close relays drain first, then close, through the live subscriptions.
            $this->retireConnection();
        } finally {
            if ($coldClose) {
                $this->events->emitDrain();
            }

            if ($abandonsAReplacement || $coldClose) {
                try {
                    $this->events->emitClose();
                } catch (\Throwable $e) {
                    $this->events->emitError($e);
                }
            } else {
                $this->endConnection();
            }
        }
    }

    #[\Override]
    public function onMessage(\Closure $listener): ListenerHandleInterface
    {
        return $this->events->onMessage($listener);
    }

    #[\Override]
    public function onError(\Closure $listener): ListenerHandleInterface
    {
        return $this->events->onError($listener);
    }

    #[\Override]
    public function onDrain(\Closure $listener): ListenerHandleInterface
    {
        return $this->events->onDrain($listener);
    }

    #[\Override]
    public function onClose(\Closure $listener): ListenerHandleInterface
    {
        return $this->events->onClose($listener);
    }

    #[\Override]
    public function isReconnecting(): bool
    {
        return $this->respawning;
    }

    #[\Override]
    public function onReconnect(\Closure $listener): ListenerHandleInterface
    {
        $id = spl_object_id($listener);
        $this->reconnectListeners[$id] = $listener;

        return new ListenerHandle(function () use ($id): void {
            unset($this->reconnectListeners[$id]);
        });
    }

    private function spawn(): void
    {
        $inner = ($this->factory)();
        $this->inner = $inner;

        $this->connectionEnded = false;

        $this->subscriptions = [
            $inner->onMessage($this->events->emitMessage(...)),
            $inner->onError($this->events->emitError(...)),
            $inner->onDrain($this->events->emitDrain(...)),
            $inner->onClose($this->endConnection(...)),
            $inner->onUnexpectedExit(function (?int $exitCode): void {
                try {
                    $this->endConnection();
                } finally {
                    $this->scheduleRespawn($exitCode);
                }
            }),
        ];

        try {
            $inner->start();
        } catch (\Throwable $e) {
            $this->connectionEnded = true;
            $this->releaseConnection();

            throw $e;
        }
    }

    private function endConnection(): void
    {
        if ($this->connectionEnded) {
            return;
        }

        $this->connectionEnded = true;
        $this->events->emitClose();
    }

    private function scheduleRespawn(?int $exitCode): void
    {
        if (TransportState::Running !== $this->state) {
            return;
        }

        $now = $this->stopwatch->read();

        if (0 === $this->restartsInWindow || $this->restartWindow < $now - $this->windowStartedAt) {
            $this->restartsInWindow = 0;
            $this->windowStartedAt = $now;
        }

        ++$this->restartsInWindow;

        if ($this->restartsInWindow > $this->maxRestarts) {
            $this->logger->error(
                'Supervised client transport exhausted its restart budget of {budget}.',
                ['budget' => $this->maxRestarts],
            );

            try {
                $this->events->emitError(new SupervisionExhaustedException($this->maxRestarts));
            } finally {
                $this->close();
            }

            return;
        }

        $this->logger->warning(
            'Supervised client transport respawning the peer after an unexpected exit (code {exitCode}), attempt {attempt} of {budget}.',
            ['exitCode' => $exitCode ?? 'unknown', 'attempt' => $this->restartsInWindow, 'budget' => $this->maxRestarts],
        );

        $this->respawning = true;

        $this->retireConnection();

        if (TransportState::Running !== $this->state) {
            return;
        }

        $this->respawnWatcher = EventLoop::delay($this->restartDelay, function (): void {
            $this->respawnWatcher = null;

            try {
                $this->spawn();
            } catch (\Throwable $e) {
                $this->events->emitError($e);
                $this->scheduleRespawn(null);

                return;
            }

            if (TransportState::Running !== $this->state) {
                return;
            }

            $this->respawning = false;

            foreach ($this->reconnectListeners as $listener) {
                try {
                    $listener();
                } catch (\Throwable $e) {
                    $this->events->emitError($e);
                }
            }
        });
    }

    private function retireConnection(): void
    {
        $inner = $this->inner;

        try {
            $inner?->close();
        } finally {
            $this->releaseConnection();
        }
    }

    private function releaseConnection(): void
    {
        foreach ($this->subscriptions as $subscription) {
            $subscription->dispose();
        }

        $this->subscriptions = [];
        $this->inner = null;
    }
}
