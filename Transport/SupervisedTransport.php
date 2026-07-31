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
use Nexus\Mcp\Core\Exception\SupervisionExhaustedException;
use Nexus\Mcp\Core\Exception\TransportAlreadyClosedException;
use Nexus\Mcp\Core\Exception\TransportAlreadyStartedException;
use Nexus\Mcp\Core\Exception\TransportNotStartedException;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcMessage;
use Nexus\Mcp\Core\Transport\ReceiveContext;
use Nexus\Mcp\Core\Transport\SendContext;
use Nexus\Mcp\Core\Transport\SubscriptionInterface;
use Nexus\Mcp\Core\Transport\SupervisableTransportInterface;
use Nexus\Mcp\Core\Transport\TransportEvents;
use Nexus\Mcp\Core\Transport\TransportInterface;
use Nexus\Mcp\Core\Transport\TransportState;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Revolt\EventLoop;

/**
 * Transport that mints each connection from a factory and respawns the peer when one ends without
 * `close()` having been called. Forwards the caller's listeners to whichever connection is current.
 *
 * @see docs/transports.md for the close, budget and retry semantics.
 */
final class SupervisedTransport implements TransportInterface
{
    private const string LABEL = 'Supervised client';

    private readonly TransportEvents $events;
    private readonly LoggerInterface $logger;
    private TransportState $state = TransportState::Idle;
    private ?SupervisableTransportInterface $inner = null;

    /**
     * False exactly while a live connection still owes the caller a close.
     */
    private bool $connectionEnded = true;

    /**
     * Consecutive respawns that have not yet carried an inbound message.
     */
    private int $restarts = 0;

    /**
     * @var list<SubscriptionInterface>
     */
    private array $subscriptions = [];

    private ?string $respawnWatcher = null;

    /**
     * @param \Closure(): SupervisableTransportInterface $factory      Mints one connection, called once per spawn.
     * @param int                                        $maxRestarts  Consecutive respawns allowed before giving up.
     * @param float                                      $restartDelay Seconds to wait before each respawn.
     */
    public function __construct(
        private readonly \Closure $factory,
        private readonly int $maxRestarts = 3,
        private readonly float $restartDelay = 0.1,
        LoggerInterface $logger = new NullLogger(),
    ) {
        Assert::that($maxRestarts)->isPositiveInt('maxRestarts must be a positive integer, {value} given.');
        Assert::that($restartDelay)->isBetween(0.0, \PHP_FLOAT_MAX, message: 'restartDelay must not be negative, {value} given.');

        $this->logger = $logger;
        $this->events = new TransportEvents();
    }

    #[\Override]
    public function start(): void
    {
        match ($this->state) {
            TransportState::Running => throw new TransportAlreadyStartedException(transport: self::class),
            TransportState::Closed => throw new TransportAlreadyClosedException(operation: 'start'),
            TransportState::Idle => null,
        };

        // Only a connection that actually started makes this transport running, so a failed launch stays
        // retryable instead of reporting itself as already started.
        $this->spawn();
        $this->state = TransportState::Running;
    }

    #[\Override]
    public function send(JsonRpcMessage $message, ?SendContext $context = null): void
    {
        if (TransportState::Idle === $this->state) {
            throw new TransportNotStartedException(operation: 'send');
        }

        // Released on close, and between a peer's death and its replacement being spawned. The connection
        // the caller wrote against is gone, and the one that replaces it never carried the request.
        if (null === $this->inner) {
            throw new TransportAlreadyClosedException(operation: 'send');
        }

        $this->inner->send($message, $context);
    }

    #[\Override]
    public function close(): void
    {
        // Every step below is idempotent, so a second call needs no guard of its own.
        $this->state = TransportState::Closed;

        if (null !== $this->respawnWatcher) {
            EventLoop::cancel($this->respawnWatcher);
            $this->respawnWatcher = null;
        }

        try {
            // Told before delegating, so a peer that throws on the way down cannot swallow the signal.
            $this->endConnection();
        } finally {
            $this->retireConnection();
        }
    }

    #[\Override]
    public function onMessage(\Closure $listener): SubscriptionInterface
    {
        return $this->events->onMessage($listener);
    }

    #[\Override]
    public function onError(\Closure $listener): SubscriptionInterface
    {
        return $this->events->onError($listener);
    }

    #[\Override]
    public function onDrain(\Closure $listener): SubscriptionInterface
    {
        return $this->events->onDrain($listener);
    }

    #[\Override]
    public function onClose(\Closure $listener): SubscriptionInterface
    {
        return $this->events->onClose($listener);
    }

    /**
     * Builds a connection, binds this instance's listeners to it, and starts it.
     *
     * Every path that supersedes a connection releases it first, so a peer that has been replaced holds
     * none of these listeners and cannot emit through this instance afterwards.
     */
    private function spawn(): void
    {
        $inner = ($this->factory)();
        $this->inner = $inner;

        // Set only once a connection exists, so a factory that throws leaves no close owed.
        $this->connectionEnded = false;

        $this->subscriptions = [
            $inner->onMessage(function (array $envelope, ReceiveContext $context): void {
                // A served message proves the replacement works, so the budget bounds consecutive
                // failures rather than the lifetime of the supervision.
                $this->restarts = 0;
                $this->events->emitMessage($envelope, $context);
            }),
            $inner->onError($this->events->emitError(...)),
            $inner->onDrain($this->events->emitDrain(...)),
            $inner->onClose($this->endConnection(...)),
            $inner->onUnexpectedExit(function (?int $exitCode): void {
                try {
                    $this->endConnection();
                } finally {
                    // A close listener that throws aborts the chain, and must not take supervision with it.
                    $this->scheduleRespawn($exitCode);
                }
            }),
        ];

        try {
            $inner->start();
        } catch (\Throwable $e) {
            // A connection that never started is not one this instance can serve: it neither stays
            // attached to the caller's listeners nor owes them a close.
            $this->connectionEnded = true;
            $this->releaseConnection();

            throw $e;
        }
    }

    /**
     * Emits the caller's close for the current connection, once, whichever of the peer's death signals
     * arrived first.
     */
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

        ++$this->restarts;

        if ($this->restarts > $this->maxRestarts) {
            $this->logger->error(
                '{label} transport exhausted its restart budget of {budget}.',
                ['label' => self::LABEL, 'budget' => $this->maxRestarts],
            );

            try {
                $this->events->emitError(new SupervisionExhaustedException($this->maxRestarts));
            } finally {
                $this->close();
            }

            return;
        }

        $this->logger->warning(
            '{label} transport respawning the peer after an unexpected exit (code {exitCode}), attempt {attempt} of {budget}.',
            ['label' => self::LABEL, 'exitCode' => $exitCode ?? 'unknown', 'attempt' => $this->restarts, 'budget' => $this->maxRestarts],
        );

        $this->retireConnection();

        // close() cancels this watcher, so reaching the callback proves supervision is still wanted.
        $this->respawnWatcher = EventLoop::delay($this->restartDelay, function (): void {
            $this->respawnWatcher = null;

            try {
                $this->spawn();
            } catch (\Throwable $e) {
                // A replacement that cannot be built is itself a failed attempt, so it spends budget
                // instead of escaping into the event loop's error handler.
                $this->events->emitError($e);
                $this->scheduleRespawn(null);
            }
        });
    }

    /**
     * Closes the current connection and drops this instance's listeners from it.
     */
    private function retireConnection(): void
    {
        $inner = $this->inner;

        try {
            // Closing first keeps the peer's drain and close on the caller's chain, and forces EOF on a
            // read loop the peer left parked on a stream something else still holds open.
            $inner?->close();
        } finally {
            $this->releaseConnection();
        }
    }

    /**
     * Drops this instance's listeners from the current connection and forgets it.
     */
    private function releaseConnection(): void
    {
        foreach ($this->subscriptions as $subscription) {
            $subscription->dispose();
        }

        $this->subscriptions = [];
        $this->inner = null;
    }
}
