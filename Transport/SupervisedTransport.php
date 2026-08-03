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
use Nexus\Mcp\Core\Transport\ReconnectingTransportInterface;
use Nexus\Mcp\Core\Transport\SendContext;
use Nexus\Mcp\Core\Transport\Subscription;
use Nexus\Mcp\Core\Transport\SubscriptionInterface;
use Nexus\Mcp\Core\Transport\SupervisableTransportInterface;
use Nexus\Mcp\Core\Transport\TransportEvents;
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
final class SupervisedTransport implements ReconnectingTransportInterface
{
    /**
     * Seconds the restart count is measured over before it starts again from zero.
     */
    public const float DEFAULT_RESTART_WINDOW = 60.0;

    private const string LABEL = 'Supervised client';

    private readonly TransportEvents $events;
    private readonly LoggerInterface $logger;

    /**
     * @var \Closure(): float
     */
    private readonly \Closure $clock;

    private TransportState $state = TransportState::Idle;
    private ?SupervisableTransportInterface $inner = null;

    /**
     * False exactly while a live connection still owes the caller a close.
     */
    private bool $connectionEnded = true;

    /**
     * Respawns counted so far in the current window.
     */
    private int $restarts = 0;

    /**
     * When the current window opened, as a reading from `$clock`. Zero until the first respawn.
     */
    private float $windowStartedAt = 0.0;

    /**
     * @var list<SubscriptionInterface>
     */
    private array $subscriptions = [];

    /**
     * @var array<int, \Closure(): void>
     */
    private array $reconnectListeners = [];

    private ?string $respawnWatcher = null;

    /**
     * True from the moment a replacement is decided on until it is serving. Tracked apart from the
     * watcher because arming one happens after a retire that suspends.
     */
    private bool $respawning = false;

    /**
     * @param \Closure(): SupervisableTransportInterface $factory       Mints one connection, called once per spawn.
     * @param int                                        $maxRestarts   Respawns allowed within one window before giving up.
     * @param float                                      $restartDelay  Seconds to wait before each respawn.
     * @param float                                      $restartWindow Seconds the restart count is measured over.
     * @param null|\Closure(): float                     $clock         Reads the current time in **seconds**, replaceable so the window boundary is exact under test. A source in other units silently makes the budget unspendable.
     */
    public function __construct(
        private readonly \Closure $factory,
        private readonly int $maxRestarts = 3,
        private readonly float $restartDelay = 0.1,
        LoggerInterface $logger = new NullLogger(),
        private readonly float $restartWindow = self::DEFAULT_RESTART_WINDOW,
        ?\Closure $clock = null,
    ) {
        Assert::that($maxRestarts)->isPositiveInt('maxRestarts must be a positive integer, {value} given.');
        Assert::that($restartDelay)->isBetween(0.0, \PHP_FLOAT_MAX, message: 'restartDelay must not be negative, {value} given.');
        Assert::that($restartWindow)->isBetween(\PHP_FLOAT_EPSILON, \PHP_FLOAT_MAX, message: 'restartWindow must be positive, {value} given.');

        $this->logger = $logger;
        $this->clock = $clock ?? static fn(): float => microtime(true);
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

        // The dead connection's own close already went out, and the caller has been holding its state for
        // a replacement ever since. Abandoning that replacement owes them a second close, or they wait on
        // a peer that is never coming. A replacement that is already up owes them nothing extra: the
        // teardown below emits for it like any other live connection.
        $abandonsAReplacement = $this->respawning && $this->connectionEnded;
        $this->respawning = false;

        if (null !== $this->respawnWatcher) {
            EventLoop::cancel($this->respawnWatcher);
            $this->respawnWatcher = null;
        }

        try {
            // Told before delegating, so a peer that throws on the way down cannot swallow the signal.
            $this->endConnection();

            if ($abandonsAReplacement) {
                try {
                    $this->events->emitClose();
                } catch (\Throwable $e) {
                    // Reached from a loop callback on the exhausted-budget path, and one listener failing
                    // must not strand the rest, which is the very thing this emission exists to prevent.
                    $this->events->emitError($e);
                }
            }
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

    #[\Override]
    public function isReconnecting(): bool
    {
        return $this->respawning;
    }

    #[\Override]
    public function onReconnect(\Closure $listener): SubscriptionInterface
    {
        $id = spl_object_id($listener);
        $this->reconnectListeners[$id] = $listener;

        return new Subscription(function () use ($id): void {
            unset($this->reconnectListeners[$id]);
        });
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
            $inner->onMessage($this->events->emitMessage(...)),
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

        $now = ($this->clock)();

        // Counted over a moving window, so a peer that ran for a while and then died starts a fresh
        // budget. Treating a served message as proof of health cannot work: the protocol layer replays
        // its own state on every reconnect, so even a crash-looping peer answers something.
        // The window opens at the first restart rather than at whatever the clock's origin happens to be:
        // a monotonic source legitimately starts near zero, which would anchor it before the process ran.
        if (0 === $this->restarts || $this->restartWindow < $now - $this->windowStartedAt) {
            $this->restarts = 0;
            $this->windowStartedAt = $now;
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

        // Set before retiring, which suspends on any transport that drains its streams on the way down.
        // Anything the close already queued runs inside that suspension and must see a replacement coming.
        $this->respawning = true;

        $this->retireConnection();

        // Retiring suspends on any transport that drains on the way down, so a close can land inside it.
        // Arming now would resurrect a peer the caller has already been told is never coming, and nothing
        // afterwards would ever close it.
        if (TransportState::Running !== $this->state) {
            return;
        }

        // close() cancels this watcher, so reaching the callback proves supervision was still wanted.
        $this->respawnWatcher = EventLoop::delay($this->restartDelay, function (): void {
            $this->respawnWatcher = null;

            try {
                $this->spawn();
            } catch (\Throwable $e) {
                // A replacement that cannot be built is itself a failed attempt, so it spends budget
                // instead of escaping into the event loop's error handler.
                $this->events->emitError($e);
                $this->scheduleRespawn(null);

                return;
            }

            // Starting suspends too, so the same close can land while the replacement comes up. It is
            // nobody's peer then, and announcing it would have listeners write to a closed transport.
            if (TransportState::Running !== $this->state) {
                // The close that got here retired this connection on its way past: `spawn()` publishes
                // it before `start()` suspends, so there is nothing left to release.
                return;
            }

            $this->respawning = false;

            // Announced only once the replacement is serving, so a listener that rebuilds per-connection
            // state writes to a peer that can take it.
            foreach ($this->reconnectListeners as $listener) {
                try {
                    $listener();
                } catch (\Throwable $e) {
                    // One listener's failure must not cost the rest theirs: the protocol layer rebuilding
                    // its state is in this chain, and losing it silently strands every open stream.
                    $this->events->emitError($e);
                }
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
