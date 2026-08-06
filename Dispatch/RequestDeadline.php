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

namespace Nexus\Mcp\Client\Dispatch;

use Amp\Cancellation;
use Amp\DeferredCancellation;
use Revolt\EventLoop;

/**
 * Bounds how long one outbound request may go unanswered. `extend()` restarts the idle timer, so a peer
 * reporting progress keeps its request alive, while the optional ceiling runs from creation and ignores
 * progress entirely.
 *
 * Both timers are unreferenced, so a deadline never keeps the event loop alive on its own. Reaching one
 * takes a transport holding its own I/O open, which is what a request in flight always has.
 *
 * @internal
 */
final class RequestDeadline
{
    /**
     * Seconds the deadline that fired was measuring, or `0.0` while none has.
     */
    private float $elapsed = 0.0;

    private bool $fired = false;
    private readonly DeferredCancellation $expiry;
    private string $idleCallbackId;
    private readonly ?string $ceilingCallbackId;

    /**
     * @param float      $timeout    Seconds the peer may stay silent before the request is abandoned
     * @param null|float $maxTimeout Seconds the request may run in total however much progress arrives, or `null` to leave it unbounded
     */
    public function __construct(private readonly float $timeout, ?float $maxTimeout = null)
    {
        $this->expiry = new DeferredCancellation();
        $this->idleCallbackId = $this->arm($timeout);

        // The ceiling never lands before the idle timeout it bounds: a nearer one could only pre-empt it,
        // cutting the request short of the deadline it was given. That is the shape a per-request override
        // longer than the client-wide ceiling produces.
        $this->ceilingCallbackId = null === $maxTimeout ? null : $this->arm(max($maxTimeout, $timeout));
    }

    public function getCancellation(): Cancellation
    {
        return $this->expiry->getCancellation();
    }

    /**
     * Seconds the deadline that fired was measuring, or `0.0` while none has.
     */
    public function readElapsed(): float
    {
        return $this->elapsed;
    }

    /**
     * Restarts the idle timer, leaving the ceiling to run on.
     */
    public function extend(): void
    {
        EventLoop::cancel($this->idleCallbackId);
        $this->idleCallbackId = $this->arm($this->timeout);
    }

    /**
     * Disarms both timers once the request has settled.
     */
    public function release(): void
    {
        EventLoop::cancel($this->idleCallbackId);

        if (null !== $this->ceilingCallbackId) {
            EventLoop::cancel($this->ceilingCallbackId);
        }
    }

    private function arm(float $seconds): string
    {
        $callbackId = EventLoop::delay($seconds, function () use ($seconds): void {
            // Whichever deadline fires first is the one that abandoned the request. A later one, such as
            // an idle timer still armed past the ceiling, must not restate what elapsed.
            if (! $this->fired) {
                $this->fired = true;
                $this->elapsed = $seconds;
            }

            $this->expiry->cancel();
        });

        // A deadline bounds work rather than being work, so it must never be what keeps the loop alive.
        // Were it referenced, one that outlived its request would hold the loop open until it fired.
        EventLoop::unreference($callbackId);

        return $callbackId;
    }
}
