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
 * Bound on how long one outbound request may go unanswered.
 *
 * @internal
 */
final class RequestDeadline
{
    private float $elapsed = 0.0;
    private bool $fired = false;
    private readonly DeferredCancellation $expiry;
    private string $idleCallbackId;
    private readonly ?string $ceilingCallbackId;

    public function __construct(
        private readonly float $timeout,
        ?float $maxTimeout = null,
    ) {
        $this->expiry = new DeferredCancellation();
        $this->idleCallbackId = $this->arm($timeout);
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
            if (! $this->fired) {
                $this->fired = true;
                $this->elapsed = $seconds;
            }

            $this->expiry->cancel();
        });

        EventLoop::unreference($callbackId);

        return $callbackId;
    }
}
