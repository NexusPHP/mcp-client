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

namespace Nexus\Mcp\Client\Time;

use Amp\Cancellation;
use Nexus\Clock\Microseconds;

use function Amp\delay;

/**
 * A delay that suspends the current fiber on the event loop.
 */
final readonly class EventLoopDelay implements CancellableDelayInterface
{
    #[\Override]
    public function sleep(float|int $seconds, ?Cancellation $cancellation = null): void
    {
        if (Microseconds::fromSeconds($seconds) < 1) {
            $cancellation?->throwIfRequested();

            return;
        }

        delay($seconds, cancellation: $cancellation);
    }
}
