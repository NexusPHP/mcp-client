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

namespace Nexus\Mcp\Client\Auth;

use Amp\DeferredFuture;
use Amp\Future;

/**
 * Runs at most one flow per key at a time, handing every caller that arrives while one is in flight the
 * result of the run already under way.
 *
 * @internal
 *
 * @template T
 */
final class SharedFlow
{
    /**
     * @var array<string, Future<T>>
     */
    private array $inFlight = [];

    /**
     * @param \Closure(): T $flow
     *
     * @return T
     */
    public function run(string $key, \Closure $flow): mixed
    {
        $pending = $this->inFlight[$key] ?? null;

        if (null !== $pending) {
            return $pending->await();
        }

        $deferred = new DeferredFuture();

        // Nothing awaits the future when no second caller arrives, which is the common case, so a failed run
        // would otherwise be reported to the loop as an unhandled error.
        $this->inFlight[$key] = $deferred->getFuture()->ignore();

        try {
            $result = $flow();
            $deferred->complete($result);

            return $result;
        } catch (\Throwable $e) {
            $deferred->error($e);

            throw $e;
        } finally {
            unset($this->inFlight[$key]);
        }
    }
}
