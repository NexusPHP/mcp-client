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

namespace Nexus\Mcp\Client\Subscription;

use Amp\Future;
use Nexus\Mcp\Client\Exception\SubscriptionClosedException;
use Nexus\Mcp\Core\Exception\RemoteCallFailedException;
use Nexus\Mcp\Core\Schema\RequestId;
use Nexus\Mcp\Core\Schema\Result\SubscriptionsListenResult;
use Nexus\Mcp\Core\Schema\ResultResponse\SubscriptionsListenResultResponse;

/**
 * An open `subscriptions/listen` stream. Ends when the caller closes it or the server tears it down.
 */
final class SubscriptionStream
{
    private bool $closed = false;

    /**
     * @param Future<SubscriptionsListenResultResponse> $response
     * @param \Closure(): void                          $onClose
     *
     * @internal
     */
    public function __construct(
        public readonly RequestId $subscriptionId,
        private readonly Future $response,
        private readonly \Closure $onClose,
    ) {
    }

    /**
     * Stops the stream, telling the server the subscription is over. Subsequent calls are no-ops.
     */
    public function close(): void
    {
        if ($this->closed) {
            return;
        }

        $this->closed = true;
        ($this->onClose)();
    }

    /**
     * Blocks until the server tears the subscription down of its own accord.
     *
     * @throws RemoteCallFailedException
     * @throws SubscriptionClosedException
     */
    public function await(): SubscriptionsListenResult
    {
        if ($this->closed) {
            // The spec answers an abrupt close with nothing, so this response can never arrive and
            // awaiting it would park the caller for good.
            throw new SubscriptionClosedException($this->subscriptionId);
        }

        return $this->response->await()->result;
    }
}
