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
use Nexus\Mcp\Client\Exception\SubscriptionDeliveryDroppedException;
use Nexus\Mcp\Core\Exception\LogicException;
use Nexus\Mcp\Core\Exception\RemoteCallFailedException;
use Nexus\Mcp\Core\Schema\RequestId;
use Nexus\Mcp\Core\Schema\Result\SubscriptionsListenResult;

/**
 * An open `subscriptions/listen` stream, surviving a restart under the same subscription id.
 */
final class SubscriptionStream
{
    private bool $closed = false;

    /**
     * @param Future<SubscriptionsListenResult> $outcome
     * @param \Closure(): void                  $onClose
     *
     * @internal
     */
    public function __construct(
        public readonly RequestId $subscriptionId,
        private readonly Future $outcome,
        private readonly \Closure $onClose,
    ) {
    }

    /**
     * Stops the stream, with subsequent calls no-ops.
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
     * @throws LogicException
     * @throws RemoteCallFailedException
     * @throws SubscriptionDeliveryDroppedException
     */
    public function await(): SubscriptionsListenResult
    {
        if ($this->closed) {
            throw new LogicException(\sprintf(
                'Subscription %s was closed by this client, so it carries no response to await.',
                var_export($this->subscriptionId->id, true),
            ));
        }

        return $this->outcome->await();
    }
}
