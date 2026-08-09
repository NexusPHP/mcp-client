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

use Amp\DeferredFuture;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcNotification;
use Nexus\Mcp\Core\Schema\RequestId;
use Nexus\Mcp\Core\Schema\Result\SubscriptionsListenResult;
use Nexus\Mcp\Core\Schema\SubscriptionFilter;

/**
 * One `subscriptions/listen` stream the client holds open past the connection it was opened on.
 *
 * @internal
 */
final readonly class OpenSubscription
{
    /**
     * @param \Closure(JsonRpcNotification<non-empty-string>): void $onNotification
     * @param DeferredFuture<SubscriptionsListenResult>             $outcome
     */
    public function __construct(
        public RequestId $subscriptionId,
        public SubscriptionFilter $notifications,
        public \Closure $onNotification,
        public DeferredFuture $outcome,
    ) {
    }
}
