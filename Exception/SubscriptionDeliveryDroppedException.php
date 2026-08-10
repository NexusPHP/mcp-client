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

namespace Nexus\Mcp\Client\Exception;

use Nexus\Mcp\Core\Exception\McpExceptionInterface;
use Nexus\Mcp\Core\Schema\RequestId;

/**
 * Thrown when a subscription stream ended because the client shed one of its deliveries.
 */
final class SubscriptionDeliveryDroppedException extends \RuntimeException implements McpExceptionInterface
{
    public function __construct(public readonly RequestId $subscriptionId)
    {
        parent::__construct(
            \sprintf('Subscription %s was ended because a delivery was shed at the client\'s in-flight dispatch cap.', var_export($subscriptionId->id, true)),
        );
    }
}
