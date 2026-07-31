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
 * Thrown when a subscription stream the caller already closed is awaited.
 */
final class SubscriptionClosedException extends \LogicException implements McpExceptionInterface
{
    public function __construct(public readonly RequestId $subscriptionId, ?\Throwable $previous = null)
    {
        parent::__construct(
            \sprintf('Subscription %s was closed by this client, so it carries no response to await.', var_export($subscriptionId->id, true)),
            previous: $previous,
        );
    }
}
