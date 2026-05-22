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

namespace Nexus\Mcp\Client\Handler\Notification;

use Nexus\Mcp\Core\Handler\NotificationHandlerInterface;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcNotification;
use Nexus\Mcp\Core\Schema\Notification\LoggingMessageNotification;

/**
 * Adapts a closure into a `notifications/message` handler, so consumers can
 * register a callback instead of an interface implementation.
 *
 * @implements NotificationHandlerInterface<'notifications/message'>
 */
final readonly class LoggingMessageNotificationHandler implements NotificationHandlerInterface
{
    /**
     * @param \Closure(LoggingMessageNotification): void $listener
     */
    public function __construct(private \Closure $listener)
    {
    }

    #[\Override]
    public function handle(JsonRpcNotification $notification): void
    {
        \assert($notification instanceof LoggingMessageNotification);

        ($this->listener)($notification);
    }
}
