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

use Nexus\Mcp\Client\Dispatch\ProgressListenerRegistry;
use Nexus\Mcp\Core\Handler\NotificationHandlerInterface;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcNotification;
use Nexus\Mcp\Core\Schema\Notification\ProgressNotification;

/**
 * Notification handler routing `notifications/progress` to the per-call listener registered for its token.
 *
 * @internal
 *
 * @implements NotificationHandlerInterface<'notifications/progress'>
 */
final readonly class RoutingProgressNotificationHandler implements NotificationHandlerInterface
{
    /**
     * @param null|NotificationHandlerInterface<non-empty-string> $fallback
     */
    public function __construct(private ProgressListenerRegistry $listeners, private ?NotificationHandlerInterface $fallback = null)
    {
    }

    #[\Override]
    public function handle(JsonRpcNotification $notification): void
    {
        \assert($notification instanceof ProgressNotification);

        $params = $notification->params;
        $listener = $this->listeners->get($params->progressToken);

        if (null === $listener) {
            $this->fallback?->handle($notification);

            return;
        }

        $listener($params->progress, $params->total, $params->message);
    }
}
