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

use Nexus\Mcp\Client\Dispatch\DiscoveredServerCapabilities;
use Nexus\Mcp\Core\Handler\NotificationHandlerInterface;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcNotification;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Gate dropping an extension-owned notification from a server that did not advertise the extension.
 *
 * @internal
 *
 * @implements NotificationHandlerInterface<non-empty-string>
 */
final readonly class ExtensionGateNotificationHandler implements NotificationHandlerInterface
{
    /**
     * @param non-empty-string                               $identifier
     * @param NotificationHandlerInterface<non-empty-string> $handler
     */
    public function __construct(
        private string $identifier,
        private NotificationHandlerInterface $handler,
        private DiscoveredServerCapabilities $serverCapabilities,
        private LoggerInterface $logger = new NullLogger(),
    ) {
    }

    #[\Override]
    public function handle(JsonRpcNotification $notification): void
    {
        $capabilities = $this->serverCapabilities->current();

        if (null !== $capabilities && ! \array_key_exists($this->identifier, $capabilities->extensions ?? [])) {
            $this->logger->warning(
                'Dropping {method}: the server did not advertise extension {extension}.',
                ['method' => $notification::getMethod(), 'extension' => $this->identifier],
            );

            return;
        }

        $this->handler->handle($notification);
    }
}
