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

namespace Nexus\Mcp\Client;

use Nexus\Assert\Assert;
use Nexus\Mcp\Client\Dispatch\ClientInitializationGate;
use Nexus\Mcp\Client\Dispatch\ClientMessageDispatcher;
use Nexus\Mcp\Core\Dispatch\PendingOutboundRequests;
use Nexus\Mcp\Core\Handler\HandlerRegistry;
use Nexus\Mcp\Core\Handler\NotificationHandlerInterface;
use Nexus\Mcp\Core\Handler\RequestHandlerInterface;
use Nexus\Mcp\Core\Schema\Icon;
use Nexus\Mcp\Core\Schema\Implementation;
use Nexus\Mcp\Core\Schema\Result;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Fluent builder that assembles the per-feature handler registries, the
 * client-side dispatch kernel, the outbound-request correlator, and the
 * handshake gate into a runnable `Client` instance.
 */
final class ClientBuilder
{
    private ?Implementation $clientInfo = null;
    private LoggerInterface $logger;

    /**
     * @var array<non-empty-string, RequestHandlerInterface<non-empty-string, Result, ClientContext>>
     */
    private array $requestHandlers = [];

    /**
     * @var array<non-empty-string, NotificationHandlerInterface<non-empty-string>>
     */
    private array $notificationHandlers = [];

    /**
     * @var null|\Closure(): (int|non-empty-string)
     */
    private ?\Closure $requestIdFactory = null;

    public function __construct()
    {
        $this->logger = new NullLogger();
    }

    /**
     * @param null|list<Icon> $icons
     */
    public function setClientInfo(
        string $name,
        string $version,
        ?string $title = null,
        ?string $description = null,
        ?string $websiteUrl = null,
        ?array $icons = null,
    ): self {
        $this->clientInfo = new Implementation($name, $version, $title, $description, $websiteUrl, $icons);

        return $this;
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    /**
     * Overrides the default monotonically-incrementing integer factory.
     *
     * @param \Closure(): (int|non-empty-string) $factory
     */
    public function setRequestIdFactory(\Closure $factory): self
    {
        $this->requestIdFactory = $factory;

        return $this;
    }

    /**
     * Registers a handler for an inbound request method the peer may send to the client.
     *
     * @param non-empty-string                                                 $method
     * @param RequestHandlerInterface<non-empty-string, Result, ClientContext> $handler
     */
    public function addRequestHandler(string $method, RequestHandlerInterface $handler): self
    {
        $this->requestHandlers[$method] = $handler;

        return $this;
    }

    /**
     * Registers a handler for an inbound notification method.
     *
     * @param non-empty-string                               $method
     * @param NotificationHandlerInterface<non-empty-string> $handler
     */
    public function addNotificationHandler(string $method, NotificationHandlerInterface $handler): self
    {
        $this->notificationHandlers[$method] = $handler;

        return $this;
    }

    public function build(): Client
    {
        Assert::that($this->clientInfo)->isInstanceOf(
            Implementation::class,
            'Client information must be set before build() via setClientInfo().',
        );

        $outboundRequests = new PendingOutboundRequests();

        return new Client(
            $this->clientInfo,
            new ClientMessageDispatcher(
                new HandlerRegistry($this->requestHandlers, RequestHandlerInterface::class, 'Request handler'),
                new HandlerRegistry($this->notificationHandlers, NotificationHandlerInterface::class, 'Notification handler'),
                $outboundRequests,
                logger: $this->logger,
            ),
            $outboundRequests,
            new ClientInitializationGate(),
            $this->requestIdFactory ?? self::defaultRequestIdFactory(),
            $this->logger,
        );
    }

    /**
     * @return \Closure(): int
     */
    private static function defaultRequestIdFactory(): \Closure
    {
        $counter = 0;

        return static fn(): int => ++$counter;
    }
}
