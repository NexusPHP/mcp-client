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
use Nexus\Mcp\Client\Dispatch\ClientMessageDispatcher;
use Nexus\Mcp\Client\Dispatch\ProgressListenerRegistry;
use Nexus\Mcp\Client\Handler\Notification\RoutingProgressNotificationHandler;
use Nexus\Mcp\Core\Dispatch\PendingInboundRequests;
use Nexus\Mcp\Core\Dispatch\PendingOutboundRequests;
use Nexus\Mcp\Core\Handler\HandlerRegistry;
use Nexus\Mcp\Core\Handler\Notification\CancelledNotificationHandler;
use Nexus\Mcp\Core\Handler\NotificationHandlerInterface;
use Nexus\Mcp\Core\Handler\RequestHandlerInterface;
use Nexus\Mcp\Core\Schema\ClientCapabilities;
use Nexus\Mcp\Core\Schema\Icon;
use Nexus\Mcp\Core\Schema\Implementation;
use Nexus\Mcp\Core\Schema\Notification\CancelledNotification;
use Nexus\Mcp\Core\Schema\Notification\ProgressNotification;
use Nexus\Mcp\Core\Schema\Result;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Fluent builder that assembles the per-feature handler registries, the
 * client-side dispatch kernel, and the outbound-request correlator into a
 * runnable `Client` instance.
 */
final class ClientBuilder
{
    private ?Implementation $clientInfo = null;
    private ClientCapabilities $clientCapabilities;
    private LoggerInterface $logger;
    private ?float $requestTimeout = Client::DEFAULT_REQUEST_TIMEOUT;
    private ?float $maxRequestTimeout = Client::DEFAULT_MAX_REQUEST_TIMEOUT;

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

    /**
     * @var null|\Closure(): (int|non-empty-string)
     */
    private ?\Closure $progressTokenFactory = null;

    public function __construct()
    {
        $this->clientCapabilities = new ClientCapabilities();
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
        $this->clientInfo = new Implementation(
            name: $name,
            version: $version,
            title: $title,
            description: $description,
            websiteUrl: $websiteUrl,
            icons: $icons,
        );

        return $this;
    }

    /**
     * Declares the capabilities advertised in every request's `_meta` envelope.
     */
    public function setClientCapabilities(ClientCapabilities $capabilities): self
    {
        $this->clientCapabilities = $capabilities;

        return $this;
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->logger = $logger;

        return $this;
    }

    /**
     * Seconds a request may go unanswered before it is abandoned, or `null` to wait indefinitely. Each
     * progress notification for the request restarts it.
     */
    public function setRequestTimeout(?float $seconds): self
    {
        if (null !== $seconds && $seconds <= 0.0) {
            throw new \InvalidArgumentException(\sprintf('The request timeout must be positive or null, %s given.', $seconds));
        }

        $this->requestTimeout = $seconds;

        return $this;
    }

    /**
     * Seconds a request may run in total however much progress arrives, or `null` to leave it unbounded.
     */
    public function setMaxRequestTimeout(?float $seconds): self
    {
        if (null !== $seconds && $seconds <= 0.0) {
            throw new \InvalidArgumentException(\sprintf('The maximum request timeout must be positive or null, %s given.', $seconds));
        }

        $this->maxRequestTimeout = $seconds;

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
     * Overrides the default progress-token factory used by `Client::callTool()`
     * when an `onProgress` callback is supplied.
     *
     * @param \Closure(): (int|non-empty-string) $factory
     */
    public function setProgressTokenFactory(\Closure $factory): self
    {
        $this->progressTokenFactory = $factory;

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
        $progressListeners = new ProgressListenerRegistry();
        $inboundRequests = new PendingInboundRequests();

        $requestHandlers = $this->requestHandlers;

        $notificationHandlers = [
            CancelledNotification::getMethod() => new CancelledNotificationHandler($inboundRequests, $this->logger),
            ...$this->notificationHandlers,
        ];
        $notificationHandlers[ProgressNotification::getMethod()] = new RoutingProgressNotificationHandler(
            $progressListeners,
            // register the custom progress handler as fallback
            $notificationHandlers[ProgressNotification::getMethod()] ?? null,
        );

        return new Client(
            $this->clientInfo,
            $this->clientCapabilities,
            new ClientMessageDispatcher(
                new HandlerRegistry($requestHandlers, RequestHandlerInterface::class, 'Request handler'),
                new HandlerRegistry($notificationHandlers, NotificationHandlerInterface::class, 'Notification handler'),
                $outboundRequests,
                logger: $this->logger,
                inboundRequests: $inboundRequests,
            ),
            $outboundRequests,
            $this->requestIdFactory ?? self::buildDefaultRequestIdFactory(),
            $this->progressTokenFactory ?? self::buildDefaultProgressTokenFactory(),
            progressListeners: $progressListeners,
            logger: $this->logger,
            requestTimeout: $this->requestTimeout,
            maxRequestTimeout: $this->maxRequestTimeout,
        );
    }

    /**
     * @return \Closure(): int
     */
    private static function buildDefaultRequestIdFactory(): \Closure
    {
        $counter = 0;

        return static function () use (&$counter): int {
            return ++$counter;
        };
    }

    /**
     * @return \Closure(): non-empty-string
     */
    private static function buildDefaultProgressTokenFactory(): \Closure
    {
        $counter = 0;

        return static function () use (&$counter): string {
            return \sprintf('progress-%d', ++$counter);
        };
    }
}
