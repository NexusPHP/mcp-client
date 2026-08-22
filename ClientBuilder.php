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
use Nexus\Mcp\Client\Dispatch\DiscoveredServerCapabilities;
use Nexus\Mcp\Client\Dispatch\ProgressListenerRegistry;
use Nexus\Mcp\Client\Extension\ClientExtensionInterface;
use Nexus\Mcp\Client\Handler\Notification\ExtensionGateNotificationHandler;
use Nexus\Mcp\Client\Handler\Notification\RoutingProgressNotificationHandler;
use Nexus\Mcp\Client\Handler\Request\ExtensionGateRequestHandler;
use Nexus\Mcp\Client\Subscription\SubscriptionRegistry;
use Nexus\Mcp\Core\Dispatch\PendingInboundRequests;
use Nexus\Mcp\Core\Dispatch\PendingOutboundRequests;
use Nexus\Mcp\Core\Exception\LogicException;
use Nexus\Mcp\Core\Extension\ExtensionCollection;
use Nexus\Mcp\Core\Handler\HandlerRegistry;
use Nexus\Mcp\Core\Handler\Notification\CancelledNotificationHandler;
use Nexus\Mcp\Core\Handler\NotificationHandlerInterface;
use Nexus\Mcp\Core\Handler\RequestHandlerInterface;
use Nexus\Mcp\Core\JsonRpc\JsonRpcMessageParser;
use Nexus\Mcp\Core\JsonRpc\JsonRpcMethodRegistry;
use Nexus\Mcp\Core\Schema\ClientCapabilities;
use Nexus\Mcp\Core\Schema\Icon;
use Nexus\Mcp\Core\Schema\Implementation;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcNotification;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcRequest;
use Nexus\Mcp\Core\Schema\Notification\CancelledNotification;
use Nexus\Mcp\Core\Schema\Notification\ProgressNotification;
use Nexus\Mcp\Core\Schema\Result;
use Nexus\Mcp\Core\Validation\IconSrcValidator;
use Nexus\Mcp\Core\Validation\MethodClassValidator;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Fluent builder for a runnable `Client` instance.
 */
final class ClientBuilder
{
    public const int DEFAULT_MAX_IN_FLIGHT = 1_024;

    private bool $built = false;
    private ?Implementation $clientInfo = null;
    private ClientCapabilities $clientCapabilities;
    private LoggerInterface $logger;
    private ?float $requestTimeout = Client::DEFAULT_REQUEST_TIMEOUT;
    private ?float $maxRequestTimeout = Client::DEFAULT_MAX_REQUEST_TIMEOUT;
    private bool $retryLostRequests = false;

    /**
     * @var null|int<1, max>
     */
    private ?int $maxInFlight = self::DEFAULT_MAX_IN_FLIGHT;

    /**
     * @var array<non-empty-string, RequestHandlerInterface<non-empty-string, Result, ClientContext>>
     */
    private array $requestHandlers = [];

    /**
     * @var array<non-empty-string, NotificationHandlerInterface<non-empty-string>>
     */
    private array $notificationHandlers = [];

    /**
     * @var array<non-empty-string, class-string<JsonRpcRequest<non-empty-string>>>
     */
    private array $requestClasses = [];

    /**
     * @var array<non-empty-string, class-string<JsonRpcNotification<non-empty-string>>>
     */
    private array $notificationClasses = [];

    /**
     * @var ExtensionCollection<ClientContext>
     */
    private readonly ExtensionCollection $extensions;

    /**
     * @var null|\Closure(): (int|non-empty-string)
     */
    private ?\Closure $requestIdFactory = null;

    /**
     * @var null|\Closure(): (int|non-empty-string)
     */
    private ?\Closure $progressTokenFactory = null;

    /**
     * @var null|\Closure(): array<non-empty-string, mixed>
     */
    private ?\Closure $metaExtrasFactory = null;

    public function __construct()
    {
        $this->clientCapabilities = new ClientCapabilities();
        $this->logger = new NullLogger();
        $this->extensions = new ExtensionCollection();
    }

    /**
     * @throws LogicException
     */
    public function enableExtension(ClientExtensionInterface $extension): self
    {
        $this->assertNotBuilt();
        $this->extensions->add(
            $extension,
            claimedRequests: array_keys($this->requestHandlers),
            claimedNotifications: array_keys($this->notificationHandlers),
            outboundRequests: $extension->getOutboundRequests(),
        );

        return $this;
    }

    /**
     * @param non-empty-string      $name
     * @param non-empty-string      $version
     * @param null|non-empty-string $title
     * @param null|non-empty-string $description
     * @param null|non-empty-string $websiteUrl
     * @param null|list<Icon>       $icons
     */
    public function setClientInfo(
        string $name,
        string $version,
        ?string $title = null,
        ?string $description = null,
        ?string $websiteUrl = null,
        ?array $icons = null,
    ): self {
        $this->assertNotBuilt();
        IconSrcValidator::validate($icons, 'clientInfo');

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

    public function setClientCapabilities(ClientCapabilities $capabilities): self
    {
        $this->assertNotBuilt();
        $this->clientCapabilities = $capabilities;

        return $this;
    }

    public function setLogger(LoggerInterface $logger): self
    {
        $this->assertNotBuilt();
        $this->logger = $logger;

        return $this;
    }

    /**
     * Seconds a request may go unanswered before it is abandoned, or `null` to wait indefinitely.
     */
    public function setRequestTimeout(?float $seconds): self
    {
        $this->assertNotBuilt();

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
        $this->assertNotBuilt();

        if (null !== $seconds && $seconds <= 0.0) {
            throw new \InvalidArgumentException(\sprintf('The maximum request timeout must be positive or null, %s given.', $seconds));
        }

        $this->maxRequestTimeout = $seconds;

        return $this;
    }

    /**
     * Sends a state-reading request again when the peer carrying it is replaced, which is an at-least-once
     * retry.
     */
    public function setRetryLostRequests(bool $retry): self
    {
        $this->assertNotBuilt();
        $this->retryLostRequests = $retry;

        return $this;
    }

    /**
     * Caps how many inbound messages the client processes at once, defaulting to `DEFAULT_MAX_IN_FLIGHT`, with
     * null lifting the cap.
     */
    public function setMaxInFlightDispatches(?int $max): self
    {
        $this->assertNotBuilt();

        Assert::that($max)->nullOr()->isPositiveInt('Maximum in-flight dispatches must be a positive integer or null, {value} given.');

        $this->maxInFlight = $max;

        return $this;
    }

    /**
     * @param \Closure(): (int|non-empty-string) $factory
     */
    public function setRequestIdFactory(\Closure $factory): self
    {
        $this->assertNotBuilt();
        $this->requestIdFactory = $factory;

        return $this;
    }

    /**
     * @param \Closure(): (int|non-empty-string) $factory
     */
    public function setProgressTokenFactory(\Closure $factory): self
    {
        $this->assertNotBuilt();
        $this->progressTokenFactory = $factory;

        return $this;
    }

    /**
     * Sets the factory called once per outbound request for the extra `_meta` keys it carries, such as the W3C
     * `traceparent`. A lifecycle key it returns is ignored.
     *
     * @param \Closure(): array<non-empty-string, mixed> $factory
     */
    public function setMetaExtrasFactory(\Closure $factory): self
    {
        $this->assertNotBuilt();
        $this->metaExtrasFactory = $factory;

        return $this;
    }

    /**
     * @param non-empty-string                                                 $method
     * @param RequestHandlerInterface<non-empty-string, Result, ClientContext> $handler
     * @param class-string<JsonRpcRequest<non-empty-string>>                   $requestClass Parses inbound `$method` envelopes into typed requests
     */
    public function addRequestHandler(string $method, RequestHandlerInterface $handler, string $requestClass): self
    {
        $this->assertNotBuilt();
        $this->extensions->assertNotOwned($method);

        MethodClassValidator::validate($requestClass, $method);

        $registry = JsonRpcMethodRegistry::requests();

        if (\array_key_exists($method, $registry)) {
            Assert::that($requestClass)->isIdentical($registry[$method], \sprintf(
                'Request method "%s" is defined by the MCP specification and keeps its registry envelope class, {value} given.',
                $method,
            ));
        } else {
            $this->requestClasses[$method] = $requestClass;
        }

        $this->requestHandlers[$method] = $handler;

        return $this;
    }

    /**
     * `$notificationClass` is needed only for a vendor method that does not already parse.
     *
     * @param non-empty-string                                         $method
     * @param NotificationHandlerInterface<non-empty-string>           $handler
     * @param null|class-string<JsonRpcNotification<non-empty-string>> $notificationClass
     *
     * @throws LogicException
     */
    public function addNotificationHandler(
        string $method,
        NotificationHandlerInterface $handler,
        ?string $notificationClass = null,
    ): self {
        $this->assertNotBuilt();
        $this->extensions->assertNotOwned($method, isNotification: true);

        $registryClass = JsonRpcMethodRegistry::notifications()[$method] ?? null;

        if (null === $registryClass && null === $notificationClass) {
            throw new LogicException(\sprintf(
                'Notification method "%s" is not defined by the MCP specification, so its handler registration must name the $notificationClass that parses it.',
                $method,
            ));
        }

        if (null !== $registryClass && null !== $notificationClass) {
            Assert::that($notificationClass)->isIdentical($registryClass, \sprintf(
                'Notification method "%s" is defined by the MCP specification and keeps its registry envelope class, {value} given.',
                $method,
            ));
        }

        if (null !== $notificationClass) {
            MethodClassValidator::validate($notificationClass, $method, isNotification: true);
            $this->notificationClasses[$method] = $notificationClass;
        }

        $this->notificationHandlers[$method] = $handler;

        return $this;
    }

    public function build(): Client
    {
        $this->assertNotBuilt();
        $this->built = true;

        Assert::that($this->clientInfo)->isInstanceOf(
            Implementation::class,
            'Client information must be set before build() via setClientInfo().',
        );

        $outboundRequests = new PendingOutboundRequests();
        $progressListeners = new ProgressListenerRegistry();
        $subscriptions = new SubscriptionRegistry();
        $inboundRequests = new PendingInboundRequests();

        $discoveredCapabilities = new DiscoveredServerCapabilities();
        $extensionRequestHandlers = [];

        foreach ($this->extensions->getRequestHandlerGroups() as $identifier => $group) {
            foreach ($group as $extensionMethod => $extensionHandler) {
                $extensionRequestHandlers[$extensionMethod] = new ExtensionGateRequestHandler($identifier, $extensionHandler, $discoveredCapabilities);
            }
        }

        $requestHandlers = [...$extensionRequestHandlers, ...$this->requestHandlers];

        $extensionNotificationHandlers = [];

        foreach ($this->extensions->buildNotificationHandlers() as $extensionMethod => $extensionHandler) {
            $owner = $this->extensions->findNotificationOwner($extensionMethod);
            \assert(\is_string($owner));
            $extensionNotificationHandlers[$extensionMethod] = new ExtensionGateNotificationHandler($owner, $extensionHandler, $discoveredCapabilities, $this->logger);
        }

        $notificationHandlers = [
            CancelledNotification::getMethod() => new CancelledNotificationHandler($inboundRequests, $this->logger),
            ...$extensionNotificationHandlers,
            ...$this->notificationHandlers,
        ];
        $notificationHandlers[ProgressNotification::getMethod()] = new RoutingProgressNotificationHandler(
            $progressListeners,
            $notificationHandlers[ProgressNotification::getMethod()] ?? null,
        );

        return new Client(
            $this->clientInfo,
            $this->buildClientCapabilities(),
            new ClientMessageDispatcher(
                new HandlerRegistry($requestHandlers, RequestHandlerInterface::class, 'Request handler'),
                new HandlerRegistry($notificationHandlers, NotificationHandlerInterface::class, 'Notification handler'),
                $outboundRequests,
                logger: $this->logger,
                parser: new JsonRpcMessageParser(
                    [...$this->extensions->buildRequestClasses(), ...$this->requestClasses],
                    [...$this->extensions->buildNotificationClasses(), ...$this->notificationClasses],
                ),
                inboundRequests: $inboundRequests,
                subscriptions: $subscriptions,
                maxInFlight: $this->maxInFlight,
            ),
            $outboundRequests,
            $this->requestIdFactory ?? self::buildDefaultRequestIdFactory(),
            $this->progressTokenFactory ?? self::buildDefaultProgressTokenFactory(),
            progressListeners: $progressListeners,
            subscriptions: $subscriptions,
            logger: $this->logger,
            requestTimeout: $this->requestTimeout,
            maxRequestTimeout: $this->maxRequestTimeout,
            retryLostRequests: $this->retryLostRequests,
            extensionMethods: $this->extensions->getOutboundOwners(),
            serverCapabilities: $discoveredCapabilities,
            metaExtrasFactory: $this->metaExtrasFactory,
        );
    }

    /**
     * @throws LogicException
     */
    private function assertNotBuilt(): void
    {
        if ($this->built) {
            throw new LogicException('This builder has already been built. Construct a new ClientBuilder for another client.');
        }
    }

    /**
     * @throws LogicException
     */
    private function buildClientCapabilities(): ClientCapabilities
    {
        $slot = $this->extensions->buildCapabilitySlot();

        if (null === $slot) {
            return $this->clientCapabilities;
        }

        $base = $this->clientCapabilities;
        $declared = $base->extensions ?? [];

        foreach (array_keys($slot) as $identifier) {
            if (\array_key_exists($identifier, $declared)) {
                ExtensionCollection::refuseDuplicateDeclaration($identifier);
            }
        }

        return new ClientCapabilities(
            elicitation: $base->elicitation,
            experimental: $base->experimental,
            extensions: [...$declared, ...$slot],
            extras: $base->extras,
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
