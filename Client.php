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

use Amp\CancelledException;
use Amp\DeferredFuture;
use Nexus\Mcp\Client\Dispatch\DiscoveredServerCapabilities;
use Nexus\Mcp\Client\Dispatch\ProgressListenerRegistry;
use Nexus\Mcp\Client\Dispatch\RequestDeadline;
use Nexus\Mcp\Client\Exception\ServerCapabilityNotSupportedException;
use Nexus\Mcp\Client\Subscription\OpenSubscription;
use Nexus\Mcp\Client\Subscription\SubscriptionRegistry;
use Nexus\Mcp\Client\Subscription\SubscriptionStream;
use Nexus\Mcp\Core\Dispatch\MessageDispatcherInterface;
use Nexus\Mcp\Core\Dispatch\PendingOutboundRequests;
use Nexus\Mcp\Core\Exception\LogicException;
use Nexus\Mcp\Core\Exception\OutboundRequestFailedException;
use Nexus\Mcp\Core\Exception\RemoteCallFailedException;
use Nexus\Mcp\Core\Exception\RequestTimeoutException;
use Nexus\Mcp\Core\Exception\SupervisionExhaustedException;
use Nexus\Mcp\Core\Exception\TransportAlreadyClosedException;
use Nexus\Mcp\Core\Http\ParameterHeaderBinding;
use Nexus\Mcp\Core\Http\ParameterHeaders;
use Nexus\Mcp\Core\Http\ParameterHeaderScanner;
use Nexus\Mcp\Core\SafeDisplay;
use Nexus\Mcp\Core\Schema\ClientCapabilities;
use Nexus\Mcp\Core\Schema\Cursor;
use Nexus\Mcp\Core\Schema\Enum\ProtocolErrorCode;
use Nexus\Mcp\Core\Schema\Error\UnsupportedProtocolVersionError;
use Nexus\Mcp\Core\Schema\Implementation;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcNotification;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcRequest;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcResultResponse;
use Nexus\Mcp\Core\Schema\MetaObject\RequestMetaObject;
use Nexus\Mcp\Core\Schema\Notification\CancelledNotification;
use Nexus\Mcp\Core\Schema\NotificationParams\CancelledNotificationParams;
use Nexus\Mcp\Core\Schema\ProgressToken;
use Nexus\Mcp\Core\Schema\Prompt\PromptReference;
use Nexus\Mcp\Core\Schema\ProtocolVersion;
use Nexus\Mcp\Core\Schema\Request\CallToolRequest;
use Nexus\Mcp\Core\Schema\Request\CompleteRequest;
use Nexus\Mcp\Core\Schema\Request\DiscoverRequest;
use Nexus\Mcp\Core\Schema\Request\GetPromptRequest;
use Nexus\Mcp\Core\Schema\Request\ListPromptsRequest;
use Nexus\Mcp\Core\Schema\Request\ListResourcesRequest;
use Nexus\Mcp\Core\Schema\Request\ListResourceTemplatesRequest;
use Nexus\Mcp\Core\Schema\Request\ListToolsRequest;
use Nexus\Mcp\Core\Schema\Request\ReadResourceRequest;
use Nexus\Mcp\Core\Schema\Request\SubscriptionsListenRequest;
use Nexus\Mcp\Core\Schema\RequestId;
use Nexus\Mcp\Core\Schema\RequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\CallToolRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\CompleteRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\EmptyRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\GetPromptRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\InputResponseCarrierInterface;
use Nexus\Mcp\Core\Schema\RequestParams\PaginatedRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\ReadResourceRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\SubscriptionsListenRequestParams;
use Nexus\Mcp\Core\Schema\RequestParamsInterface;
use Nexus\Mcp\Core\Schema\Resource\ResourceTemplateReference;
use Nexus\Mcp\Core\Schema\Result\CallToolResult;
use Nexus\Mcp\Core\Schema\Result\CompleteResult;
use Nexus\Mcp\Core\Schema\Result\DiscoverResult;
use Nexus\Mcp\Core\Schema\Result\GetPromptResult;
use Nexus\Mcp\Core\Schema\Result\InputRequiredResult;
use Nexus\Mcp\Core\Schema\Result\InputResponse;
use Nexus\Mcp\Core\Schema\Result\ListPromptsResult;
use Nexus\Mcp\Core\Schema\Result\ListResourcesResult;
use Nexus\Mcp\Core\Schema\Result\ListResourceTemplatesResult;
use Nexus\Mcp\Core\Schema\Result\ListToolsResult;
use Nexus\Mcp\Core\Schema\Result\ReadResourceResult;
use Nexus\Mcp\Core\Schema\Result\SubscriptionsListenResult;
use Nexus\Mcp\Core\Schema\ResultResponse\CallToolResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\CompleteResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\DiscoverResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\GetPromptResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\ListPromptsResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\ListResourcesResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\ListResourceTemplatesResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\ListToolsResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\ReadResourceResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\SubscriptionsListenResultResponse;
use Nexus\Mcp\Core\Schema\ServerCapabilities;
use Nexus\Mcp\Core\Schema\SubscriptionFilter;
use Nexus\Mcp\Core\Transport\AbortableTransportInterface;
use Nexus\Mcp\Core\Transport\ListenerHandleInterface;
use Nexus\Mcp\Core\Transport\ParameterHeaderMirroringInterface;
use Nexus\Mcp\Core\Transport\ReceiveContext;
use Nexus\Mcp\Core\Transport\ReconnectingTransportInterface;
use Nexus\Mcp\Core\Transport\SendContext;
use Nexus\Mcp\Core\Transport\TransportInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Revolt\EventLoop;

/**
 * Client-side entry point for the typed JSON-RPC operations issued against an MCP server.
 */
final class Client
{
    /**
     * Seconds a request may go unanswered before it is abandoned.
     */
    public const float DEFAULT_REQUEST_TIMEOUT = 60.0;

    /**
     * Seconds a request may run in total, however much progress arrives.
     */
    public const float DEFAULT_MAX_REQUEST_TIMEOUT = 600.0;

    private const int MAX_HEADER_REFRESH_PAGES = 100;
    private const array RETRYABLE_REQUESTS = [
        CompleteRequest::class,
        DiscoverRequest::class,
        GetPromptRequest::class,
        ListPromptsRequest::class,
        ListResourcesRequest::class,
        ListResourceTemplatesRequest::class,
        ListToolsRequest::class,
        ReadResourceRequest::class,
    ];

    private ?TransportInterface $transport = null;
    private ?Implementation $serverInfo = null;

    /**
     * @var array<string, list<ParameterHeaderBinding>>
     */
    private array $toolHeaderBindings = [];

    /**
     * @var list<ListenerHandleInterface>
     */
    private array $listeners = [];

    /**
     * @param \Closure(): (int|non-empty-string)        $requestIdFactory
     * @param \Closure(): (int|non-empty-string)        $progressTokenFactory
     * @param array<non-empty-string, non-empty-string> $extensionMethods
     */
    public function __construct(
        private readonly Implementation $clientInfo,
        private readonly ClientCapabilities $clientCapabilities,
        private readonly MessageDispatcherInterface $dispatcher,
        private readonly PendingOutboundRequests $outboundRequests,
        private readonly \Closure $requestIdFactory,
        private readonly \Closure $progressTokenFactory,
        private readonly ProtocolVersion $protocolVersion = new ProtocolVersion(version: ProtocolVersion::LATEST_VERSION),
        private readonly ProgressListenerRegistry $progressListeners = new ProgressListenerRegistry(),
        private readonly SubscriptionRegistry $subscriptions = new SubscriptionRegistry(),
        private readonly LoggerInterface $logger = new NullLogger(),
        private readonly ?float $requestTimeout = self::DEFAULT_REQUEST_TIMEOUT,
        private readonly ?float $maxRequestTimeout = self::DEFAULT_MAX_REQUEST_TIMEOUT,
        private readonly bool $retryLostRequests = false,
        private readonly array $extensionMethods = [],
        private readonly DiscoveredServerCapabilities $serverCapabilities = new DiscoveredServerCapabilities(),
    ) {
    }

    /**
     * Non-blocking connect to the transport.
     *
     * @throws LogicException
     */
    public function connect(TransportInterface $transport): void
    {
        if (null !== $this->transport) {
            throw new LogicException('Client is already connected to a transport.');
        }

        $this->logger->info('Starting MCP client.');
        $this->transport = $transport;

        $this->listeners[] = $transport->onMessage(function (array $envelope, ReceiveContext $context) use ($transport): void {
            $this->dispatcher->dispatch($envelope, $transport, $context);
        });
        $this->listeners[] = $transport->onError(function (\Throwable $e): void {
            if ($e instanceof OutboundRequestFailedException) {
                $this->outboundRequests->reject($e->requestId, $e);
            }

            if ($e instanceof SupervisionExhaustedException) {
                $this->failSubscriptions($e);
                $this->outboundRequests->cancelAll($e);
            }

            $this->logger->error('Transport error.', ['exception' => $e]);
        });
        $this->listeners[] = $transport->onDrain(function (): void {
            $this->dispatcher->flushPending();
        });
        $this->listeners[] = $transport->onClose(function () use ($transport): void {
            $error = new TransportAlreadyClosedException(operation: 'await-response');
            $this->outboundRequests->cancelUnretained($error);

            EventLoop::queue(function () use ($transport, $error): void {
                if ($transport !== $this->transport) {
                    return;
                }

                if ($transport instanceof ReconnectingTransportInterface && $transport->isReconnecting()) {
                    return;
                }

                $this->outboundRequests->cancelAll($error);
            });
        });

        if ($transport instanceof ReconnectingTransportInterface) {
            $this->listeners[] = $transport->onReconnect(function () use ($transport): void {
                foreach ($this->outboundRequests->collectRetained() as $retained) {
                    $request = $retained['request'];

                    try {
                        $transport->send($request, $retained['context']);
                    } catch (\Throwable $e) {
                        if ($transport->isReconnecting()) {
                            $this->logger->warning(
                                'Could not send request {id} again to the replacement peer.',
                                ['id' => $request->id->id, 'exception' => $e],
                            );

                            continue;
                        }

                        $this->outboundRequests->reject($request->id, $e);
                    }
                }

                foreach ($this->subscriptions->all() as $subscription) {
                    try {
                        $this->openStream($subscription, $transport);
                    } catch (\Throwable $e) {
                        $this->logger->error(
                            'Could not re-open subscription {id} against the replacement peer.',
                            ['id' => $subscription->subscriptionId->id, 'exception' => $e],
                        );
                    }
                }
            });
        }

        $transport->start();
    }

    /**
     * Closes the transport and detaches it, doing nothing when not connected.
     */
    public function disconnect(): void
    {
        $transport = $this->transport;
        $this->transport = null;

        $this->toolHeaderBindings = [];
        $this->serverInfo = null;
        $this->serverCapabilities->record(null);

        $error = new TransportAlreadyClosedException(operation: 'await-response');
        $this->failSubscriptions($error);
        $this->outboundRequests->cancelAll($error);

        $listeners = $this->listeners;
        $this->listeners = [];

        try {
            $transport?->close();
        } finally {
            foreach ($listeners as $listener) {
                $listener->dispose();
            }
        }
    }

    public function getServerInfo(): ?Implementation
    {
        return $this->serverInfo;
    }

    public function getServerCapabilities(): ?ServerCapabilities
    {
        return $this->serverCapabilities->current();
    }

    /**
     * Sends `server/discover` and records the advertised server info and capabilities.
     *
     * @throws LogicException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function discover(): DiscoverResult
    {
        $result = $this->sendRequest(
            new DiscoverRequest(id: $this->mintRequestId(), params: new EmptyRequestParams(meta: $this->stampMeta())),
            DiscoverResultResponse::class,
        )->result;

        $this->serverInfo = $result->meta->serverInfo;
        $this->serverCapabilities->record($result->capabilities);

        return $result;
    }

    /**
     * Opens a `subscriptions/listen` stream, returning as soon as the request is away.
     *
     * @param \Closure(JsonRpcNotification<non-empty-string>): void $onNotification
     *
     * @throws LogicException
     * @throws TransportAlreadyClosedException
     */
    public function listen(SubscriptionFilter $notifications, \Closure $onNotification): SubscriptionStream
    {
        $transport = $this->requireConnectedTransport();

        $id = $this->mintRequestId();

        /** @var DeferredFuture<SubscriptionsListenResult> $outcome */
        $outcome = new DeferredFuture();

        $future = $outcome->getFuture();
        $future->ignore();

        $subscription = new OpenSubscription($id, $notifications, $onNotification, $outcome);

        $this->openStream($subscription, $transport);
        $this->subscriptions->register($subscription);

        return new SubscriptionStream($id, $future, function () use ($id, $transport): void {
            $this->subscriptions->forget($id);

            if (! $this->outboundRequests->forget($id)) {
                return;
            }

            self::abortExchange($transport, $id);

            try {
                $transport->send(new CancelledNotification(
                    params: new CancelledNotificationParams(requestId: $id, reason: 'The subscription was closed.'),
                ));
            } catch (\Throwable $e) {
                $this->logger->debug(
                    'Could not tell the server that subscription {id} was closed.',
                    ['id' => $id->id, 'exception' => $e],
                );
            }
        });
    }

    /**
     * @throws LogicException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function listTools(?Cursor $cursor = null): ListToolsResult
    {
        $result = $this->sendRequest(
            new ListToolsRequest(
                id: $this->mintRequestId(),
                params: new PaginatedRequestParams(meta: $this->stampMeta(), cursor: $cursor),
            ),
            ListToolsResultResponse::class,
        )->result;

        return $this->transport instanceof ParameterHeaderMirroringInterface
            ? $this->admitMirrorableTools($result)
            : $result;
    }

    /**
     * @throws LogicException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function listResources(?Cursor $cursor = null): ListResourcesResult
    {
        return $this->sendRequest(
            new ListResourcesRequest(
                id: $this->mintRequestId(),
                params: new PaginatedRequestParams(meta: $this->stampMeta(), cursor: $cursor),
            ),
            ListResourcesResultResponse::class,
        )->result;
    }

    /**
     * @throws LogicException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function listResourceTemplates(?Cursor $cursor = null): ListResourceTemplatesResult
    {
        return $this->sendRequest(
            new ListResourceTemplatesRequest(
                id: $this->mintRequestId(),
                params: new PaginatedRequestParams(meta: $this->stampMeta(), cursor: $cursor),
            ),
            ListResourceTemplatesResultResponse::class,
        )->result;
    }

    /**
     * @throws LogicException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function listPrompts(?Cursor $cursor = null): ListPromptsResult
    {
        return $this->sendRequest(
            new ListPromptsRequest(
                id: $this->mintRequestId(),
                params: new PaginatedRequestParams(meta: $this->stampMeta(), cursor: $cursor),
            ),
            ListPromptsResultResponse::class,
        )->result;
    }

    /**
     * @param non-empty-string                                $uri
     * @param null|array<int|non-empty-string, InputResponse> $inputResponses
     *
     * @throws LogicException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function readResource(
        string $uri,
        ?array $inputResponses = null,
        ?string $requestState = null,
    ): InputRequiredResult|ReadResourceResult {
        return $this->sendRequest(
            new ReadResourceRequest(
                id: $this->mintRequestId(),
                params: new ReadResourceRequestParams(
                    uri: $uri,
                    meta: $this->stampMeta(),
                    inputResponses: $inputResponses,
                    requestState: $requestState,
                ),
            ),
            ReadResourceResultResponse::class,
        )->result;
    }

    /**
     * @param non-empty-string                                $name
     * @param null|array<array-key, string>                   $arguments
     * @param null|array<int|non-empty-string, InputResponse> $inputResponses
     *
     * @throws LogicException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function getPrompt(
        string $name,
        ?array $arguments = null,
        ?array $inputResponses = null,
        ?string $requestState = null,
    ): GetPromptResult|InputRequiredResult {
        return $this->sendRequest(
            new GetPromptRequest(
                id: $this->mintRequestId(),
                params: new GetPromptRequestParams(
                    name: $name,
                    meta: $this->stampMeta(),
                    arguments: $arguments,
                    inputResponses: $inputResponses,
                    requestState: $requestState,
                ),
            ),
            GetPromptResultResponse::class,
        )->result;
    }

    /**
     * @param array{name: string, value: string}               $argument
     * @param null|array{arguments?: array<array-key, string>} $context
     *
     * @throws LogicException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function complete(
        PromptReference|ResourceTemplateReference $ref,
        array $argument,
        ?array $context = null,
    ): CompleteResult {
        return $this->sendRequest(
            new CompleteRequest(
                id: $this->mintRequestId(),
                params: new CompleteRequestParams(
                    ref: $ref,
                    argument: $argument,
                    meta: $this->stampMeta(),
                    context: $context,
                ),
            ),
            CompleteResultResponse::class,
        )->result;
    }

    /**
     * Invokes a tool, answering with an `InputRequiredResult` whose `requestState` must be echoed back
     * unchanged when the server needs more input.
     *
     * @param non-empty-string                                                      $name
     * @param null|array<array-key, mixed>                                          $arguments
     * @param null|\Closure(float $progress, ?float $total, ?string $message): void $onProgress
     * @param null|array<int|non-empty-string, InputResponse>                       $inputResponses
     *
     * @throws LogicException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function callTool(
        string $name,
        ?array $arguments = null,
        ?\Closure $onProgress = null,
        ?array $inputResponses = null,
        ?string $requestState = null,
    ): CallToolResult|InputRequiredResult {
        try {
            return $this->attemptToolCall($name, $arguments, $onProgress, $inputResponses, $requestState);
        } catch (RemoteCallFailedException $e) {
            if ($e->getCode() !== ProtocolErrorCode::HeaderMismatch->value) {
                throw $e;
            }
        }

        $this->refreshToolHeaderBindings($name);

        return $this->attemptToolCall($name, $arguments, $onProgress, $inputResponses, $requestState);
    }

    /**
     * @template TResponse of JsonRpcResultResponse = JsonRpcResultResponse
     *
     * @param JsonRpcRequest<non-empty-string> $request
     * @param class-string<TResponse>          $response
     *
     * @return TResponse
     *
     * @throws LogicException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function sendRequest(
        JsonRpcRequest $request,
        string $response,
        ?SendContext $context = null,
        ?float $timeout = null,
    ): JsonRpcResultResponse {
        return $this->dispatch($request, $response, $context, $this->openDeadline($timeout));
    }

    public function stampMeta(?ProgressToken $progressToken = null): RequestMetaObject
    {
        return new RequestMetaObject(
            protocolVersion: $this->protocolVersion,
            clientInfo: $this->clientInfo,
            clientCapabilities: $this->clientCapabilities,
            progressToken: $progressToken,
        );
    }

    public function mintRequestId(): RequestId
    {
        return new RequestId(id: ($this->requestIdFactory)());
    }

    /**
     * @throws TransportAlreadyClosedException
     */
    private function openStream(OpenSubscription $subscription, TransportInterface $transport): void
    {
        $id = $subscription->subscriptionId;
        $response = $this->outboundRequests->register($id, SubscriptionsListenResultResponse::class);

        $response
            ->map(function (SubscriptionsListenResultResponse $response) use ($id): void {
                $this->subscriptions->forget($id)?->outcome->complete($response->result);
            })
            ->catch(function (\Throwable $e) use ($id, $transport): void {
                if ($transport instanceof ReconnectingTransportInterface && $transport->isReconnecting()) {
                    return;
                }

                $this->subscriptions->forget($id)?->outcome->error($e);
            })
            ->ignore()
        ;

        try {
            $transport->send(new SubscriptionsListenRequest(
                id: $id,
                params: new SubscriptionsListenRequestParams(
                    notifications: $subscription->notifications,
                    meta: $this->stampMeta(),
                ),
            ));
        } catch (\Throwable $e) {
            $this->outboundRequests->forget($id);

            throw $e;
        }
    }

    /**
     * @param JsonRpcRequest<non-empty-string> $request
     */
    private function retainsAcrossRestart(JsonRpcRequest $request): bool
    {
        if (! $this->retryLostRequests) {
            return false;
        }

        $method = $request::getMethod();

        foreach (self::RETRYABLE_REQUESTS as $retryable) {
            if ($retryable::getMethod() === $method) {
                return ! self::resumesAnEarlierRound($request->params);
            }
        }

        return false;
    }

    private static function resumesAnEarlierRound(?RequestParamsInterface $params): bool
    {
        if (! $params instanceof InputResponseCarrierInterface) {
            return false;
        }

        return $params->getInputResponses() !== null || $params->getRequestState() !== null;
    }

    private static function abortExchange(TransportInterface $transport, RequestId $id): void
    {
        if ($transport instanceof AbortableTransportInterface) {
            $transport->abort($id);
        }
    }

    private function failSubscriptions(\Throwable $reason): void
    {
        foreach ($this->subscriptions->drain() as $subscription) {
            $subscription->outcome->error($reason);
        }
    }

    private function refreshToolHeaderBindings(string $name): void
    {
        if (! $this->transport instanceof ParameterHeaderMirroringInterface) {
            return;
        }

        $cursor = null;
        $seen = [];

        for ($page = 1; $page <= self::MAX_HEADER_REFRESH_PAGES; ++$page) {
            $result = $this->listTools($cursor);

            foreach ($result->tools as $tool) {
                if ($tool->name === $name) {
                    return;
                }
            }

            $cursor = $result->nextCursor;

            if (null === $cursor) {
                return;
            }

            if (isset($seen[$cursor->cursor])) {
                unset($this->toolHeaderBindings[$name]);
                $this->logger->warning(
                    'Server sent cursor {cursor} again while re-listing tool {tool}, first seen on page {page}, so the refresh stopped.',
                    ['cursor' => SafeDisplay::sanitise($cursor->cursor), 'tool' => $name, 'page' => $seen[$cursor->cursor]],
                );

                return;
            }

            $seen[$cursor->cursor] = $page;
        }

        unset($this->toolHeaderBindings[$name]);
        $this->logger->warning(
            'Re-listing tool {tool} passed {pages} pages without reaching it, so the refresh stopped.',
            ['tool' => $name, 'pages' => self::MAX_HEADER_REFRESH_PAGES],
        );
    }

    /**
     * @param non-empty-string                                                      $name
     * @param null|array<array-key, mixed>                                          $arguments
     * @param null|\Closure(float $progress, ?float $total, ?string $message): void $onProgress
     * @param null|array<int|non-empty-string, InputResponse>                       $inputResponses
     */
    private function attemptToolCall(
        string $name,
        ?array $arguments,
        ?\Closure $onProgress,
        ?array $inputResponses = null,
        ?string $requestState = null,
    ): CallToolResult|InputRequiredResult {
        $context = new SendContext(headers: $this->mirrorParameterHeaders($name, $arguments));

        if (null === $onProgress) {
            return $this->sendRequest(
                new CallToolRequest(
                    id: $this->mintRequestId(),
                    params: new CallToolRequestParams(
                        name: $name,
                        meta: $this->stampMeta(),
                        arguments: $arguments,
                        inputResponses: $inputResponses,
                        requestState: $requestState,
                    ),
                ),
                CallToolResultResponse::class,
                $context,
            )->result;
        }

        $progressToken = $this->mintProgressToken();
        $deadline = $this->openDeadline();

        try {
            $this->progressListeners->register(
                $progressToken,
                static function (float $progress, ?float $total, ?string $message) use ($onProgress, $deadline): void {
                    $deadline?->extend();
                    $onProgress($progress, $total, $message);
                },
            );

            return $this->dispatch(
                new CallToolRequest(
                    id: $this->mintRequestId(),
                    params: new CallToolRequestParams(
                        name: $name,
                        meta: $this->stampMeta($progressToken),
                        arguments: $arguments,
                        inputResponses: $inputResponses,
                        requestState: $requestState,
                    ),
                ),
                CallToolResultResponse::class,
                $context,
                $deadline,
            )->result;
        } finally {
            $deadline?->release();
            $this->progressListeners->unregister($progressToken);
        }
    }

    /**
     * @template TResponse of JsonRpcResultResponse
     *
     * @param JsonRpcRequest<non-empty-string> $request
     * @param class-string<TResponse>          $response
     *
     * @return TResponse
     *
     * @throws LogicException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     */
    private function dispatch(
        JsonRpcRequest $request,
        string $response,
        ?SendContext $context,
        ?RequestDeadline $deadline,
    ): JsonRpcResultResponse {
        try {
            try {
                return $this->exchange($request, $response, $context, $deadline);
            } catch (RemoteCallFailedException $e) {
                // SEP-2575: the client SHOULD retry once with a version the rejection named, and never retry the retry.
                $retry = $this->renegotiateProtocolVersion($request, $e);

                if (null === $retry) {
                    throw $e;
                }

                $this->logger->info(
                    'Retrying request {id} as {retry}: the server does not support {requested}.',
                    ['id' => $request->id->id, 'retry' => $retry->id->id, 'requested' => SafeDisplay::sanitiseCause($e->error->message)],
                );

                return $this->exchange($retry, $response, $context, $deadline);
            }
        } finally {
            $deadline?->release();
        }
    }

    /**
     * @template TResponse of JsonRpcResultResponse
     *
     * @param JsonRpcRequest<non-empty-string> $request
     * @param class-string<TResponse>          $response
     *
     * @return TResponse
     *
     * @throws LogicException
     * @throws RemoteCallFailedException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     */
    private function exchange(
        JsonRpcRequest $request,
        string $response,
        ?SendContext $context,
        ?RequestDeadline $deadline,
    ): JsonRpcResultResponse {
        $transport = $this->requireConnectedTransport();

        $this->assertServerSupports($request::getMethod());

        $retained = $this->retainsAcrossRestart($request);
        $future = $this->outboundRequests->register(
            $request->id,
            $response,
            $retained ? $request : null,
            $retained ? $context : null,
        );

        try {
            $transport->send($request, $context);
        } catch (\Throwable $e) {
            $this->outboundRequests->forget($request->id);

            throw $e;
        }

        if (null === $deadline) {
            return $future->await();
        }

        try {
            return $future->await($deadline->getCancellation());
        } catch (CancelledException $e) {
            throw $this->abandon($request, $transport, $deadline, $e);
        }
    }

    /**
     * @template TMethod of non-empty-string
     *
     * @param JsonRpcRequest<TMethod> $request
     *
     * @return null|JsonRpcRequest<TMethod>
     */
    private function renegotiateProtocolVersion(JsonRpcRequest $request, RemoteCallFailedException $failure): ?JsonRpcRequest
    {
        $error = $failure->error;

        if (! $error instanceof UnsupportedProtocolVersionError) {
            return null;
        }

        $version = self::pickSupportedVersion($error->supported);

        if (null === $version) {
            return null;
        }

        $params = $request->params;

        if (! $params instanceof RequestParams) {
            return null;
        }

        $meta = $params->meta->toArray();
        $meta[RequestMetaObject::PROTOCOL_VERSION_KEY] = $version;

        $fields = $params->toArray();
        $fields['_meta'] = $meta;

        $envelope = $request->toArray();
        $envelope['params'] = $fields;
        $envelope['id'] = $this->mintRequestId()->id;

        return $request::fromArray($envelope);
    }

    /**
     * The first version the peer named that this SDK also speaks.
     *
     * @param list<string> $supported
     */
    private static function pickSupportedVersion(array $supported): ?string
    {
        foreach ($supported as $version) {
            if (\in_array($version, ProtocolVersion::SUPPORTED_VERSIONS, true)) {
                return $version;
            }
        }

        return null;
    }

    /**
     * @param JsonRpcRequest<non-empty-string> $request
     */
    private function abandon(
        JsonRpcRequest $request,
        TransportInterface $transport,
        RequestDeadline $deadline,
        CancelledException $cause,
    ): RequestTimeoutException {
        $this->outboundRequests->forget($request->id);
        self::abortExchange($transport, $request->id);

        try {
            $transport->send(new CancelledNotification(
                params: new CancelledNotificationParams(requestId: $request->id, reason: 'The request timed out.'),
            ));
        } catch (\Throwable $e) {
            $this->logger->warning(
                'Could not tell the server that request {id} was abandoned.',
                ['id' => $request->id->id, 'exception' => $e],
            );
        }

        return new RequestTimeoutException($request->id, $deadline->readElapsed(), $cause);
    }

    /**
     * @param null|float $timeout Overrides the configured idle deadline for one request
     */
    private function openDeadline(?float $timeout = null): ?RequestDeadline
    {
        $timeout ??= $this->requestTimeout;

        return null === $timeout ? null : new RequestDeadline($timeout, $this->maxRequestTimeout);
    }

    /**
     * Caches the `x-mcp-header` bindings of every tool whose declarations hold, and drops the rest from the
     * listing.
     */
    private function admitMirrorableTools(ListToolsResult $result): ListToolsResult
    {
        $admitted = [];

        foreach ($result->tools as $tool) {
            $scan = ParameterHeaderScanner::scan($tool->inputSchema);

            if (! $scan->valid) {
                unset($this->toolHeaderBindings[$tool->name]);

                $reason = $scan->reason;
                \assert(\is_string($reason));

                $this->logger->warning(
                    'Excluding tool {tool} from the listing: its "x-mcp-header" declarations are invalid.',
                    ['tool' => SafeDisplay::sanitise($tool->name), 'reason' => SafeDisplay::sanitiseCause($reason)],
                );

                continue;
            }

            $this->toolHeaderBindings[$tool->name] = $scan->bindings;
            $admitted[] = $tool;
        }

        return $admitted === $result->tools ? $result : new ListToolsResult(
            tools: $admitted,
            ttlMs: $result->ttlMs,
            cacheScope: $result->cacheScope,
            nextCursor: $result->nextCursor,
            meta: $result->meta,
        );
    }

    /**
     * @param null|array<array-key, mixed> $arguments
     *
     * @return array<non-empty-string, string>
     */
    private function mirrorParameterHeaders(string $name, ?array $arguments): array
    {
        return ParameterHeaders::build($this->toolHeaderBindings[$name] ?? [], $arguments ?? []);
    }

    /**
     * @throws ServerCapabilityNotSupportedException
     */
    private function assertServerSupports(string $method): void
    {
        $capabilities = $this->serverCapabilities->current();

        if (null === $capabilities) {
            return;
        }

        $owner = $this->extensionMethods[$method] ?? null;

        if (null !== $owner && ! \array_key_exists($owner, $capabilities->extensions ?? [])) {
            throw new ServerCapabilityNotSupportedException($method);
        }

        $supported = match ($method) {
            ListToolsRequest::getMethod(), CallToolRequest::getMethod() => null !== $capabilities->tools,
            ListResourcesRequest::getMethod(),
            ListResourceTemplatesRequest::getMethod(),
            ReadResourceRequest::getMethod() => null !== $capabilities->resources,
            ListPromptsRequest::getMethod(), GetPromptRequest::getMethod() => null !== $capabilities->prompts,
            CompleteRequest::getMethod() => null !== $capabilities->completions,
            default => true,
        };

        if (! $supported) {
            throw new ServerCapabilityNotSupportedException($method);
        }
    }

    private function mintProgressToken(): ProgressToken
    {
        return new ProgressToken(token: ($this->progressTokenFactory)());
    }

    private function requireConnectedTransport(): TransportInterface
    {
        return $this->transport ?? throw new LogicException('Client is not connected. Call connect() first.');
    }
}
