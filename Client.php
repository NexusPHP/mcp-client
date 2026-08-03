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
use Nexus\Mcp\Client\Dispatch\ProgressListenerRegistry;
use Nexus\Mcp\Client\Dispatch\RequestDeadline;
use Nexus\Mcp\Client\Exception\ClientAlreadyConnectedException;
use Nexus\Mcp\Client\Exception\ClientNotConnectedException;
use Nexus\Mcp\Client\Exception\ServerCapabilityNotSupportedException;
use Nexus\Mcp\Client\Subscription\OpenSubscription;
use Nexus\Mcp\Client\Subscription\SubscriptionRegistry;
use Nexus\Mcp\Client\Subscription\SubscriptionStream;
use Nexus\Mcp\Core\Dispatch\MessageDispatcherInterface;
use Nexus\Mcp\Core\Dispatch\PendingOutboundRequests;
use Nexus\Mcp\Core\Exception\OutboundRequestFailedException;
use Nexus\Mcp\Core\Exception\RemoteCallFailedException;
use Nexus\Mcp\Core\Exception\RequestTimeoutException;
use Nexus\Mcp\Core\Exception\SupervisionExhaustedException;
use Nexus\Mcp\Core\Exception\TransportAlreadyClosedException;
use Nexus\Mcp\Core\Http\ParameterHeaderBinding;
use Nexus\Mcp\Core\Http\ParameterHeaders;
use Nexus\Mcp\Core\Http\ParameterHeaderScanner;
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
use Nexus\Mcp\Core\Schema\RequestParams\InputResponseRequestParams;
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
use Nexus\Mcp\Core\Transport\ParameterHeaderMirroringInterface;
use Nexus\Mcp\Core\Transport\ReceiveContext;
use Nexus\Mcp\Core\Transport\ReconnectingTransportInterface;
use Nexus\Mcp\Core\Transport\SendContext;
use Nexus\Mcp\Core\Transport\TransportInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Revolt\EventLoop;

/**
 * Client-side entry point: drives the transport lifecycle and exposes the typed
 * JSON-RPC operations a client issues against an MCP server.
 */
final class Client
{
    /**
     * Seconds a request may go unanswered before it is abandoned. Each progress notification for the
     * request restarts it.
     */
    public const float DEFAULT_REQUEST_TIMEOUT = 60.0;

    /**
     * Seconds a request may run in total, however much progress arrives.
     */
    public const float DEFAULT_MAX_REQUEST_TIMEOUT = 600.0;

    /**
     * The requests a lost call may be sent again as. A retry is at-least-once, because the peer may have
     * carried the work out before it died, so only requests that read state are eligible. The spec marks
     * no tool as idempotent, which keeps `tools/call` off the list however harmless a given tool is, and
     * a vendor method sent through `sendRequest()` has no semantics this SDK can judge.
     */
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
    private ?ServerCapabilities $serverCapabilities = null;

    /**
     * `x-mcp-header` bindings of every tool a `tools/list` admitted, keyed by tool name. Only a transport
     * that mirrors parameter headers populates it.
     *
     * @var array<string, list<ParameterHeaderBinding>>
     */
    private array $toolHeaderBindings = [];

    /**
     * @param \Closure(): (int|non-empty-string) $requestIdFactory
     * @param \Closure(): (int|non-empty-string) $progressTokenFactory
     * @param null|float                         $requestTimeout       Seconds a request may go unanswered, or `null` to wait indefinitely
     * @param null|float                         $maxRequestTimeout    Seconds a request may run however much progress arrives, or `null` to leave it unbounded
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
    ) {
    }

    /**
     * Non-blocking connect to the transport.
     *
     * @throws ClientAlreadyConnectedException
     */
    public function connect(TransportInterface $transport): void
    {
        if (null !== $this->transport) {
            // Reject reentry to avoid orphaning the previous transport.
            throw new ClientAlreadyConnectedException();
        }

        $this->logger->info('Starting MCP client.');

        $this->transport = $transport;

        $transport->onMessage(function (array $envelope, ReceiveContext $context) use ($transport): void {
            $this->dispatcher->dispatch($envelope, $transport, $context);
        });
        $transport->onError(function (\Throwable $e): void {
            if ($e instanceof OutboundRequestFailedException) {
                // The exchange that carried this request is over, so its response can no longer arrive.
                // A caller still awaiting one would otherwise block for the life of the process.
                $this->outboundRequests->reject($e->requestId, $e);
            }

            if ($e instanceof SupervisionExhaustedException) {
                // No further peer is coming, so a stream held open across the restarts has nothing left
                // to be re-opened against, and a retained request has nothing left to be sent to. Both
                // would otherwise wait for the life of the process.
                $this->settleSubscriptions($e);
                $this->outboundRequests->cancelAll($e);
            }

            $this->logger->error('Transport error.', ['exception' => $e]);
        });
        $transport->onDrain(function (): void {
            $this->dispatcher->flushPending();
        });
        $transport->onClose(function () use ($transport): void {
            $error = new TransportAlreadyClosedException(operation: 'await-response');

            // A retained request outlives the peer that was carrying it, so only the rest fail here.
            $this->outboundRequests->cancelUnretained($error);

            // The supervisor decides on a replacement after emitting this close, so whether one is coming
            // is only readable on the next tick.
            EventLoop::queue(function () use ($transport, $error): void {
                if ($transport !== $this->transport) {
                    // A transport this client has already let go of speaks for nothing that is pending
                    // now. `disconnect()` failed what it was owed before detaching it.
                    return;
                }

                if ($transport instanceof ReconnectingTransportInterface && $transport->isReconnecting()) {
                    return;
                }

                // Nothing replaces this peer, so a retained request has run out of peers to be sent to.
                // Streams need no help here: the close that got us this far freed their correlation
                // slots, and each stream settles from its own failed exchange.
                $this->outboundRequests->cancelAll($error);
            });
        });

        if ($transport instanceof ReconnectingTransportInterface) {
            $transport->onReconnect(function () use ($transport): void {
                foreach ($this->outboundRequests->collectRetained() as $retained) {
                    $request = $retained['request'];

                    try {
                        $transport->send($request, $retained['context']);
                    } catch (\Throwable $e) {
                        if ($transport->isReconnecting()) {
                            // This replacement died too. Left retained so the peer after it tries again,
                            // matching what the subscription walk below does.
                            $this->logger->warning(
                                'Could not send request {id} again to the replacement peer.',
                                ['id' => $request->id->id, 'exception' => $e],
                            );

                            continue;
                        }

                        // Nothing else will carry it, so the caller hears now rather than at the deadline.
                        $this->outboundRequests->reject($request->id, $e);
                    }
                }

                foreach ($this->subscriptions->all() as $subscription) {
                    try {
                        $this->openStream($subscription, $transport);
                    } catch (\Throwable $e) {
                        // Left registered, so the next replacement peer gets another go at it.
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
     * Closes the transport and detaches it so a fresh `connect()` can run.
     * A no-op when the client is not connected.
     */
    public function disconnect(): void
    {
        $transport = $this->transport;
        $this->transport = null;

        // The cached bindings describe the server that just went away, so a later connection must not
        // mirror headers from them.
        $this->toolHeaderBindings = [];

        // Settled before the close, so a supervised transport cannot answer the peer loss it is about to
        // see by re-opening streams, or re-sending requests, the caller has just given up.
        $error = new TransportAlreadyClosedException(operation: 'await-response');
        $this->settleSubscriptions($error);
        $this->outboundRequests->cancelAll($error);

        $transport?->close();
    }

    /**
     * The server's `Implementation` block from the last `server/discover`
     * response `_meta`, or `null` if discovery has not run or the server did
     * not identify itself.
     */
    public function getServerInfo(): ?Implementation
    {
        return $this->serverInfo;
    }

    /**
     * The server's capabilities from the last `server/discover` response, or
     * `null` if discovery has not run.
     */
    public function getServerCapabilities(): ?ServerCapabilities
    {
        return $this->serverCapabilities;
    }

    /**
     * Sends `server/discover` and records the advertised server info and capabilities.
     *
     * @throws ClientNotConnectedException
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
        $this->serverCapabilities = $result->capabilities;

        return $result;
    }

    /**
     * Opens a `subscriptions/listen` stream and routes every notification the server tags with its id to
     * `$onNotification`. Returns as soon as the request is away: the stream runs until either side ends it.
     *
     * @param \Closure(JsonRpcNotification<non-empty-string>): void $onNotification
     *
     * @throws ClientNotConnectedException
     * @throws TransportAlreadyClosedException
     */
    public function listen(SubscriptionFilter $notifications, \Closure $onNotification): SubscriptionStream
    {
        $transport = $this->transport ?? throw new ClientNotConnectedException();

        $id = $this->mintRequestId();

        /** @var DeferredFuture<SubscriptionsListenResult> $outcome */
        $outcome = new DeferredFuture();

        // Only an explicit await() observes the outcome. Left unignored, a refused subscription would
        // surface as an unhandled future when the stream is collected.
        $future = $outcome->getFuture();
        $future->ignore();

        $subscription = new OpenSubscription($id, $notifications, $onNotification, $outcome);

        // Routed only once the correlation slot is claimed, so an id already in flight is refused before
        // this stream can displace the routing entry of the live one that owns it.
        $this->openStream($subscription, $transport);
        $this->subscriptions->register($subscription);

        return new SubscriptionStream($id, $future, function () use ($id, $transport): void {
            $this->subscriptions->forget($id);

            if (! $this->outboundRequests->forget($id)) {
                // The server already answered, so no in-flight request remains for a cancellation to name.
                return;
            }

            try {
                $transport->send(new CancelledNotification(
                    params: new CancelledNotificationParams(requestId: $id, reason: 'The subscription was closed.'),
                ));
            } catch (\Throwable $e) {
                // Closing a stream whose transport already went away is teardown, not a failure to report.
                $this->logger->debug(
                    'Could not tell the server that subscription {id} was closed.',
                    ['id' => $id->id, 'exception' => $e],
                );
            }
        });
    }

    /**
     * @throws ClientNotConnectedException
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
     * @throws ClientNotConnectedException
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
     * @throws ClientNotConnectedException
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
     * @throws ClientNotConnectedException
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
     * @throws ClientNotConnectedException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function readResource(string $uri): InputRequiredResult|ReadResourceResult
    {
        return $this->sendRequest(
            new ReadResourceRequest(
                id: $this->mintRequestId(),
                params: new ReadResourceRequestParams(uri: $uri, meta: $this->stampMeta()),
            ),
            ReadResourceResultResponse::class,
        )->result;
    }

    /**
     * @param null|array<string, string> $arguments
     *
     * @throws ClientNotConnectedException
     * @throws RequestTimeoutException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function getPrompt(string $name, ?array $arguments = null): GetPromptResult|InputRequiredResult
    {
        return $this->sendRequest(
            new GetPromptRequest(
                id: $this->mintRequestId(),
                params: new GetPromptRequestParams(name: $name, meta: $this->stampMeta(), arguments: $arguments),
            ),
            GetPromptResultResponse::class,
        )->result;
    }

    /**
     * @param array{name: string, value: string}            $argument
     * @param null|array{arguments?: array<string, string>} $context
     *
     * @throws ClientNotConnectedException
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
     * Invokes a tool. When `$onProgress` is given, a fresh `progressToken` is
     * minted into the request's `_meta` and the callback receives every
     * matching `notifications/progress` for the duration of the call.
     *
     * A server that needs more input answers with an `InputRequiredResult` rather
     * than a result. Satisfy each of its `inputRequests` and call again with the
     * answers plus the `requestState` it carried, which is opaque and must be
     * echoed back unchanged.
     *
     * @param null|array<string, mixed>                                             $arguments
     * @param null|\Closure(float $progress, ?float $total, ?string $message): void $onProgress
     * @param null|array<string, InputResponse>                                     $inputResponses Answers to a prior `InputRequiredResult`, keyed as its `inputRequests` were
     * @param null|string                                                           $requestState   Echoed verbatim from the `InputRequiredResult` being answered
     *
     * @throws ClientNotConnectedException
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

        // A header mismatch means the cached `inputSchema` is behind the server's, so refresh it and
        // retry exactly once. A second mismatch is the server's answer and propagates.
        $this->refreshToolHeaderBindings($name);

        return $this->attemptToolCall($name, $arguments, $onProgress, $inputResponses, $requestState);
    }

    /**
     * Sends an outbound JSON-RPC request and awaits the correlated response.
     *
     * @template TResponse of JsonRpcResultResponse = JsonRpcResultResponse
     *
     * @param JsonRpcRequest<non-empty-string> $request
     * @param class-string<TResponse>          $response
     * @param null|float                       $timeout  Seconds this one request may go unanswered, overriding the client's default
     *
     * @return TResponse
     *
     * @throws ClientNotConnectedException
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

    /**
     * Sends `$subscription`'s listen request on `$transport` and routes that one connection's answer to
     * the caller-facing outcome. Runs once per connection the subscription is carried on.
     *
     * @throws TransportAlreadyClosedException
     */
    private function openStream(OpenSubscription $subscription, TransportInterface $transport): void
    {
        $id = $subscription->subscriptionId;

        // Claim the correlation slot first: a duplicate id must not leave a routing entry behind.
        $response = $this->outboundRequests->register($id, SubscriptionsListenResultResponse::class);

        $response
            ->map(function (SubscriptionsListenResultResponse $response) use ($id): void {
                // Absent when the caller closed the stream first, which owes them no outcome.
                $this->subscriptions->forget($id)?->outcome->complete($response->result);
            })
            ->catch(function (\Throwable $e) use ($id, $transport): void {
                // Read here rather than when the request went out, because only a failure that a
                // replacement peer will be given another go at leaves the stream owing an outcome. A peer
                // that answers "no" is answering, so it ends the stream however replaceable it was.
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
     * Whether a peer that dies mid-`$request` should be replaced and the request sent again, rather than
     * the caller hearing that the connection went away.
     *
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
                // A multi-round-trip continuation only names a state-reading method. It carries the user's
                // answers and an opaque resume token, so sending it again hands a one-time answer over
                // twice and resumes work the peer that issued the token no longer has.
                return ! self::resumesAnEarlierRound($request->params);
            }
        }

        return false;
    }

    /**
     * Whether these params continue an exchange the server suspended, rather than opening a fresh one.
     */
    private static function resumesAnEarlierRound(?RequestParamsInterface $params): bool
    {
        [$inputResponses, $requestState] = match (true) {
            $params instanceof InputResponseRequestParams => [$params->inputResponses, $params->requestState],
            $params instanceof ReadResourceRequestParams => [$params->inputResponses, $params->requestState],
            default => [null, null],
        };

        return null !== $inputResponses || null !== $requestState;
    }

    /**
     * Fails every stream still open, for a client that will not be re-opening them.
     */
    private function settleSubscriptions(\Throwable $reason): void
    {
        foreach ($this->subscriptions->drain() as $subscription) {
            $subscription->outcome->error($reason);
        }
    }

    /**
     * Re-lists the named tool so its cached `x-mcp-header` bindings match the server's current
     * `inputSchema`, walking pages until the listing yields it or runs out of them.
     */
    private function refreshToolHeaderBindings(string $name): void
    {
        $cursor = null;

        do {
            $page = $this->listTools($cursor);

            foreach ($page->tools as $tool) {
                if ($tool->name === $name) {
                    return;
                }
            }

            $cursor = $page->nextCursor;
        } while (null !== $cursor);
    }

    /**
     * One `tools/call` attempt, mirroring whatever parameter headers are cached for the tool.
     *
     * @param null|array<string, mixed>                                             $arguments
     * @param null|\Closure(float $progress, ?float $total, ?string $message): void $onProgress
     * @param null|array<string, InputResponse>                                     $inputResponses
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

        // The deadline arms its timers on construction, so everything from here on runs under the `finally`
        // that disarms them. A throw in between would otherwise hold the event loop open for the ceiling.
        $deadline = $this->openDeadline();

        try {
            // Progress means the call is alive, so each report buys it another idle window, up to the ceiling.
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
     * @throws ClientNotConnectedException
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
                // SEP-2575: a server that rejects the requested version names the ones it accepts, and the
                // client SHOULD retry with one of them. The retry is not itself retried.
                $retry = $this->renegotiateProtocolVersion($request, $e);

                if (null === $retry) {
                    throw $e;
                }

                $this->logger->info(
                    'Retrying request {id} as {retry}: the server does not support {requested}.',
                    ['id' => $request->id->id, 'retry' => $retry->id->id, 'requested' => $e->error->message],
                );

                return $this->exchange($retry, $response, $context, $deadline);
            }
        } finally {
            $deadline?->release();
        }
    }

    /**
     * Sends one request and awaits its correlated response.
     *
     * @template TResponse of JsonRpcResultResponse
     *
     * @param JsonRpcRequest<non-empty-string> $request
     * @param class-string<TResponse>          $response
     *
     * @return TResponse
     *
     * @throws ClientNotConnectedException
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
        $transport = $this->transport ?? throw new ClientNotConnectedException();

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
            // A failed send leaves the registration with no awaiter and no
            // response to correlate, so free the slot before propagating.
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
     * Rebuilds the request under a version the rejection named as supported, or null when the failure is
     * not a version rejection or names no version this SDK speaks.
     *
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
            // A request carrying no typed params carries no `_meta` to restamp either.
            return null;
        }

        $meta = $params->meta->toArray();
        $meta[RequestMetaObject::PROTOCOL_VERSION_KEY] = $version;

        $fields = $params->toArray();
        $fields['_meta'] = $meta;

        $envelope = $request->toArray();
        $envelope['params'] = $fields;

        // A fresh id: the rejected one has already been answered and its slot retired.
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
     * Frees the request's slot and tells the peer to stop working on it, then reports the timeout. A
     * response arriving after this has no awaiter left and is discarded as an orphan.
     *
     * @param JsonRpcRequest<non-empty-string> $request
     */
    private function abandon(
        JsonRpcRequest $request,
        TransportInterface $transport,
        RequestDeadline $deadline,
        CancelledException $cause,
    ): RequestTimeoutException {
        $this->outboundRequests->forget($request->id);

        try {
            $transport->send(new CancelledNotification(
                params: new CancelledNotificationParams(requestId: $request->id, reason: 'The request timed out.'),
            ));
        } catch (\Throwable $e) {
            // The peer goes on working on a result nobody will read, which the timeout itself survives.
            $this->logger->warning(
                'Could not tell the server that request {id} was abandoned.',
                ['id' => $request->id->id, 'exception' => $e],
            );
        }

        return new RequestTimeoutException($request->id, $deadline->elapsed, $cause);
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
     * listing: the spec has a client exclude a tool it cannot mirror rather than call it unmirrored.
     */
    private function admitMirrorableTools(ListToolsResult $result): ListToolsResult
    {
        $admitted = [];

        foreach ($result->tools as $tool) {
            $scan = ParameterHeaderScanner::scan($tool->inputSchema);

            if (! $scan->valid) {
                // A re-listed tool whose declarations no longer hold must not keep mirroring the bindings
                // an earlier listing cached for it.
                unset($this->toolHeaderBindings[$tool->name]);

                $this->logger->warning(
                    'Excluding tool {tool} from the listing: its "x-mcp-header" declarations are invalid.',
                    ['tool' => $tool->name, 'reason' => $scan->reason],
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
     * The mirrored `Mcp-Param-{Name}` headers for one tool call, empty when the transport does not mirror
     * them or the tool declared none.
     *
     * @param null|array<string, mixed> $arguments
     *
     * @return array<non-empty-string, string>
     */
    private function mirrorParameterHeaders(string $name, ?array $arguments): array
    {
        // Only a mirroring transport ever fills the cache, so an empty one already means nothing to mirror.
        return ParameterHeaders::build($this->toolHeaderBindings[$name] ?? [], $arguments ?? []);
    }

    /**
     * Builds the self-describing `_meta` envelope stamped onto every request.
     */
    private function stampMeta(?ProgressToken $progressToken = null): RequestMetaObject
    {
        return new RequestMetaObject(
            protocolVersion: $this->protocolVersion,
            clientInfo: $this->clientInfo,
            clientCapabilities: $this->clientCapabilities,
            progressToken: $progressToken,
        );
    }

    /**
     * @throws ServerCapabilityNotSupportedException
     */
    private function assertServerSupports(string $method): void
    {
        $capabilities = $this->serverCapabilities;

        if (null === $capabilities) {
            // Discovery has not run, so there are no advertised capabilities to enforce.
            return;
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

    private function mintRequestId(): RequestId
    {
        return new RequestId(id: ($this->requestIdFactory)());
    }

    private function mintProgressToken(): ProgressToken
    {
        return new ProgressToken(token: ($this->progressTokenFactory)());
    }
}
