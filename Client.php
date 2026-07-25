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

use Nexus\Mcp\Client\Dispatch\ProgressListenerRegistry;
use Nexus\Mcp\Client\Exception\ClientAlreadyConnectedException;
use Nexus\Mcp\Client\Exception\ClientNotConnectedException;
use Nexus\Mcp\Client\Exception\ServerCapabilityNotSupportedException;
use Nexus\Mcp\Core\Dispatch\MessageDispatcherInterface;
use Nexus\Mcp\Core\Dispatch\PendingOutboundRequests;
use Nexus\Mcp\Core\Exception\OutboundRequestFailedException;
use Nexus\Mcp\Core\Exception\TransportAlreadyClosedException;
use Nexus\Mcp\Core\Http\ParameterHeaderBinding;
use Nexus\Mcp\Core\Http\ParameterHeaders;
use Nexus\Mcp\Core\Http\ParameterHeaderScanner;
use Nexus\Mcp\Core\Schema\ClientCapabilities;
use Nexus\Mcp\Core\Schema\Cursor;
use Nexus\Mcp\Core\Schema\Implementation;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcRequest;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcResultResponse;
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
use Nexus\Mcp\Core\Schema\RequestId;
use Nexus\Mcp\Core\Schema\RequestMetaObject;
use Nexus\Mcp\Core\Schema\RequestParams\CallToolRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\CompleteRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\EmptyRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\GetPromptRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\PaginatedRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\ReadResourceRequestParams;
use Nexus\Mcp\Core\Schema\Resource\ResourceTemplateReference;
use Nexus\Mcp\Core\Schema\Result\CallToolResult;
use Nexus\Mcp\Core\Schema\Result\CompleteResult;
use Nexus\Mcp\Core\Schema\Result\DiscoverResult;
use Nexus\Mcp\Core\Schema\Result\GetPromptResult;
use Nexus\Mcp\Core\Schema\Result\InputRequiredResult;
use Nexus\Mcp\Core\Schema\Result\ListPromptsResult;
use Nexus\Mcp\Core\Schema\Result\ListResourcesResult;
use Nexus\Mcp\Core\Schema\Result\ListResourceTemplatesResult;
use Nexus\Mcp\Core\Schema\Result\ListToolsResult;
use Nexus\Mcp\Core\Schema\Result\ReadResourceResult;
use Nexus\Mcp\Core\Schema\ResultResponse\CallToolResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\CompleteResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\DiscoverResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\GetPromptResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\ListPromptsResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\ListResourcesResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\ListResourceTemplatesResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\ListToolsResultResponse;
use Nexus\Mcp\Core\Schema\ResultResponse\ReadResourceResultResponse;
use Nexus\Mcp\Core\Schema\ServerCapabilities;
use Nexus\Mcp\Core\Transport\ParameterHeaderMirroringInterface;
use Nexus\Mcp\Core\Transport\ReceiveContext;
use Nexus\Mcp\Core\Transport\SendContext;
use Nexus\Mcp\Core\Transport\TransportInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Client-side entry point: drives the transport lifecycle and exposes the typed
 * JSON-RPC operations a client issues against an MCP server.
 */
final class Client
{
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
        private readonly LoggerInterface $logger = new NullLogger(),
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

            $this->logger->error('Transport error.', ['exception' => $e]);
        });
        $transport->onDrain(function (): void {
            $this->dispatcher->flushPending();
        });
        $transport->onClose(function (): void {
            $this->outboundRequests->cancelAll(
                new TransportAlreadyClosedException(operation: 'await-response'),
            );
        });

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
     * @throws ClientNotConnectedException
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
     * @param null|array<string, mixed>                                             $arguments
     * @param null|\Closure(float $progress, ?float $total, ?string $message): void $onProgress
     *
     * @throws ClientNotConnectedException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function callTool(string $name, ?array $arguments = null, ?\Closure $onProgress = null): CallToolResult|InputRequiredResult
    {
        $context = new SendContext(headers: $this->mirrorParameterHeaders($name, $arguments));

        if (null === $onProgress) {
            return $this->sendRequest(
                new CallToolRequest(
                    id: $this->mintRequestId(),
                    params: new CallToolRequestParams(name: $name, meta: $this->stampMeta(), arguments: $arguments),
                ),
                CallToolResultResponse::class,
                $context,
            )->result;
        }

        $progressToken = $this->mintProgressToken();
        $this->progressListeners->register($progressToken, $onProgress);

        try {
            return $this->sendRequest(
                new CallToolRequest(
                    id: $this->mintRequestId(),
                    params: new CallToolRequestParams(
                        name: $name,
                        meta: $this->stampMeta($progressToken),
                        arguments: $arguments,
                    ),
                ),
                CallToolResultResponse::class,
                $context,
            )->result;
        } finally {
            $this->progressListeners->unregister($progressToken);
        }
    }

    /**
     * Sends an outbound JSON-RPC request and awaits the correlated response.
     *
     * @template TResponse of JsonRpcResultResponse = JsonRpcResultResponse
     *
     * @param JsonRpcRequest<non-empty-string> $request
     * @param class-string<TResponse>          $response
     *
     * @return TResponse
     *
     * @throws ClientNotConnectedException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function sendRequest(JsonRpcRequest $request, string $response, ?SendContext $context = null): JsonRpcResultResponse
    {
        $transport = $this->transport;

        if (null === $transport) {
            throw new ClientNotConnectedException();
        }

        $this->assertServerSupports($request::getMethod());

        $future = $this->outboundRequests->register($request->id, $response);

        try {
            $transport->send($request, $context);
        } catch (\Throwable $e) {
            // A failed send leaves the registration with no awaiter and no
            // response to correlate, so free the slot before propagating.
            $this->outboundRequests->forget($request->id);

            throw $e;
        }

        return $future->await();
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
     * @param ?array<string, mixed> $arguments
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
