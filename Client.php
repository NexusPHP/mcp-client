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

use Nexus\Mcp\Client\Dispatch\ClientInitializationGate;
use Nexus\Mcp\Client\Dispatch\ProgressListenerRegistry;
use Nexus\Mcp\Core\Dispatch\MessageDispatcherInterface;
use Nexus\Mcp\Core\Dispatch\PendingOutboundRequests;
use Nexus\Mcp\Core\Exception\TransportAlreadyClosedException;
use Nexus\Mcp\Core\Schema\ClientCapabilities;
use Nexus\Mcp\Core\Schema\Cursor;
use Nexus\Mcp\Core\Schema\Implementation;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcRequest;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcResultResponse;
use Nexus\Mcp\Core\Schema\Notification\InitializedNotification;
use Nexus\Mcp\Core\Schema\ProgressToken;
use Nexus\Mcp\Core\Schema\Prompt\PromptReference;
use Nexus\Mcp\Core\Schema\ProtocolVersion;
use Nexus\Mcp\Core\Schema\Request\CallToolRequest;
use Nexus\Mcp\Core\Schema\Request\CompleteRequest;
use Nexus\Mcp\Core\Schema\Request\GetPromptRequest;
use Nexus\Mcp\Core\Schema\Request\InitializeRequest;
use Nexus\Mcp\Core\Schema\Request\ListPromptsRequest;
use Nexus\Mcp\Core\Schema\Request\ListResourcesRequest;
use Nexus\Mcp\Core\Schema\Request\ListResourceTemplatesRequest;
use Nexus\Mcp\Core\Schema\Request\ListToolsRequest;
use Nexus\Mcp\Core\Schema\Request\ReadResourceRequest;
use Nexus\Mcp\Core\Schema\RequestId;
use Nexus\Mcp\Core\Schema\RequestMetaObject;
use Nexus\Mcp\Core\Schema\RequestParams\CallToolRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\CompleteRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\GetPromptRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\InitializeRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\PaginatedRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\ReadResourceRequestParams;
use Nexus\Mcp\Core\Schema\Resource\ResourceTemplateReference;
use Nexus\Mcp\Core\Schema\Result;
use Nexus\Mcp\Core\Schema\Result\CallToolResult;
use Nexus\Mcp\Core\Schema\Result\CompleteResult;
use Nexus\Mcp\Core\Schema\Result\GetPromptResult;
use Nexus\Mcp\Core\Schema\Result\InitializeResult;
use Nexus\Mcp\Core\Schema\Result\ListPromptsResult;
use Nexus\Mcp\Core\Schema\Result\ListResourcesResult;
use Nexus\Mcp\Core\Schema\Result\ListResourceTemplatesResult;
use Nexus\Mcp\Core\Schema\Result\ListToolsResult;
use Nexus\Mcp\Core\Schema\Result\ReadResourceResult;
use Nexus\Mcp\Core\Transport\TransportInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Client-side entry point: drives the transport lifecycle, runs the
 * `initialize` handshake, and exposes the typed JSON-RPC operations a client
 * issues against an MCP server.
 */
final class Client
{
    private ?TransportInterface $transport = null;
    private ?Implementation $serverInfo = null;

    /**
     * @param \Closure(): (int|non-empty-string) $requestIdFactory
     * @param \Closure(): (int|non-empty-string) $progressTokenFactory
     */
    public function __construct(
        private readonly Implementation $clientInfo,
        private readonly MessageDispatcherInterface $dispatcher,
        private readonly PendingOutboundRequests $outboundRequests,
        private readonly ClientInitializationGate $initializationGate,
        private readonly \Closure $requestIdFactory,
        private readonly \Closure $progressTokenFactory,
        private readonly ProgressListenerRegistry $progressListeners = new ProgressListenerRegistry(),
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {
    }

    public static function builder(): ClientBuilder
    {
        return new ClientBuilder();
    }

    /**
     * Non-blocking connect to the transport.
     *
     * @throws \LogicException
     */
    public function connect(TransportInterface $transport): void
    {
        if (null !== $this->transport) {
            // Reject reentry to avoid orphaning the previous transport.
            throw new \LogicException('Client is already connected to a transport.');
        }

        $this->logger->info('Starting MCP client.');

        $this->transport = $transport;

        $transport->onMessage(function (array $envelope) use ($transport): void {
            $this->dispatcher->dispatch($envelope, $transport);
        });
        $transport->onError(function (\Throwable $e): void {
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
     * Sends `initialize`, awaits the result, then sends `notifications/initialized`.
     *
     * @throws \LogicException
     * @throws TransportAlreadyClosedException
     */
    public function initialize(
        ClientCapabilities $capabilities = new ClientCapabilities(),
        ?ProtocolVersion $protocolVersion = null,
    ): InitializeResult {
        if (null === $this->transport) {
            throw new \LogicException('Client is not connected. Call connect() first.');
        }

        if (! $this->initializationGate->markInitializeInFlight()) {
            throw new \LogicException('Client handshake already started or completed.');
        }

        try {
            $protocolVersion ??= new ProtocolVersion(ProtocolVersion::LATEST_VERSION);
            $request = new InitializeRequest(
                $this->mintRequestId(),
                new InitializeRequestParams($protocolVersion, $capabilities, $this->clientInfo),
            );

            $future = $this->outboundRequests->register($request->id, InitializeResult::class);
            $this->transport->send($request);
            $response = $future->await();

            $this->transport->send(new InitializedNotification());
            $this->initializationGate->markInitialized();

            $result = $response->result;
            $this->serverInfo = $result->serverInfo;

            return $result;
        } catch (\Throwable $e) {
            $this->initializationGate->revertInitializeInFlight();

            throw $e;
        }
    }

    /**
     * Server `Implementation` block captured from the initialize response, or
     * `null` if the handshake has not completed yet.
     */
    public function getServerInfo(): ?Implementation
    {
        return $this->serverInfo;
    }

    /**
     * @throws \LogicException
     * @throws TransportAlreadyClosedException
     */
    public function listTools(?Cursor $cursor = null): ListToolsResult
    {
        return $this->sendRequest(
            new ListToolsRequest($this->mintRequestId(), new PaginatedRequestParams($cursor)),
            ListToolsResult::class,
        )->result;
    }

    /**
     * @throws \LogicException
     * @throws TransportAlreadyClosedException
     */
    public function listResources(?Cursor $cursor = null): ListResourcesResult
    {
        return $this->sendRequest(
            new ListResourcesRequest($this->mintRequestId(), new PaginatedRequestParams($cursor)),
            ListResourcesResult::class,
        )->result;
    }

    /**
     * @throws \LogicException
     * @throws TransportAlreadyClosedException
     */
    public function listResourceTemplates(?Cursor $cursor = null): ListResourceTemplatesResult
    {
        return $this->sendRequest(
            new ListResourceTemplatesRequest($this->mintRequestId(), new PaginatedRequestParams($cursor)),
            ListResourceTemplatesResult::class,
        )->result;
    }

    /**
     * @throws \LogicException
     * @throws TransportAlreadyClosedException
     */
    public function listPrompts(?Cursor $cursor = null): ListPromptsResult
    {
        return $this->sendRequest(
            new ListPromptsRequest($this->mintRequestId(), new PaginatedRequestParams($cursor)),
            ListPromptsResult::class,
        )->result;
    }

    /**
     * @throws \LogicException
     * @throws TransportAlreadyClosedException
     */
    public function readResource(string $uri): ReadResourceResult
    {
        return $this->sendRequest(
            new ReadResourceRequest($this->mintRequestId(), new ReadResourceRequestParams($uri)),
            ReadResourceResult::class,
        )->result;
    }

    /**
     * @param null|array<string, string> $arguments
     *
     * @throws \LogicException
     * @throws TransportAlreadyClosedException
     */
    public function getPrompt(string $name, ?array $arguments = null): GetPromptResult
    {
        return $this->sendRequest(
            new GetPromptRequest($this->mintRequestId(), new GetPromptRequestParams($name, $arguments)),
            GetPromptResult::class,
        )->result;
    }

    /**
     * @param array{name: string, value: string}            $argument
     * @param null|array{arguments?: array<string, string>} $context
     *
     * @throws \LogicException
     * @throws TransportAlreadyClosedException
     */
    public function complete(
        PromptReference|ResourceTemplateReference $ref,
        array $argument,
        ?array $context = null,
    ): CompleteResult {
        return $this->sendRequest(
            new CompleteRequest(
                $this->mintRequestId(),
                new CompleteRequestParams($ref, $argument, $context),
            ),
            CompleteResult::class,
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
     * @throws \LogicException
     * @throws TransportAlreadyClosedException
     */
    public function callTool(string $name, ?array $arguments = null, ?\Closure $onProgress = null): CallToolResult
    {
        if (null === $onProgress) {
            return $this->sendRequest(
                new CallToolRequest($this->mintRequestId(), new CallToolRequestParams($name, $arguments)),
                CallToolResult::class,
            )->result;
        }

        $progressToken = $this->mintProgressToken();
        $this->progressListeners->register($progressToken, $onProgress);

        try {
            return $this->sendRequest(
                new CallToolRequest(
                    $this->mintRequestId(),
                    new CallToolRequestParams(
                        $name,
                        $arguments,
                        meta: new RequestMetaObject(progressToken: $progressToken),
                    ),
                ),
                CallToolResult::class,
            )->result;
        } finally {
            $this->progressListeners->unregister($progressToken);
        }
    }

    /**
     * Sends an outbound JSON-RPC request and awaits the correlated response.
     *
     * @template T of Result
     *
     * @param JsonRpcRequest<non-empty-string> $request
     * @param class-string<T>                  $result
     *
     * @return JsonRpcResultResponse<T>
     *
     * @throws \LogicException
     * @throws TransportAlreadyClosedException
     */
    public function sendRequest(JsonRpcRequest $request, string $result): JsonRpcResultResponse
    {
        if (null === $this->transport) {
            throw new \LogicException('Client is not connected. Call connect() first.');
        }

        $method = $request::method();

        if (! $this->initializationGate->allowsRequest($method)) {
            throw new \LogicException(\sprintf(
                'Request method "%s" cannot be sent before the client handshake completes.',
                $method,
            ));
        }

        $future = $this->outboundRequests->register($request->id, $result);
        $this->transport->send($request);

        return $future->await();
    }

    private function mintRequestId(): RequestId
    {
        return new RequestId(($this->requestIdFactory)());
    }

    private function mintProgressToken(): ProgressToken
    {
        return new ProgressToken(($this->progressTokenFactory)());
    }
}
