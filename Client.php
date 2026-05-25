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
use Nexus\Mcp\Client\Exception\ClientAlreadyConnectedException;
use Nexus\Mcp\Client\Exception\ClientAlreadyInitializedException;
use Nexus\Mcp\Client\Exception\ClientNotConnectedException;
use Nexus\Mcp\Client\Exception\ClientNotInitializedException;
use Nexus\Mcp\Client\Exception\ServerCapabilityNotSupportedException;
use Nexus\Mcp\Client\Exception\UnsupportedProtocolVersionException;
use Nexus\Mcp\Core\Dispatch\MessageDispatcherInterface;
use Nexus\Mcp\Core\Dispatch\PendingOutboundRequests;
use Nexus\Mcp\Core\Exception\TransportAlreadyClosedException;
use Nexus\Mcp\Core\Schema\ClientCapabilities;
use Nexus\Mcp\Core\Schema\Cursor;
use Nexus\Mcp\Core\Schema\Enum\LoggingLevel;
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
use Nexus\Mcp\Core\Schema\Request\PingRequest;
use Nexus\Mcp\Core\Schema\Request\ReadResourceRequest;
use Nexus\Mcp\Core\Schema\Request\SetLevelRequest;
use Nexus\Mcp\Core\Schema\RequestId;
use Nexus\Mcp\Core\Schema\RequestMetaObject;
use Nexus\Mcp\Core\Schema\RequestParams\CallToolRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\CompleteRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\EmptyRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\GetPromptRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\InitializeRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\PaginatedRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\ReadResourceRequestParams;
use Nexus\Mcp\Core\Schema\RequestParams\SetLevelRequestParams;
use Nexus\Mcp\Core\Schema\Resource\ResourceTemplateReference;
use Nexus\Mcp\Core\Schema\Result;
use Nexus\Mcp\Core\Schema\Result\CallToolResult;
use Nexus\Mcp\Core\Schema\Result\CompleteResult;
use Nexus\Mcp\Core\Schema\Result\EmptyResult;
use Nexus\Mcp\Core\Schema\Result\GetPromptResult;
use Nexus\Mcp\Core\Schema\Result\InitializeResult;
use Nexus\Mcp\Core\Schema\Result\ListPromptsResult;
use Nexus\Mcp\Core\Schema\Result\ListResourcesResult;
use Nexus\Mcp\Core\Schema\Result\ListResourceTemplatesResult;
use Nexus\Mcp\Core\Schema\Result\ListToolsResult;
use Nexus\Mcp\Core\Schema\Result\ReadResourceResult;
use Nexus\Mcp\Core\Schema\ServerCapabilities;
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
    private ?ServerCapabilities $serverCapabilities = null;

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
     * Closes the transport and detaches it so a fresh `connect()` can run.
     * A no-op when the client is not connected.
     */
    public function disconnect(): void
    {
        $transport = $this->transport;
        $this->transport = null;
        $transport?->close();
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
     * Server capabilities negotiated during the initialize response, or `null` if
     * the handshake has not completed yet.
     */
    public function getServerCapabilities(): ?ServerCapabilities
    {
        return $this->serverCapabilities;
    }

    /**
     * Sends a `ping` and awaits the peer's empty acknowledgement. Permitted
     * before the handshake completes.
     *
     * @throws ClientNotConnectedException
     * @throws TransportAlreadyClosedException
     */
    public function ping(): void
    {
        $this->sendRequest(
            new PingRequest($this->mintRequestId(), new EmptyRequestParams()),
            EmptyResult::class,
        );
    }

    /**
     * Sends `initialize`, awaits the result, then sends `notifications/initialized`.
     *
     * @throws ClientAlreadyInitializedException
     * @throws ClientNotConnectedException
     * @throws TransportAlreadyClosedException
     */
    public function initialize(
        ClientCapabilities $capabilities = new ClientCapabilities(),
        ?ProtocolVersion $protocolVersion = null,
    ): InitializeResult {
        if (null === $this->transport) {
            throw new ClientNotConnectedException();
        }

        if (! $this->initializationGate->markInitializeInFlight()) {
            throw new ClientAlreadyInitializedException();
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
            $result = $response->result;

            // Spec: when the negotiated version is one the client cannot speak, it
            // must not confirm the handshake and SHOULD disconnect.
            if (ProtocolVersion::LATEST_VERSION !== $result->protocolVersion->version) {
                $this->disconnect();

                throw new UnsupportedProtocolVersionException($result->protocolVersion);
            }

            $this->transport->send(new InitializedNotification());
            $this->initializationGate->markInitialized();

            $this->serverInfo = $result->serverInfo;
            $this->serverCapabilities = $result->capabilities;

            return $result;
        } catch (\Throwable $e) {
            $this->initializationGate->revertInitializeInFlight();

            throw $e;
        }
    }

    /**
     * @throws ClientNotConnectedException
     * @throws ClientNotInitializedException
     * @throws ServerCapabilityNotSupportedException
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
     * @throws ClientNotConnectedException
     * @throws ClientNotInitializedException
     * @throws ServerCapabilityNotSupportedException
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
     * @throws ClientNotConnectedException
     * @throws ClientNotInitializedException
     * @throws ServerCapabilityNotSupportedException
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
     * @throws ClientNotConnectedException
     * @throws ClientNotInitializedException
     * @throws ServerCapabilityNotSupportedException
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
     * @throws ClientNotConnectedException
     * @throws ClientNotInitializedException
     * @throws ServerCapabilityNotSupportedException
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
     * @throws ClientNotConnectedException
     * @throws ClientNotInitializedException
     * @throws ServerCapabilityNotSupportedException
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
     * @throws ClientNotConnectedException
     * @throws ClientNotInitializedException
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
     * @throws ClientNotConnectedException
     * @throws ClientNotInitializedException
     * @throws ServerCapabilityNotSupportedException
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
     * Sets the minimum severity the server should emit via `logging/setLevel`.
     *
     * @throws ClientNotConnectedException
     * @throws ClientNotInitializedException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function setLoggingLevel(LoggingLevel $level): void
    {
        $this->sendRequest(
            new SetLevelRequest($this->mintRequestId(), new SetLevelRequestParams($level)),
            EmptyResult::class,
        );
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
     * @throws ClientNotConnectedException
     * @throws ClientNotInitializedException
     * @throws ServerCapabilityNotSupportedException
     * @throws TransportAlreadyClosedException
     */
    public function sendRequest(JsonRpcRequest $request, string $result): JsonRpcResultResponse
    {
        $transport = $this->transport;

        if (null === $transport) {
            throw new ClientNotConnectedException();
        }

        $method = $request::getMethod();

        if (! $this->initializationGate->allowsRequest($method)) {
            throw new ClientNotInitializedException($method);
        }

        $this->assertServerSupports($method);

        $future = $this->outboundRequests->register($request->id, $result);
        $transport->send($request);

        return $future->await();
    }

    /**
     * @throws ServerCapabilityNotSupportedException
     */
    private function assertServerSupports(string $method): void
    {
        $capabilities = $this->serverCapabilities;

        if (null === $capabilities) {
            // Before the handshake there are no negotiated capabilities to enforce.
            return;
        }

        $supported = match ($method) {
            ListToolsRequest::getMethod(), CallToolRequest::getMethod() => null !== $capabilities->tools,
            ListResourcesRequest::getMethod(),
            ListResourceTemplatesRequest::getMethod(),
            ReadResourceRequest::getMethod() => null !== $capabilities->resources,
            ListPromptsRequest::getMethod(), GetPromptRequest::getMethod() => null !== $capabilities->prompts,
            CompleteRequest::getMethod() => null !== $capabilities->completions,
            SetLevelRequest::getMethod() => null !== $capabilities->logging,
            default => true,
        };

        if (! $supported) {
            throw new ServerCapabilityNotSupportedException($method);
        }
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
