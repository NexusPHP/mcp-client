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
use Nexus\Mcp\Core\Dispatch\MessageDispatcherInterface;
use Nexus\Mcp\Core\Dispatch\PendingOutboundRequests;
use Nexus\Mcp\Core\Exception\TransportAlreadyClosedException;
use Nexus\Mcp\Core\Schema\ClientCapabilities;
use Nexus\Mcp\Core\Schema\Implementation;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcRequest;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcResultResponse;
use Nexus\Mcp\Core\Schema\Notification\InitializedNotification;
use Nexus\Mcp\Core\Schema\ProtocolVersion;
use Nexus\Mcp\Core\Schema\Request\InitializeRequest;
use Nexus\Mcp\Core\Schema\RequestId;
use Nexus\Mcp\Core\Schema\RequestParams\InitializeRequestParams;
use Nexus\Mcp\Core\Schema\Result;
use Nexus\Mcp\Core\Schema\Result\InitializeResult;
use Nexus\Mcp\Core\Transport\TransportInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Thin shell that drives a single transport's client-side lifecycle. `connect()`
 * attaches the listeners and starts the transport. `initialize()` runs the
 * handshake. `sendRequest()` registers an outbound id, transmits, and awaits
 * the correlated response.
 */
final class Client
{
    private ?TransportInterface $transport = null;

    /**
     * @param \Closure(): (int|non-empty-string) $requestIdFactory
     */
    public function __construct(
        private readonly Implementation $clientInfo,
        private readonly MessageDispatcherInterface $dispatcher,
        private readonly PendingOutboundRequests $outboundRequests,
        private readonly ClientInitializationGate $initializationGate,
        private readonly \Closure $requestIdFactory,
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

        $this->logger->info(
            'Starting MCP client with {transport} client transport.',
            ['transport' => $transport->label()],
        );

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
            Assert::that($result)->isInstanceOf(InitializeResult::class);

            return $result;
        } catch (\Throwable $e) {
            $this->initializationGate->revertInitializeInFlight();

            throw $e;
        }
    }

    /**
     * Sends an outbound JSON-RPC request and awaits the correlated response.
     *
     * @param JsonRpcRequest<non-empty-string> $request
     * @param class-string<Result>             $result
     *
     * @return JsonRpcResultResponse<Result>
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
}
