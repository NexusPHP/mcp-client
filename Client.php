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

use Nexus\Mcp\Core\Dispatch\MessageDispatcherInterface;
use Nexus\Mcp\Core\Dispatch\PendingOutboundRequests;
use Nexus\Mcp\Core\Exception\TransportAlreadyClosedException;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcRequest;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcResultResponse;
use Nexus\Mcp\Core\Schema\Result;
use Nexus\Mcp\Core\Transport\TransportInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Thin shell that drives a single transport's client-side lifecycle. `connect()`
 * attaches the listeners and starts the transport. `sendRequest()` registers an
 * outbound id, transmits, and awaits the correlated response.
 */
final class Client
{
    private ?TransportInterface $transport = null;

    public function __construct(
        private readonly MessageDispatcherInterface $dispatcher,
        private readonly PendingOutboundRequests $outboundRequests,
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

        $future = $this->outboundRequests->register($request->id, $result);
        $this->transport->send($request);

        return $future->await();
    }
}
