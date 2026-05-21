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

namespace Nexus\Mcp\Client\Dispatch;

use Amp\Cancellation;
use Amp\NullCancellation;
use Nexus\Assert\Assert;
use Nexus\Mcp\Client\ClientContext;
use Nexus\Mcp\Core\Dispatch\MessageDispatcherInterface;
use Nexus\Mcp\Core\Dispatch\PendingCoroutines;
use Nexus\Mcp\Core\Dispatch\PendingInboundRequests;
use Nexus\Mcp\Core\Dispatch\PendingOutboundRequests;
use Nexus\Mcp\Core\Dispatch\RequestBoundSender;
use Nexus\Mcp\Core\Exception\AbstractJsonRpcProtocolException;
use Nexus\Mcp\Core\Exception\DuplicateInboundRequestIdException;
use Nexus\Mcp\Core\Exception\MethodMisroutedException;
use Nexus\Mcp\Core\Exception\MethodNotFoundException;
use Nexus\Mcp\Core\Exception\RemoteCallFailedException;
use Nexus\Mcp\Core\Exception\TransportAlreadyClosedException;
use Nexus\Mcp\Core\Handler\HandlerRegistry;
use Nexus\Mcp\Core\Handler\NotificationHandlerInterface;
use Nexus\Mcp\Core\Handler\RequestHandlerInterface;
use Nexus\Mcp\Core\JsonRpc\ErrorFactory;
use Nexus\Mcp\Core\JsonRpc\JsonRpcMessageParser;
use Nexus\Mcp\Core\JsonRpc\UnparsedResultEnvelope;
use Nexus\Mcp\Core\Schema\Error\InternalError;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcErrorResponse;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcMessage;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcNotification;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcRequest;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcResultResponse;
use Nexus\Mcp\Core\Schema\RequestId;
use Nexus\Mcp\Core\Schema\Result;
use Nexus\Mcp\Core\Transport\TransportInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

use function Amp\async;

/**
 * Client-side per-envelope inbound dispatch. Parses, classifies, and routes:
 * success/error response envelopes to `PendingOutboundRequests` for correlation,
 * peer-initiated requests to registered handlers, and notifications to their
 * handlers.
 *
 * @internal
 */
final readonly class ClientMessageDispatcher implements MessageDispatcherInterface
{
    private PendingCoroutines $coroutines;
    private PendingInboundRequests $inboundRequests;

    /**
     * @param HandlerRegistry<RequestHandlerInterface<non-empty-string, Result, ClientContext>> $requestHandlers
     * @param HandlerRegistry<NotificationHandlerInterface<non-empty-string>>                   $notificationHandlers
     */
    public function __construct(
        private HandlerRegistry $requestHandlers,
        private HandlerRegistry $notificationHandlers,
        private PendingOutboundRequests $outboundRequests,
        private LoggerInterface $logger = new NullLogger(),
        private JsonRpcMessageParser $parser = new JsonRpcMessageParser(),
        private Cancellation $cancellation = new NullCancellation(),
    ) {
        $this->coroutines = new PendingCoroutines();
        $this->inboundRequests = new PendingInboundRequests();
    }

    #[\Override]
    public function flushPending(): void
    {
        $this->coroutines->flushPending();
    }

    /**
     * @param array<string, mixed> $envelope
     */
    #[\Override]
    public function dispatch(array $envelope, TransportInterface $transport): void
    {
        if (\array_key_exists('result', $envelope) || \array_key_exists('error', $envelope)) {
            $this->dispatchResponseEnvelope($envelope);
        } else {
            $this->dispatchInboundEnvelope($envelope, $transport);
        }
    }

    /**
     * @param array<string, mixed> $envelope
     */
    private function dispatchInboundEnvelope(array $envelope, TransportInterface $transport): void
    {
        $isNotification = ! \array_key_exists('id', $envelope);

        try {
            $message = $this->parser->parse($envelope);
        } catch (MethodMisroutedException $e) {
            $this->logger->warning(
                'Rejecting envelope whose method was sent under the wrong JSON-RPC shape.',
                ['envelope' => $envelope, 'exception' => $e],
            );

            if (! $isNotification) {
                return;
            }

            $this->sendResponse($transport, self::toErrorResponse($e, null), 'misrouted');

            return;
        } catch (AbstractJsonRpcProtocolException $e) {
            if ($isNotification) {
                $this->logger->info(
                    'Dropping malformed notification (JSON-RPC 2.0 §4.1 forbids responses to notifications).',
                    ['envelope' => $envelope, 'exception' => $e],
                );

                return;
            }

            $this->sendResponse($transport, self::toErrorResponse($e, null), 'parse-error');

            return;
        }

        if ($message instanceof JsonRpcRequest) {
            $this->dispatchRequest($message, $transport);
        } elseif ($message instanceof JsonRpcNotification) {
            $this->dispatchNotification($message);
        }
    }

    /**
     * @param array<string, mixed> $envelope
     */
    private function dispatchResponseEnvelope(array $envelope): void
    {
        try {
            $peeked = $this->parser->parse($envelope);
        } catch (\Throwable $e) {
            $this->logger->warning(
                'Discarding malformed response envelope from peer.',
                ['envelope' => $envelope, 'exception' => $e],
            );

            return;
        }

        if ($peeked instanceof JsonRpcErrorResponse) {
            $this->dispatchErrorResponse($peeked);
        } elseif ($peeked instanceof UnparsedResultEnvelope) {
            $this->dispatchSuccessResponse($envelope, $peeked);
        }
    }

    private function dispatchErrorResponse(JsonRpcErrorResponse $response): void
    {
        if (null === $response->id) {
            $this->logger->warning(
                'Discarding error response with null id. No correlation to an outbound request is possible.',
                ['error' => $response->error->message],
            );

            return;
        }

        $exception = new RemoteCallFailedException($response->error);

        if (! $this->outboundRequests->reject($response->id, $exception)) {
            $this->logger->warning(
                'Discarding orphan error response for unknown request id.',
                ['id' => $response->id->id, 'error' => $response->error->message],
            );
        }
    }

    /**
     * @param array<string, mixed> $envelope
     */
    private function dispatchSuccessResponse(array $envelope, UnparsedResultEnvelope $peeked): void
    {
        $resultClass = $this->outboundRequests->resultClassFor($peeked->id);

        if (null === $resultClass) {
            $this->logger->warning(
                'Discarding orphan success response for unknown request id.',
                ['id' => $peeked->id->id],
            );

            return;
        }

        try {
            $response = $this->parser->parse($envelope, $resultClass);
        } catch (\Throwable $e) {
            $this->outboundRequests->reject($peeked->id, $e);

            return;
        }

        Assert::that($response)->isInstanceOf(JsonRpcResultResponse::class);

        $this->outboundRequests->resolve($peeked->id, $response);
    }

    /**
     * @param JsonRpcRequest<non-empty-string> $request
     */
    private function dispatchRequest(JsonRpcRequest $request, TransportInterface $transport): void
    {
        $method = $request::method();

        if (! $this->inboundRequests->claim($request->id)) {
            $exception = new DuplicateInboundRequestIdException($request->id);
            $this->sendResponse($transport, self::toErrorResponse($exception, $request->id), $method);

            return;
        }

        $this->coroutines->track(async(function () use ($request, $transport, $method): void {
            try {
                $sender = new RequestBoundSender($transport, $request->id);
                $context = new ClientContext(
                    $request->id,
                    $this->cancellation,
                    $request->params->meta,
                    $transport->sessionId(),
                    $sender,
                );

                try {
                    $handler = $this->requestHandlers->get($method)
                        ?? throw new MethodNotFoundException($method, $request->id);
                    $result = $handler->handle($request, $context);
                } catch (TransportAlreadyClosedException $e) {
                    $this->logSkippedDelivery($method, $e);

                    return;
                } catch (AbstractJsonRpcProtocolException $e) {
                    $this->sendResponse($transport, self::toErrorResponse($e, $request->id), $method);

                    return;
                } catch (\Throwable $e) {
                    $this->logger->error(
                        'Uncaught request handler exception.',
                        ['method' => $method, 'exception' => $e],
                    );
                    $this->sendResponse($transport, new JsonRpcErrorResponse(
                        $request->id,
                        new InternalError(),
                    ), $method);

                    return;
                }

                $this->sendResponse($transport, new JsonRpcResultResponse($request->id, $result), $method);
            } finally {
                $this->inboundRequests->release($request->id);
            }
        }));
    }

    /**
     * @param JsonRpcNotification<non-empty-string> $notification
     */
    private function dispatchNotification(JsonRpcNotification $notification): void
    {
        $method = $notification::method();
        $handler = $this->notificationHandlers->get($method);

        if (null === $handler) {
            return;
        }

        $this->coroutines->track(async(function () use ($handler, $notification, $method): void {
            try {
                $handler->handle($notification);
            } catch (\Throwable $e) {
                $this->logger->error(
                    'Uncaught notification handler exception.',
                    ['method' => $method, 'exception' => $e],
                );
            }
        }));
    }

    private function sendResponse(TransportInterface $transport, JsonRpcMessage $message, string $method): void
    {
        try {
            $transport->send($message);
        } catch (TransportAlreadyClosedException $e) {
            $this->logSkippedDelivery($method, $e);
        } catch (\Throwable $e) {
            $this->logger->error(
                'Failed to deliver response to transport.',
                ['method' => $method, 'exception' => $e],
            );
        }
    }

    private function logSkippedDelivery(string $method, TransportAlreadyClosedException $exception): void
    {
        $this->logger->info(
            'Skipping response delivery. Transport is closed.',
            ['method' => $method, 'exception' => $exception],
        );
    }

    private static function toErrorResponse(
        AbstractJsonRpcProtocolException $exception,
        ?RequestId $fallbackId,
    ): JsonRpcErrorResponse {
        return new JsonRpcErrorResponse(
            $exception->requestId ?? $fallbackId,
            ErrorFactory::create($exception::errorCode(), $exception->getMessage()),
        );
    }
}
