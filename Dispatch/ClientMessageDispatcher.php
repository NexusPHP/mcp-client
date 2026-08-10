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
use Nexus\Mcp\Client\ClientContext;
use Nexus\Mcp\Client\Exception\SubscriptionDeliveryDroppedException;
use Nexus\Mcp\Client\Subscription\SubscriptionRegistry;
use Nexus\Mcp\Core\Dispatch\LogThrottle;
use Nexus\Mcp\Core\Dispatch\MessageDispatcherInterface;
use Nexus\Mcp\Core\Dispatch\PendingCoroutines;
use Nexus\Mcp\Core\Dispatch\PendingInboundRequests;
use Nexus\Mcp\Core\Dispatch\PendingOutboundRequests;
use Nexus\Mcp\Core\Dispatch\RequestBoundSender;
use Nexus\Mcp\Core\Dispatch\ResponseSender;
use Nexus\Mcp\Core\Exception\AbstractJsonRpcProtocolException;
use Nexus\Mcp\Core\Exception\DuplicateInboundRequestIdException;
use Nexus\Mcp\Core\Exception\MethodMisroutedException;
use Nexus\Mcp\Core\Exception\MethodNotFoundException;
use Nexus\Mcp\Core\Exception\RemoteCallFailedException;
use Nexus\Mcp\Core\Exception\TransportAlreadyClosedException;
use Nexus\Mcp\Core\Handler\HandlerRegistry;
use Nexus\Mcp\Core\Handler\NotificationHandlerInterface;
use Nexus\Mcp\Core\Handler\RequestHandlerInterface;
use Nexus\Mcp\Core\JsonRpc\JsonRpcMessageParser;
use Nexus\Mcp\Core\JsonRpc\ResultResponseFactory;
use Nexus\Mcp\Core\JsonRpc\UnparsedResultEnvelope;
use Nexus\Mcp\Core\SafeDisplay;
use Nexus\Mcp\Core\Schema\Enum\SdkErrorCode;
use Nexus\Mcp\Core\Schema\Error\InternalError;
use Nexus\Mcp\Core\Schema\Error\UnknownProtocolError;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcErrorResponse;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcNotification;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcRequest;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcResultResponse;
use Nexus\Mcp\Core\Schema\Notification\CancelledNotification;
use Nexus\Mcp\Core\Schema\Notification\ProgressNotification;
use Nexus\Mcp\Core\Schema\NotificationParams\CancelledNotificationParams;
use Nexus\Mcp\Core\Schema\RequestId;
use Nexus\Mcp\Core\Schema\Result;
use Nexus\Mcp\Core\Transport\ReceiveContext;
use Nexus\Mcp\Core\Transport\TransportInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

use function Amp\async;

/**
 * Client-side per-envelope inbound dispatch.
 *
 * @internal
 */
final readonly class ClientMessageDispatcher implements MessageDispatcherInterface
{
    private const string OVERLOADED_MESSAGE = 'Client overloaded';

    private PendingCoroutines $coroutines;
    private ResponseSender $responseSender;
    private LogThrottle $shedInbound;

    /**
     * @param HandlerRegistry<RequestHandlerInterface<non-empty-string, Result, ClientContext>> $requestHandlers
     * @param HandlerRegistry<NotificationHandlerInterface<non-empty-string>>                   $notificationHandlers
     * @param null|int<1, max>                                                                  $maxInFlight          Inbound messages processed at once before further ones are shed, or null for no cap
     */
    public function __construct(
        private HandlerRegistry $requestHandlers,
        private HandlerRegistry $notificationHandlers,
        private PendingOutboundRequests $outboundRequests,
        private LoggerInterface $logger = new NullLogger(),
        private JsonRpcMessageParser $parser = new JsonRpcMessageParser(),
        private PendingInboundRequests $inboundRequests = new PendingInboundRequests(),
        private SubscriptionRegistry $subscriptions = new SubscriptionRegistry(),
        private ?int $maxInFlight = null,
    ) {
        $this->coroutines = new PendingCoroutines($this->logger);
        $this->responseSender = new ResponseSender($this->logger);
        $this->shedInbound = new LogThrottle();
    }

    #[\Override]
    public function flushPending(): void
    {
        $this->coroutines->flushPending();
    }

    #[\Override]
    public function cancelRequest(RequestId $id): void
    {
        $this->inboundRequests->cancel($id);
    }

    /**
     * @param array<string, mixed> $envelope
     */
    #[\Override]
    public function dispatch(array $envelope, TransportInterface $transport, ReceiveContext $context): void
    {
        if (\array_key_exists('result', $envelope) || \array_key_exists('error', $envelope)) {
            $this->dispatchResponseEnvelope($envelope);
        } else {
            $this->dispatchInboundEnvelope($envelope, $transport);
        }
    }

    private function isSaturated(): bool
    {
        return null !== $this->maxInFlight && $this->maxInFlight <= $this->coroutines->count();
    }

    /**
     * The cap exemption performs the cancel, so each request in flight admits at most one cancellation past the cap.
     *
     * @param JsonRpcNotification<non-empty-string> $notification
     * @param non-empty-string                      $method
     */
    private function relievesSaturation(JsonRpcNotification $notification, string $method): bool
    {
        if (CancelledNotification::getMethod() !== $method) {
            return false;
        }

        $params = $notification->params;
        \assert($params instanceof CancelledNotificationParams);

        return $this->inboundRequests->cancel($params->requestId);
    }

    /**
     * @param non-empty-string $method
     */
    private function reportShed(string $method): void
    {
        if (! $this->shedInbound->admits()) {
            return;
        }

        $this->logger->warning(
            'Shed {count} inbound message(s) so far. The client is at its in-flight dispatch cap.',
            ['count' => $this->shedInbound->count(), 'method' => $method],
        );
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
                ['exception' => $e],
            );

            // §4.1 splits notification from request on the envelope's id, not on the method it names, so an id-less one goes unanswered.
            if ($isNotification) {
                return;
            }

            $this->responseSender->send($transport, ResponseSender::buildErrorResponse($e, null), 'misrouted');

            return;
        } catch (AbstractJsonRpcProtocolException $e) {
            if ($isNotification) {
                $this->logger->info(
                    'Dropping malformed notification (JSON-RPC 2.0 §4.1 forbids responses to notifications).',
                    ['exception' => $e],
                );

                return;
            }

            $this->responseSender->send($transport, ResponseSender::buildErrorResponse($e, null), 'parse-error');

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
                ['exception' => $e],
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
                ['error' => SafeDisplay::sanitiseCause($response->error->message)],
            );

            return;
        }

        $exception = new RemoteCallFailedException($response->error);

        if (! $this->outboundRequests->reject($response->id, $exception)) {
            $this->logger->warning(
                'Discarding orphan error response for unknown request id.',
                ['id' => SafeDisplay::sanitiseId($response->id->id), 'error' => SafeDisplay::sanitiseCause($response->error->message)],
            );
        }
    }

    /**
     * @param array<string, mixed> $envelope
     */
    private function dispatchSuccessResponse(array $envelope, UnparsedResultEnvelope $peeked): void
    {
        $responseClass = $this->outboundRequests->resolveResponseClass($peeked->id);

        if (null !== $responseClass) {
            try {
                $response = $this->parser->parse($envelope, $responseClass);
                \assert($response instanceof JsonRpcResultResponse);
            } catch (\Throwable $e) {
                $this->outboundRequests->reject($peeked->id, $e);

                return;
            }

            $this->outboundRequests->resolve($peeked->id, $response);

            return;
        }

        $this->logger->warning(
            'Discarding orphan success response for unknown request id.',
            ['id' => SafeDisplay::sanitiseId($peeked->id->id)],
        );
    }

    /**
     * @param JsonRpcRequest<non-empty-string> $request
     */
    private function dispatchRequest(JsonRpcRequest $request, TransportInterface $transport): void
    {
        $method = $request::getMethod();

        if ($this->isSaturated()) {
            $this->reportShed($method);
            $this->responseSender->send($transport, new JsonRpcErrorResponse(
                id: $request->id,
                error: new UnknownProtocolError(
                    code: SdkErrorCode::Overloaded->value,
                    message: self::OVERLOADED_MESSAGE,
                ),
            ), $method);

            return;
        }

        $cancellation = $this->inboundRequests->claim($request->id);

        if (null === $cancellation) {
            $exception = new DuplicateInboundRequestIdException($request->id);
            $this->responseSender->send($transport, ResponseSender::buildErrorResponse($exception, $request->id), $method);

            return;
        }

        $this->coroutines->track(async(function () use ($request, $transport, $method, $cancellation): void {
            try {
                $sender = new RequestBoundSender($transport, $request->id);

                $context = new ClientContext(
                    $request->id,
                    $cancellation,
                    null,
                    $sender,
                );

                try {
                    $handler = $this->requestHandlers->get($method)
                        ?? throw new MethodNotFoundException($method, $request->id);
                    $result = $handler->handle($request, $context);
                    $response = ResultResponseFactory::wrap($request, $result);
                } catch (TransportAlreadyClosedException $e) {
                    $this->responseSender->logSkippedDelivery($method, $e);

                    return;
                } catch (AbstractJsonRpcProtocolException $e) {
                    $this->sendUnlessCancelled($cancellation, $transport, ResponseSender::buildErrorResponse($e, $request->id), $method);

                    return;
                } catch (\Throwable $e) {
                    if ($cancellation->isRequested()) {
                        $this->logger->debug(
                            'Dropping the response to a request whose handler the cancellation interrupted.',
                            ['method' => $method],
                        );

                        return;
                    }

                    $this->logger->error(
                        'Uncaught request handler exception.',
                        ['method' => $method, 'exception' => $e],
                    );
                    $this->responseSender->send($transport, new JsonRpcErrorResponse(
                        id: $request->id,
                        error: new InternalError(message: InternalError::DEFAULT_MESSAGE),
                    ), $method);

                    return;
                }

                $this->sendUnlessCancelled($cancellation, $transport, $response, $method);
            } finally {
                $this->inboundRequests->release($request->id);
            }
        }));
    }

    /**
     * @param non-empty-string $method
     */
    private function sendUnlessCancelled(
        Cancellation $cancellation,
        TransportInterface $transport,
        JsonRpcErrorResponse|JsonRpcResultResponse $response,
        string $method,
    ): void {
        if ($cancellation->isRequested()) {
            $this->logger->debug('Dropping the response to a cancelled request.', ['method' => $method]);

            return;
        }

        $this->responseSender->send($transport, $response, $method);
    }

    /**
     * @param JsonRpcNotification<non-empty-string> $notification
     */
    private function dispatchNotification(JsonRpcNotification $notification): void
    {
        $method = $notification::getMethod();
        $subscriptionId = $notification->params->meta->subscriptionId;
        $subscription = null === $subscriptionId || ProgressNotification::getMethod() === $method
            ? null
            : $this->subscriptions->get($subscriptionId);

        if (null !== $subscription) {
            if ($this->isSaturated()) {
                // A lost delivery is undetectable from later ones, so the stream ends rather than staying silently stale.
                $this->subscriptions->forget($subscription->subscriptionId);
                $subscription->outcome->error(new SubscriptionDeliveryDroppedException($subscription->subscriptionId));
                $this->logger->warning(
                    'Ended subscription {subscriptionId} after shedding one of its deliveries at the in-flight dispatch cap.',
                    ['subscriptionId' => $subscription->subscriptionId->id, 'method' => $method],
                );

                return;
            }

            $listener = $subscription->onNotification;
            $this->coroutines->track(async(function () use ($listener, $notification, $method): void {
                try {
                    $listener($notification);
                } catch (\Throwable $e) {
                    $this->logger->error(
                        'Uncaught subscription listener exception.',
                        ['method' => $method, 'exception' => $e],
                    );
                }
            }));

            return;
        }

        $handler = $this->notificationHandlers->get($method);

        if (null === $handler) {
            return;
        }

        if ($this->isSaturated() && ! $this->relievesSaturation($notification, $method)) {
            $this->reportShed($method);

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
}
