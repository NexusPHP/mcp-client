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

namespace Nexus\Mcp\Client\Transport;

use Amp\ByteStream\BufferException;
use Amp\Cancellation;
use Amp\CancelledException;
use Amp\CompositeCancellation;
use Amp\DeferredCancellation;
use Amp\DeferredFuture;
use Amp\Http\Client\DelegateHttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
use Nexus\Assert\Assert;
use Nexus\Mcp\Core\Dispatch\PendingCoroutines;
use Nexus\Mcp\Core\Exception\OutboundRequestFailedException;
use Nexus\Mcp\Core\Exception\ResponseTooLargeException;
use Nexus\Mcp\Core\Exception\TransportAlreadyClosedException;
use Nexus\Mcp\Core\Exception\TransportAlreadyStartedException;
use Nexus\Mcp\Core\Exception\TransportNotStartedException;
use Nexus\Mcp\Core\Exception\UnexpectedHttpStatusException;
use Nexus\Mcp\Core\Http\HttpStatus;
use Nexus\Mcp\Core\Http\SseFrameParser;
use Nexus\Mcp\Core\Http\StandardHeaders;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcMessage;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcRequest;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcResponse;
use Nexus\Mcp\Core\Schema\RequestId;
use Nexus\Mcp\Core\Transport\AbortableTransportInterface;
use Nexus\Mcp\Core\Transport\ListenerHandleInterface;
use Nexus\Mcp\Core\Transport\ParameterHeaderMirroringInterface;
use Nexus\Mcp\Core\Transport\ReceiveContext;
use Nexus\Mcp\Core\Transport\SendContext;
use Nexus\Mcp\Core\Transport\TransportEvents;
use Nexus\Mcp\Core\Transport\TransportState;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

use function Amp\async;

/**
 * Streamable HTTP MCP client transport, one POST per outbound message.
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
 */
final class StreamableHttpClientTransport implements AbortableTransportInterface, ParameterHeaderMirroringInterface
{
    public const int DEFAULT_MAX_RESPONSE_BYTES = SseFrameParser::DEFAULT_MAX_FRAME_BYTES;

    private readonly DelegateHttpClient $client;
    private readonly TransportEvents $events;
    private readonly PendingCoroutines $exchanges;
    private readonly StandardHeaders $standardHeaders;
    private TransportState $state = TransportState::Idle;

    /**
     * True from the first `close()` on, which `state` cannot signal as it stays `Running` across the
     * drain so a listener may still send.
     */
    private bool $closing = false;

    /**
     * @var null|\Fiber<mixed, mixed, mixed, mixed> The close owner, `null` while no close is in progress or when {main} owns it
     */
    private ?\Fiber $closingFiber = null;

    /**
     * @var null|DeferredFuture<null>
     */
    private ?DeferredFuture $closeCompletion = null;

    /**
     * @var array<int, \Fiber<mixed, mixed, mixed, mixed>> The in-flight exchange fibers, close participants while the flush drains them
     */
    private array $exchangeFibers = [];

    private ?DeferredCancellation $lifetime = null;

    /**
     * @var array<non-empty-string, DeferredCancellation>
     */
    private array $inFlight = [];

    /**
     * @param non-empty-string        $endpoint         Absolute URL of the server's MCP endpoint
     * @param null|DelegateHttpClient $client           Defaults to the amphp default client
     * @param float                   $readTimeout      Seconds a response may stall before the exchange is abandoned.
     *                                                  It must exceed the server's SSE keep-alive interval, or a quiet
     *                                                  long-lived stream is torn down between keep-alives.
     * @param int                     $maxResponseBytes Bytes a buffered body, or one SSE frame, may occupy
     */
    public function __construct(
        private readonly string $endpoint,
        ?DelegateHttpClient $client = null,
        private readonly LoggerInterface $logger = new NullLogger(),
        private readonly float $readTimeout = 30.0,
        private readonly int $maxResponseBytes = self::DEFAULT_MAX_RESPONSE_BYTES,
    ) {
        Assert::that($endpoint)->isNonEmptyString('Streamable HTTP client endpoint must be a non-empty string.');

        if ($readTimeout <= 0.0) {
            throw new \InvalidArgumentException(\sprintf('Streamable HTTP client read timeout must be positive, %s given.', $readTimeout));
        }

        Assert::that($maxResponseBytes)->isPositiveInt(
            'Streamable HTTP client maximum response size must be a positive integer, {value} given.',
        );

        $this->client = $client ?? HttpClientBuilder::buildDefault();
        $this->events = TransportEvents::create($logger, 'Streamable HTTP client');
        $this->exchanges = new PendingCoroutines();
        $this->standardHeaders = new StandardHeaders();
    }

    #[\Override]
    public function start(): void
    {
        match ($this->state) {
            TransportState::Running => throw new TransportAlreadyStartedException(transport: self::class),
            TransportState::Closed => throw new TransportAlreadyClosedException(operation: 'start'),
            TransportState::Idle => null,
        };

        $this->state = TransportState::Running;
        $this->lifetime = new DeferredCancellation();
        $this->logger->info('Streamable HTTP client transport started. Endpoint: {endpoint}.', ['endpoint' => $this->endpoint]);
    }

    #[\Override]
    public function send(JsonRpcMessage $message, ?SendContext $context = null): void
    {
        match ($this->state) {
            TransportState::Idle => throw new TransportNotStartedException(operation: 'send'),
            TransportState::Closed => throw new TransportAlreadyClosedException(operation: 'send'),
            TransportState::Running => null,
        };

        if ($message instanceof JsonRpcResponse) {
            $this->logger->warning('Streamable HTTP client transport dropped an outbound response, which a client must not send.');

            return;
        }

        $headers = $context->headers ?? [];
        $requestId = $message instanceof JsonRpcRequest ? $message->id : null;

        \assert($this->lifetime instanceof DeferredCancellation);
        $cancellation = $this->lifetime->getCancellation();
        $held = null;

        if (null !== $requestId) {
            $abort = new DeferredCancellation();
            $this->inFlight[$this->buildKey($requestId)] = $abort;
            $held = $abort;

            $cancellation = new CompositeCancellation($cancellation, $abort->getCancellation());
        }

        $this->exchanges->track(async(function () use ($message, $headers, $cancellation, $requestId, $held): void {
            $fiber = \Fiber::getCurrent();
            \assert($fiber instanceof \Fiber);
            $this->exchangeFibers[spl_object_id($fiber)] = $fiber;

            try {
                $this->exchange($message, $headers, $cancellation);
            } catch (CancelledException) {
                // A close or an abort is not a fault, and the protocol layer signalled both.
            } catch (\Throwable $e) {
                try {
                    $this->events->emitError(null === $requestId ? $e : new OutboundRequestFailedException($requestId, $e));
                } catch (\Throwable) {
                    // A listener that throws must not cost this exchange its release, and the error channel just failed anyway.
                }
            }

            if (null !== $requestId) {
                $key = $this->buildKey($requestId);

                if (($this->inFlight[$key] ?? null) === $held) {
                    unset($this->inFlight[$key]);
                }
            }

            unset($this->exchangeFibers[spl_object_id($fiber)]);
        }));
    }

    #[\Override]
    public function close(): void
    {
        if ($this->closing) {
            if ($this->participatesInClose()) {
                return;
            }

            $this->closeCompletion?->getFuture()->await();

            return;
        }

        $this->closing = true;
        $this->closingFiber = \Fiber::getCurrent();

        /** @var DeferredFuture<null> $completion */
        $completion = new DeferredFuture();
        $this->closeCompletion = $completion;

        try {
            $this->events->emitDrain();
        } finally {
            $this->state = TransportState::Closed;

            try {
                $this->lifetime?->cancel();
                $this->exchanges->flushPending();
                $this->events->emitClose();
                $this->logger->info('Streamable HTTP client transport closed.');
            } finally {
                $completion->complete();
            }
        }
    }

    #[\Override]
    public function onMessage(\Closure $listener): ListenerHandleInterface
    {
        return $this->events->onMessage($listener);
    }

    #[\Override]
    public function onError(\Closure $listener): ListenerHandleInterface
    {
        return $this->events->onError($listener);
    }

    #[\Override]
    public function onDrain(\Closure $listener): ListenerHandleInterface
    {
        return $this->events->onDrain($listener);
    }

    #[\Override]
    public function onClose(\Closure $listener): ListenerHandleInterface
    {
        return $this->events->onClose($listener);
    }

    #[\Override]
    public function abort(RequestId $id): void
    {
        ($this->inFlight[$this->buildKey($id)] ?? null)?->cancel();
    }

    /**
     * Whether the current fiber is one the in-progress close is itself running or draining.
     */
    private function participatesInClose(): bool
    {
        $current = \Fiber::getCurrent();

        return $current === $this->closingFiber || \in_array($current, $this->exchangeFibers, true);
    }

    /**
     * @return non-empty-string
     */
    private function buildKey(RequestId $id): string
    {
        return \sprintf('"id":%s', var_export($id->id, true));
    }

    /**
     * @param array<non-empty-string, string> $headers Mirrored parameter headers the protocol layer computed
     */
    private function exchange(JsonRpcMessage $message, array $headers, Cancellation $cancellation): void
    {
        $response = $this->client->request($this->buildRequest($message, $headers), $cancellation);
        $status = $response->getStatus();

        if (HttpStatus::Accepted->value === $status) {
            if ($message instanceof JsonRpcRequest) {
                throw new UnexpectedHttpStatusException($status);
            }

            return;
        }

        if (HttpStatus::Ok->value !== $status) {
            if (! $message instanceof JsonRpcRequest || $this->isEventStream($response)) {
                throw new UnexpectedHttpStatusException($status);
            }

            try {
                $payload = $this->buffer($response, $cancellation);
            } catch (ResponseTooLargeException) {
                throw new UnexpectedHttpStatusException($status);
            }

            $decoded = json_decode($payload, true);

            if (\is_array($decoded)
                && JsonRpcMessage::JSONRPC_VERSION === ($decoded['jsonrpc'] ?? null)
                && $message->id->id === ($decoded['id'] ?? null)
                && ! \array_key_exists('method', $decoded)
                && (\array_key_exists('result', $decoded) || \array_key_exists('error', $decoded))
            ) {
                Assert::that($decoded)->isMap('Streamable HTTP client received a response envelope that is not a string-keyed object.');
                $this->events->emitMessage($decoded, new ReceiveContext());

                return;
            }

            throw new UnexpectedHttpStatusException($status, $payload);
        }

        if ($this->isEventStream($response)) {
            $this->readStream($response, $cancellation);

            return;
        }

        $this->events->emitMessage($this->decode($this->buffer($response, $cancellation)), new ReceiveContext());
    }

    /**
     * @throws ResponseTooLargeException
     */
    private function buffer(Response $response, Cancellation $cancellation): string
    {
        try {
            return $response->getBody()->buffer($cancellation, $this->maxResponseBytes);
        } catch (BufferException $e) {
            throw new ResponseTooLargeException($this->maxResponseBytes, $e);
        }
    }

    /**
     * @param array<non-empty-string, string> $headers
     */
    private function buildRequest(JsonRpcMessage $message, array $headers): Request
    {
        $request = new Request($this->endpoint, 'POST', json_encode($message, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE));

        $request->setHeaders([
            'Content-Type' => 'application/json',
            'Accept' => 'application/json, text/event-stream',
            ...$headers,
            ...$this->standardHeaders->build($message->toArray()),
        ]);

        $request->setTransferTimeout(0.0);
        $request->setInactivityTimeout($this->readTimeout);

        return $request;
    }

    private function readStream(Response $response, Cancellation $cancellation): void
    {
        $parser = new SseFrameParser($this->maxResponseBytes);
        $body = $response->getBody();
        $chunk = $body->read($cancellation);

        while (null !== $chunk) {
            foreach ($parser->feed($chunk) as $frame) {
                try {
                    $envelope = $this->decode($frame->data);
                } catch (\InvalidArgumentException|\JsonException $e) {
                    $this->events->emitError($e);

                    continue;
                }

                $this->events->emitMessage($envelope, new ReceiveContext());
            }

            $chunk = $body->read($cancellation);
        }
    }

    /**
     * @return array<string, mixed>
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function decode(string $payload): array
    {
        $envelope = json_decode($payload, associative: true, flags: \JSON_THROW_ON_ERROR);
        Assert::that($envelope)->isMap('Streamable HTTP client received a payload that is not a JSON-RPC envelope.');

        return $envelope;
    }

    private function isEventStream(Response $response): bool
    {
        return str_starts_with(strtolower($response->getHeader('Content-Type') ?? ''), 'text/event-stream');
    }
}
