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
use Amp\CancelledException;
use Amp\DeferredCancellation;
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
use Nexus\Mcp\Core\Http\HttpStatus;
use Nexus\Mcp\Core\Http\SseFrameParser;
use Nexus\Mcp\Core\Http\StandardHeaders;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcMessage;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcRequest;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcResponse;
use Nexus\Mcp\Core\Transport\ParameterHeaderMirroringInterface;
use Nexus\Mcp\Core\Transport\ReceiveContext;
use Nexus\Mcp\Core\Transport\SendContext;
use Nexus\Mcp\Core\Transport\SubscriptionInterface;
use Nexus\Mcp\Core\Transport\TransportEvents;
use Nexus\Mcp\Core\Transport\TransportState;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

use function Amp\async;

/**
 * Streamable HTTP MCP client transport. Every outbound message is its own POST to the MCP endpoint, and the
 * response, a single JSON object or a request-scoped SSE stream, is emitted back as inbound envelopes.
 *
 * @see https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http
 */
final class StreamableHttpClientTransport implements ParameterHeaderMirroringInterface
{
    /**
     * Bytes a single response may occupy before it is abandoned.
     */
    public const int DEFAULT_MAX_RESPONSE_BYTES = SseFrameParser::DEFAULT_MAX_FRAME_BYTES;

    private const string LABEL = 'Streamable HTTP client';
    private const string ACCEPT = 'application/json, text/event-stream';

    private readonly DelegateHttpClient $client;
    private readonly TransportEvents $events;
    private readonly PendingCoroutines $exchanges;
    private TransportState $state = TransportState::Idle;
    private ?DeferredCancellation $lifetime = null;

    /**
     * @param non-empty-string    $endpoint         Absolute URL of the server's MCP endpoint
     * @param ?DelegateHttpClient $client           Defaults to the amphp default client
     * @param float               $readTimeout      Seconds a response may stall before the exchange is abandoned.
     *                                              It must exceed the server's SSE keep-alive interval, or a quiet
     *                                              long-lived stream is torn down between keep-alives.
     * @param int                 $maxResponseBytes Bytes a buffered body, or one SSE frame, may occupy
     */
    public function __construct(
        private readonly string $endpoint,
        ?DelegateHttpClient $client = null,
        private readonly LoggerInterface $logger = new NullLogger(),
        private readonly float $readTimeout = 30.0,
        private readonly int $maxResponseBytes = self::DEFAULT_MAX_RESPONSE_BYTES,
    ) {
        Assert::that($endpoint)->isNonEmptyString(\sprintf('%s endpoint must be a non-empty string.', self::LABEL));

        if ($readTimeout <= 0.0) {
            throw new \InvalidArgumentException(\sprintf('%s read timeout must be positive, %s given.', self::LABEL, $readTimeout));
        }

        Assert::that($maxResponseBytes)->isPositiveInt(
            \sprintf('%s maximum response size must be a positive integer, {value} given.', self::LABEL),
        );

        $this->client = $client ?? HttpClientBuilder::buildDefault();
        $this->events = new TransportEvents();
        $this->exchanges = new PendingCoroutines();
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
        $this->logger->info('{label} transport started. Endpoint: {endpoint}.', ['label' => self::LABEL, 'endpoint' => $this->endpoint]);
    }

    #[\Override]
    public function send(JsonRpcMessage $message, ?SendContext $context = null): void
    {
        $lifetime = match ($this->state) {
            TransportState::Idle => throw new TransportNotStartedException(operation: 'send'),
            TransportState::Closed => throw new TransportAlreadyClosedException(operation: 'send'),
            TransportState::Running => $this->lifetime,
        };
        \assert($lifetime instanceof DeferredCancellation);

        if ($message instanceof JsonRpcResponse) {
            // A POST body must be a request or a notification: the spec forbids a client from sending
            // JSON-RPC responses at all, so there is no legal envelope to POST here.
            $this->logger->warning('{label} transport dropped an outbound response, which a client must not send.', ['label' => self::LABEL]);

            return;
        }

        \assert(method_exists($message, 'toArray'));
        $envelope = $message->toArray();
        Assert::that($envelope)->isMap(\sprintf('%s can only send a string-keyed envelope.', self::LABEL));

        $headers = $context->headers ?? [];

        // Only a request has a caller awaiting a response, so only a request names one to fail.
        $requestId = $message instanceof JsonRpcRequest ? $message->id : null;

        // The POST runs detached so a caller awaiting the correlated response is not the thing driving it.
        $this->exchanges->track(async(function () use ($envelope, $headers, $lifetime, $requestId): void {
            try {
                $this->exchange($envelope, $headers, $lifetime);
            } catch (CancelledException) {
                // The transport closed while this exchange was in flight. Shutdown is not a fault, and the
                // protocol layer already learns of it from the close signal.
            } catch (\Throwable $e) {
                $this->events->emitError(null === $requestId ? $e : new OutboundRequestFailedException($requestId, $e));
            }
        }));
    }

    #[\Override]
    public function close(): void
    {
        if (TransportState::Closed === $this->state) {
            return;
        }

        // Draining runs before the state flips so a listener still settling an exchange can send its last
        // message. Marking the transport closed first would answer that send with a closed-transport throw.
        try {
            $this->events->emitDrain();
        } finally {
            $this->state = TransportState::Closed;

            // Closing the response stream is itself the cancellation signal, so shutdown aborts the in-flight
            // POSTs. Awaiting them first would hang on a `subscriptions/listen` stream, which never ends.
            $this->lifetime?->cancel();
            $this->lifetime = null;
            $this->exchanges->flushPending();
            $this->events->emitClose();
        }
    }

    #[\Override]
    public function onMessage(\Closure $listener): SubscriptionInterface
    {
        return $this->events->onMessage($listener);
    }

    #[\Override]
    public function onError(\Closure $listener): SubscriptionInterface
    {
        return $this->events->onError($listener);
    }

    #[\Override]
    public function onDrain(\Closure $listener): SubscriptionInterface
    {
        return $this->events->onDrain($listener);
    }

    #[\Override]
    public function onClose(\Closure $listener): SubscriptionInterface
    {
        return $this->events->onClose($listener);
    }

    /**
     * POSTs one envelope and emits whatever the server answers with.
     *
     * @param array<string, mixed>            $envelope
     * @param array<non-empty-string, string> $headers  Mirrored parameter headers the protocol layer computed
     */
    private function exchange(array $envelope, array $headers, DeferredCancellation $lifetime): void
    {
        $response = $this->client->request($this->buildRequest($envelope, $headers), $lifetime->getCancellation());

        if ($response->getStatus() === HttpStatus::Accepted->value) {
            // The server accepted a notification. There is no body to correlate.
            return;
        }

        if (self::isEventStream($response)) {
            $this->readStream($response, $lifetime);

            return;
        }

        try {
            $payload = $response->getBody()->buffer($lifetime->getCancellation(), $this->maxResponseBytes);
        } catch (BufferException $e) {
            throw new ResponseTooLargeException($this->maxResponseBytes, $e);
        }

        $this->emit($payload);
    }

    /**
     * @param array<string, mixed>            $envelope
     * @param array<non-empty-string, string> $headers
     */
    private function buildRequest(array $envelope, array $headers): Request
    {
        $request = new Request($this->endpoint, 'POST', json_encode($envelope, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE));

        // `setHeaders()` replaces the whole bag rather than merging, so every header goes in one call.
        $request->setHeaders([
            'Content-Type' => 'application/json',
            'Accept' => self::ACCEPT,
            ...$headers,
            ...StandardHeaders::build($envelope),
        ]);

        // A request-scoped stream lives as long as the server keeps it open, so only a stall may end it.
        $request->setTransferTimeout(0.0);
        $request->setInactivityTimeout($this->readTimeout);

        return $request;
    }

    /**
     * Emits each frame of an SSE response as it arrives, until the server ends the stream.
     */
    private function readStream(Response $response, DeferredCancellation $lifetime): void
    {
        $parser = new SseFrameParser($this->maxResponseBytes);
        $body = $response->getBody();
        $cancellation = $lifetime->getCancellation();

        $chunk = $body->read($cancellation);

        // A null chunk is the server closing the stream, which ends the exchange.
        while (null !== $chunk) {
            foreach ($parser->feed($chunk) as $frame) {
                try {
                    $this->emit($frame->data);
                } catch (\InvalidArgumentException|\JsonException $e) {
                    // One unreadable frame does not end the stream: a later frame may still carry the
                    // response, so the exchange reads on rather than failing its caller here.
                    $this->events->emitError($e);
                }
            }

            $chunk = $body->read($cancellation);
        }
    }

    /**
     * Decodes one JSON-RPC envelope and hands it to the message listeners.
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function emit(string $payload): void
    {
        $envelope = json_decode($payload, associative: true, flags: \JSON_THROW_ON_ERROR);
        Assert::that($envelope)->isMap(\sprintf('%s received a payload that is not a JSON-RPC envelope.', self::LABEL));

        $this->events->emitMessage($envelope, new ReceiveContext());
    }

    private static function isEventStream(Response $response): bool
    {
        return str_contains(strtolower($response->getHeader('Content-Type') ?? ''), 'text/event-stream');
    }
}
