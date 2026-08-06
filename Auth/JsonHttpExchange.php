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

namespace Nexus\Mcp\Client\Auth;

use Amp\ByteStream\BufferException;
use Amp\Cancellation;
use Amp\Http\Client\DelegateHttpClient;
use Amp\Http\Client\Request;
use Nexus\Assert\Assert;
use Nexus\Assert\ExpectationFailedException;
use Nexus\Mcp\Client\Exception\MalformedAuthorizationResponseException;
use Nexus\Mcp\Client\Exception\RedirectRefusedException;
use Nexus\Mcp\Core\Exception\ResponseTooLargeException;

/**
 * Carries the JSON request and response pairs an OAuth flow is made of, bounding each answer by a byte cap
 * and pinning it to the URL the request was sent to.
 *
 * @internal
 */
final readonly class JsonHttpExchange
{
    /**
     * Bytes of an answer buffered before the endpoint is treated as unusable.
     */
    public const int MAX_RESPONSE_BYTES = 65_536;

    public function __construct(private DelegateHttpClient $client, private float $timeout = 10.0)
    {
    }

    /**
     * Sends a request and buffers its answer.
     *
     * @return array{int, string} The status and the buffered payload
     */
    public function send(Request $request, Cancellation $cancellation): array
    {
        $request->setHeader('Accept', 'application/json');
        $request->setTransferTimeout($this->timeout);
        $request->setInactivityTimeout($this->timeout);

        $sent = (string) $request->getUri();
        $response = $this->client->request($request, $cancellation);
        $answered = (string) $response->getRequest()->getUri();

        // An HTTP client that follows redirects re-checks neither the scheme nor the host of where it
        // landed, so nothing read from a redirected answer can be trusted.
        if ($answered !== $sent) {
            throw new RedirectRefusedException($sent, $answered);
        }

        try {
            $payload = $response->getBody()->buffer(limit: self::MAX_RESPONSE_BYTES);
        } catch (BufferException $e) {
            throw new ResponseTooLargeException(self::MAX_RESPONSE_BYTES, $e);
        }

        return [$response->getStatus(), $payload];
    }

    /**
     * @return array<string, mixed>
     */
    public static function decode(string $payload, string $label): array
    {
        try {
            $data = json_decode($payload, associative: true, flags: \JSON_THROW_ON_ERROR);
            Assert::that($data)->isMap('The payload is not a JSON object.');
        } catch (ExpectationFailedException|\JsonException $e) {
            throw new MalformedAuthorizationResponseException($label, $e);
        }

        return $data;
    }
}
