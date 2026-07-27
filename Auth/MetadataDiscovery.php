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
use Amp\Http\Client\DelegateHttpClient;
use Amp\Http\Client\Request;
use Amp\NullCancellation;
use Nexus\Assert\Assert;
use Nexus\Mcp\Client\Exception\AuthorizationDiscoveryFailedException;
use Nexus\Mcp\Client\Exception\PkceNotSupportedException;
use Nexus\Mcp\Client\Exception\UntrustedAuthorizationMetadataException;
use Nexus\Mcp\Core\Auth\AuthorizationServerMetadata;
use Nexus\Mcp\Core\Auth\ProtectedResourceMetadata;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\WellKnownUri;
use Nexus\Mcp\Core\Auth\WwwAuthenticateChallenge;
use Nexus\Mcp\Core\Http\HttpStatus;

/**
 * Locates the authorization server protecting an MCP server, by reading its Protected Resource Metadata and
 * then the metadata of the authorization server it names.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery
 */
final readonly class MetadataDiscovery
{
    private const int MAX_RESPONSE_BYTES = 65536;

    /**
     * Bytes of a non-answer drained before the connection carrying it is given up on instead.
     */
    private const int MAX_DISCARDED_BYTES = 8192;

    public function __construct(private DelegateHttpClient $client, private float $timeout = 10.0)
    {
    }

    /**
     * Reads the Protected Resource Metadata for an MCP server, preferring the URL a `WWW-Authenticate`
     * challenge advertised and falling back to the well-known URLs, path-scoped before root.
     */
    public function discoverResource(ResourceIdentifier $resource, ?WwwAuthenticateChallenge $challenge = null): ProtectedResourceMetadata
    {
        $candidates = WellKnownUri::forProtectedResource($resource->value);
        $advertised = $challenge?->readParameter('resource_metadata');

        if (null !== $advertised) {
            array_unshift($candidates, $advertised);
        }

        foreach ($candidates as $url) {
            $data = $this->fetch($url, 'protected resource metadata URL');

            if (null === $data) {
                continue;
            }

            $metadata = ProtectedResourceMetadata::fromArray($data);

            if ($metadata->resource->value !== $resource->value) {
                throw new UntrustedAuthorizationMetadataException(\sprintf(
                    'the document served for "%s" names the resource "%s".',
                    $resource->value,
                    $metadata->resource->value,
                ));
            }

            return $metadata;
        }

        throw new AuthorizationDiscoveryFailedException('protected resource metadata', $resource->value, $candidates);
    }

    /**
     * Reads an authorization server's metadata, trying the RFC 8414 and OpenID Connect well-known URLs in
     * the order the spec fixes.
     */
    public function discoverServer(string $issuer): AuthorizationServerMetadata
    {
        $candidates = WellKnownUri::forAuthorizationServer($issuer);

        foreach ($candidates as $url) {
            $data = $this->fetch($url, 'authorization server metadata URL');

            if (null === $data) {
                continue;
            }

            $metadata = AuthorizationServerMetadata::fromArray($data);

            if ($metadata->issuer !== $issuer) {
                throw new UntrustedAuthorizationMetadataException(\sprintf(
                    'the document served for "%s" names the issuer "%s".',
                    $issuer,
                    $metadata->issuer,
                ));
            }

            self::verifyPkceSupport($metadata);

            return $metadata;
        }

        throw new AuthorizationDiscoveryFailedException('authorization server metadata', $issuer, $candidates);
    }

    /**
     * @return null|array<string, mixed> The decoded document, or `null` when nothing is served there
     */
    private function fetch(string $url, string $label): ?array
    {
        SecureEndpoint::verify($url, $label);

        $request = new Request($url, 'GET');
        $request->setHeader('Accept', 'application/json');
        $request->setTransferTimeout($this->timeout);
        $request->setInactivityTimeout($this->timeout);

        $response = $this->client->request($request, new NullCancellation());

        if ($response->getStatus() !== HttpStatus::Ok->value) {
            try {
                // Reading a miss to its end returns its connection to the pool, so the next candidate
                // against the same host does not pay for a fresh one.
                $response->getBody()->buffer(limit: self::MAX_DISCARDED_BYTES);
            } catch (BufferException) {
                // A miss this large is not worth holding the connection open for.
            }

            return null;
        }

        $payload = $response->getBody()->buffer(limit: self::MAX_RESPONSE_BYTES);
        $data = json_decode($payload, associative: true, flags: \JSON_THROW_ON_ERROR);
        Assert::that($data)->isMap(\sprintf('The %s answered with a payload that is not a JSON object.', $label));

        return $data;
    }

    private static function verifyPkceSupport(AuthorizationServerMetadata $metadata): void
    {
        $methods = $metadata->codeChallengeMethodsSupported;

        if (null === $methods || ! \in_array(PkcePair::CHALLENGE_METHOD, $methods, true)) {
            throw new PkceNotSupportedException($metadata->issuer);
        }
    }
}
