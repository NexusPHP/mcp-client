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

use Amp\Cancellation;
use Amp\Http\Client\DelegateHttpClient;
use Amp\Http\Client\Request;
use Nexus\Mcp\Client\Exception\AuthorizationDiscoveryFailedException;
use Nexus\Mcp\Client\Exception\MalformedAuthorizationResponseException;
use Nexus\Mcp\Client\Exception\PkceNotSupportedException;
use Nexus\Mcp\Client\Exception\UntrustedAuthorizationMetadataException;
use Nexus\Mcp\Core\Auth\AuthorizationServerMetadata;
use Nexus\Mcp\Core\Auth\ProtectedResourceMetadata;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\WwwAuthenticateChallenge;
use Nexus\Mcp\Core\Exception\ResponseTooLargeException;
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
    private JsonHttpExchange $exchange;

    public function __construct(DelegateHttpClient $client, float $timeout = 10.0)
    {
        $this->exchange = new JsonHttpExchange($client, $timeout);
    }

    /**
     * Reads the Protected Resource Metadata for an MCP server, preferring the URL a `WWW-Authenticate`
     * challenge advertised and falling back to the well-known URLs, path-scoped before root.
     */
    public function discoverResource(
        ResourceIdentifier $resource,
        ?WwwAuthenticateChallenge $challenge,
        Cancellation $cancellation,
    ): ProtectedResourceMetadata {
        $candidates = WellKnownUri::forProtectedResource($resource->value);
        $advertised = $challenge?->readParameter('resource_metadata');

        if (null !== $advertised) {
            SecureEndpoint::verifySameOrigin($advertised, 'advertised protected resource metadata URL', $resource);
            array_unshift($candidates, $advertised);
        }

        foreach ($candidates as $url) {
            $data = $this->fetch($url, 'protected resource metadata URL', $resource, $cancellation);

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
    public function discoverServer(
        string $issuer,
        ResourceIdentifier $resource,
        Cancellation $cancellation,
    ): AuthorizationServerMetadata {
        $candidates = WellKnownUri::forAuthorizationServer($issuer);

        foreach ($candidates as $url) {
            $data = $this->fetch($url, 'authorization server metadata URL', $resource, $cancellation);

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
     * @return null|array<string, mixed> The decoded document, or `null` when nothing usable is served there
     *
     * @throws MalformedAuthorizationResponseException When the document served is not a JSON object
     */
    private function fetch(
        string $url,
        string $label,
        ResourceIdentifier $resource,
        Cancellation $cancellation,
    ): ?array {
        SecureEndpoint::verifyAdvertised($url, $label, $resource);

        try {
            [$status, $payload] = $this->exchange->send(new Request($url, 'GET'), $cancellation);
        } catch (ResponseTooLargeException) {
            // A document this large is not one this client can read, so the next candidate gets its turn.
            return null;
        }

        if (HttpStatus::Ok->value !== $status) {
            return null;
        }

        return JsonHttpExchange::decode($payload, $label);
    }

    private static function verifyPkceSupport(AuthorizationServerMetadata $metadata): void
    {
        $methods = $metadata->codeChallengeMethodsSupported;

        if (null === $methods || ! \in_array(PkcePair::CHALLENGE_METHOD, $methods, true)) {
            throw new PkceNotSupportedException($metadata->issuer);
        }
    }
}
