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
use Nexus\Mcp\Client\Exception\RedirectRefusedException;
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
    private const string RESOURCE_LABEL = 'protected resource metadata URL';
    private const string SERVER_LABEL = 'authorization server metadata URL';

    private JsonHttpExchange $exchange;

    public function __construct(
        DelegateHttpClient $client,
        float $timeout = 10.0,
        private bool $allowInsecureLoopback = false,
    ) {
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
            array_unshift($candidates, $advertised);
        }

        foreach ($candidates as $url) {
            // A challenge that advertises a document on another origin is naming one the MCP server does
            // not own. That candidate is dropped rather than trusted, and rather than taken as a reason to
            // abandon the well-known URLs the spec mandates falling back to.
            if (! $resource->sharesOriginWith($url)) {
                continue;
            }

            $data = $this->fetch($url, self::RESOURCE_LABEL, $cancellation);

            if (null === $data) {
                continue;
            }

            $metadata = self::readResource($data);

            if (! self::describesResource($metadata->resource->value, $resource->value)) {
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
    public function discoverServer(string $issuer, Cancellation $cancellation): AuthorizationServerMetadata
    {
        // Every candidate inherits the issuer's scheme and authority, so holding the issuer to HTTPS holds
        // all of them, and it does so before an unusable one reaches the URL builder.
        SecureEndpoint::verifyAuthorizationServerUrl($issuer, 'authorization server issuer', $this->allowInsecureLoopback);
        $candidates = WellKnownUri::forAuthorizationServer($issuer);

        foreach ($candidates as $url) {
            $data = $this->fetch($url, self::SERVER_LABEL, $cancellation);

            if (null === $data) {
                continue;
            }

            $metadata = self::readServer($data);

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
     * Whether a document naming `$named` may be trusted to describe `$resource`.
     *
     * The candidate list includes the origin-root well-known URL, and RFC 9728 assigns that URL to the
     * resource at the origin, so the document it serves names the origin rather than the path-scoped
     * endpoint. Accepting it is what makes that fallback reachable. A document naming any other origin
     * belongs to a resource server this one does not own and is refused.
     */
    private static function describesResource(string $named, string $resource): bool
    {
        return $named === $resource || WellKnownUri::originOf($resource) === $named;
    }

    /**
     * @return null|array<string, mixed> The decoded document, or `null` when nothing usable is served there
     */
    private function fetch(string $url, string $label, Cancellation $cancellation): ?array
    {
        try {
            [$status, $payload] = $this->exchange->send(new Request($url, 'GET'), $cancellation);

            return HttpStatus::Ok->value === $status ? JsonHttpExchange::decode($payload, $label) : null;
        } catch (\InvalidArgumentException|MalformedAuthorizationResponseException|RedirectRefusedException|ResponseTooLargeException) {
            // The spec fixes an order of candidates to fall back through, so nothing one of them answers
            // ends the search. A body too large to read, a payload that is not a JSON object, an answer
            // from a URL other than the one asked, and a peer-supplied URL built out of bytes no URI may
            // carry all leave the candidates after it their turn.
            return null;
        }
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws UntrustedAuthorizationMetadataException
     */
    private static function readResource(array $data): ProtectedResourceMetadata
    {
        try {
            return ProtectedResourceMetadata::fromArray($data);
        } catch (\InvalidArgumentException $e) {
            throw self::describeUnreadable(self::RESOURCE_LABEL, $e);
        }
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws UntrustedAuthorizationMetadataException
     */
    private static function readServer(array $data): AuthorizationServerMetadata
    {
        try {
            return AuthorizationServerMetadata::fromArray($data);
        } catch (\InvalidArgumentException $e) {
            throw self::describeUnreadable(self::SERVER_LABEL, $e);
        }
    }

    /**
     * Turns a field-level parse failure into one of this SDK's own exceptions, so a document a peer shaped
     * cannot surface as an argument fault the caller has no contract for.
     */
    private static function describeUnreadable(string $label, \InvalidArgumentException $cause): UntrustedAuthorizationMetadataException
    {
        return new UntrustedAuthorizationMetadataException(
            \sprintf('the %s answered with a document off the shape the spec fixes.', $label),
            $cause,
        );
    }

    private static function verifyPkceSupport(AuthorizationServerMetadata $metadata): void
    {
        $methods = $metadata->codeChallengeMethodsSupported;

        if (null === $methods || ! \in_array(PkcePair::CHALLENGE_METHOD, $methods, true)) {
            throw new PkceNotSupportedException($metadata->issuer);
        }
    }
}
