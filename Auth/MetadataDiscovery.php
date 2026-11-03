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
use Nexus\Mcp\Client\Exception\MalformedAuthorizationResponseException;
use Nexus\Mcp\Client\Exception\RedirectRefusedException;
use Nexus\Mcp\Client\Exception\UntrustedAuthorizationMetadataException;
use Nexus\Mcp\Core\Auth\AuthorizationServerMetadata;
use Nexus\Mcp\Core\Auth\ProtectedResourceMetadata;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\WwwAuthenticateChallenge;
use Nexus\Mcp\Core\Exception\ResponseTooLargeException;
use Nexus\Mcp\Core\Exception\RuntimeException;
use Nexus\Mcp\Core\Http\HttpStatus;
use Nexus\Mcp\Core\SafeDisplay;

/**
 * Discovery of the authorization server protecting an MCP server.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery
 */
final readonly class MetadataDiscovery
{
    private const string PROTECTED_RESOURCE_PATH = '/.well-known/oauth-protected-resource';
    private const string AUTHORIZATION_SERVER_PATH = '/.well-known/oauth-authorization-server';
    private const string OPENID_CONFIGURATION_PATH = '/.well-known/openid-configuration';

    public function __construct(
        private DelegateHttpClient $client,
        private float $timeout = 10.0,
        private SecureEndpoint $secureEndpoint = new SecureEndpoint(),
    ) {
    }

    /**
     * Reads the Protected Resource Metadata for an MCP server, preferring the URL advertised by a `WWW-Authenticate`
     * challenge over the well-known URLs.
     */
    public function discoverResource(
        ResourceIdentifier $resource,
        ?WwwAuthenticateChallenge $challenge,
        Cancellation $cancellation,
    ): ProtectedResourceMetadata {
        $candidates = self::buildProtectedResourceUrls($resource->value);
        $advertised = $challenge?->readParameter('resource_metadata');

        if (null !== $advertised) {
            array_unshift($candidates, $advertised);
        }

        foreach ($candidates as $url) {
            if (! $resource->sharesOriginWith($url)) {
                continue;
            }

            $data = $this->fetch($url, 'protected resource metadata URL', $cancellation);

            if (null === $data) {
                continue;
            }

            $metadata = $this->readResource($data);

            if (! $this->describesResource($metadata->resource->value, $resource->value)) {
                throw new UntrustedAuthorizationMetadataException(\sprintf(
                    'the document served for "%s" names the resource "%s".',
                    $resource->value,
                    SafeDisplay::sanitiseCause($metadata->resource->value),
                ));
            }

            return $metadata;
        }

        $this->refuseDiscovery('protected resource metadata', $resource->value, $candidates);
    }

    public function discoverServer(string $issuer, Cancellation $cancellation): AuthorizationServerMetadata
    {
        $this->secureEndpoint->verifyAuthorizationServerUrl($issuer, 'authorization server issuer');
        $candidates = self::buildAuthorizationServerUrls($issuer);

        foreach ($candidates as $url) {
            $data = $this->fetch($url, 'authorization server metadata URL', $cancellation);

            if (null === $data) {
                continue;
            }

            $metadata = $this->readServer($data);

            if ($metadata->issuer !== $issuer) {
                throw new UntrustedAuthorizationMetadataException(\sprintf(
                    'the document served for "%s" names the issuer "%s".',
                    SafeDisplay::sanitiseCause($issuer),
                    SafeDisplay::sanitiseCause($metadata->issuer),
                ));
            }

            return $metadata;
        }

        $this->refuseDiscovery('authorization server metadata', $issuer, $candidates);
    }

    /**
     * The Protected Resource Metadata URLs for an MCP endpoint, the path-scoped one first and the only one
     * keeping the resource identifier's query.
     *
     * @return list<string>
     */
    public static function buildProtectedResourceUrls(string $resource): array
    {
        [$origin, $path, $query] = self::splitOrigin($resource);

        if ('' === $path) {
            return [$origin.self::PROTECTED_RESOURCE_PATH.$query];
        }

        return [
            $origin.self::PROTECTED_RESOURCE_PATH.$path.$query,
            $origin.self::PROTECTED_RESOURCE_PATH,
        ];
    }

    /**
     * The Authorization Server Metadata URLs for an issuer, RFC 8414 before OpenID Connect Discovery and
     * path insertion before path appending.
     *
     * @return list<string>
     */
    public static function buildAuthorizationServerUrls(string $issuer): array
    {
        [$origin, $path] = self::splitOrigin($issuer);

        if ('' === $path) {
            return [
                $origin.self::AUTHORIZATION_SERVER_PATH,
                $origin.self::OPENID_CONFIGURATION_PATH,
            ];
        }

        return [
            $origin.self::AUTHORIZATION_SERVER_PATH.$path,
            $origin.self::OPENID_CONFIGURATION_PATH.$path,
            $origin.$path.self::OPENID_CONFIGURATION_PATH,
        ];
    }

    public static function readOrigin(string $uri): string
    {
        return self::splitOrigin($uri)[0];
    }

    /**
     * Whether a document naming `$named` may be trusted to describe `$resource`, which RFC 9728 extends to
     * the origin that the root well-known URL is assigned to.
     */
    private function describesResource(string $named, string $resource): bool
    {
        return $named === $resource || self::readOrigin($resource) === $named;
    }

    /**
     * @param non-empty-string $label
     *
     * @return null|array<string, mixed> The decoded document, or `null` when nothing usable is served there
     */
    private function fetch(string $url, string $label, Cancellation $cancellation): ?array
    {
        try {
            $exchange = new JsonHttpExchange($this->client, $label, $this->timeout);
            [$status, $payload] = $exchange->send(new Request($url, 'GET'), $cancellation);

            return HttpStatus::Ok->value === $status ? $exchange->decode($payload) : null;
        } catch (\InvalidArgumentException|MalformedAuthorizationResponseException|RedirectRefusedException|ResponseTooLargeException) {
            return null;
        }
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws UntrustedAuthorizationMetadataException
     */
    private function readResource(array $data): ProtectedResourceMetadata
    {
        try {
            return ProtectedResourceMetadata::fromArray($data);
        } catch (\InvalidArgumentException $e) {
            throw $this->describeUnreadable('protected resource metadata URL', $e);
        }
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws UntrustedAuthorizationMetadataException
     */
    private function readServer(array $data): AuthorizationServerMetadata
    {
        try {
            return AuthorizationServerMetadata::fromArray($data);
        } catch (\InvalidArgumentException $e) {
            throw $this->describeUnreadable('authorization server metadata URL', $e);
        }
    }

    private function describeUnreadable(
        string $label,
        \InvalidArgumentException $cause,
    ): UntrustedAuthorizationMetadataException {
        return new UntrustedAuthorizationMetadataException(
            \sprintf('the %s answered with a document off the shape the spec fixes.', $label),
            $cause,
        );
    }

    /**
     * @param list<string> $probed
     */
    private function refuseDiscovery(string $document, string $subject, array $probed): never
    {
        throw new RuntimeException(\sprintf(
            'No %s was served for "%s". Probed: %s.',
            $document,
            SafeDisplay::sanitiseCause($subject),
            implode(', ', array_map(static fn(string $url): string => SafeDisplay::sanitiseCause($url), $probed)),
        ));
    }

    /**
     * @return array{string, string, string}
     */
    private static function splitOrigin(string $uri): array
    {
        $parts = parse_url($uri);

        if (false === $parts || ! isset($parts['scheme'], $parts['host'])) {
            throw new \InvalidArgumentException(\sprintf(
                'A well-known metadata URL cannot be built from "%s", which is not an absolute URI.',
                $uri,
            ));
        }

        return [
            \sprintf(
                '%s://%s%s',
                strtolower($parts['scheme']),
                strtolower($parts['host']),
                isset($parts['port']) ? ':'.$parts['port'] : '',
            ),
            rtrim($parts['path'] ?? '', '/'),
            isset($parts['query']) ? '?'.$parts['query'] : '',
        ];
    }
}
