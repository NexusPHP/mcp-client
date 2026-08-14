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
use Nexus\Mcp\Client\Exception\PkceNotSupportedException;
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
     * challenge advertised over the well-known URLs.
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
                    SafeDisplay::sanitiseCause($metadata->resource->value),
                ));
            }

            return $metadata;
        }

        self::refuseDiscovery('protected resource metadata', $resource->value, $candidates);
    }

    public function discoverServer(string $issuer, Cancellation $cancellation): AuthorizationServerMetadata
    {
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
                    SafeDisplay::sanitiseCause($issuer),
                    SafeDisplay::sanitiseCause($metadata->issuer),
                ));
            }

            self::verifyPkceSupport($metadata);

            return $metadata;
        }

        self::refuseDiscovery('authorization server metadata', $issuer, $candidates);
    }

    /**
     * Whether a document naming `$named` may be trusted to describe `$resource`, which RFC 9728 extends to
     * the origin the root well-known URL is assigned to.
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

    /**
     * @param list<string> $probed
     */
    private static function refuseDiscovery(string $document, string $subject, array $probed): never
    {
        throw new RuntimeException(\sprintf(
            'No %s was served for "%s". Probed: %s.',
            $document,
            SafeDisplay::sanitiseCause($subject),
            implode(', ', array_map(static fn(string $url): string => SafeDisplay::sanitiseCause($url), $probed)),
        ));
    }
}
