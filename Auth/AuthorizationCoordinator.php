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

use Nexus\Mcp\Client\Exception\TokenRequestFailedException;
use Nexus\Mcp\Core\Auth\AuthorizationServerMetadata;
use Nexus\Mcp\Core\Auth\ProtectedResourceMetadata;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\ScopeSet;
use Nexus\Mcp\Core\Auth\WwwAuthenticateChallenge;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Runs the OAuth 2.1 flow end to end for one MCP client: discovery, client registration, the user-agent
 * round trip, and the token exchange, then holds the resulting token for reuse.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/draft/basic/authorization#authorization-flow-steps
 */
final class AuthorizationCoordinator
{
    /**
     * Seconds before its stated expiry at which a token is treated as spent, so a request is not sent with
     * a token that lapses in flight.
     */
    private const int EXPIRY_LEEWAY_SECONDS = 30;

    private const string OFFLINE_ACCESS_SCOPE = 'offline_access';

    /**
     * The authorization server each resource resolved to, so a token can be found again without repeating
     * discovery.
     *
     * @var array<string, AuthorizationServerMetadata>
     */
    private array $servers = [];

    public function __construct(
        private readonly MetadataDiscovery $discovery,
        private readonly ClientRegistrar $registrar,
        private readonly TokenEndpoint $tokenEndpoint,
        private readonly UserAuthorizationInterface $userAuthorization,
        private readonly TokenStoreInterface $tokens,
        private readonly AuthorizationOptions $options,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {
    }

    /**
     * Obtains a fresh token for an MCP server, running the full authorization flow.
     *
     * @param ScopeSet $additionalScopes Scopes an insufficient-scope challenge asked for, accumulated onto
     *                                   the set already granted
     */
    public function authorize(
        ResourceIdentifier $resource,
        ?WwwAuthenticateChallenge $challenge = null,
        ScopeSet $additionalScopes = new ScopeSet(),
    ): AccessToken {
        $metadata = $this->discovery->discoverResource($resource, $challenge);

        // A resource may name several authorization servers and the choice is the client's. Taking the
        // first honours the order the resource published them in.
        $server = $this->discovery->discoverServer($metadata->authorizationServers[0]);
        $this->servers[$resource->value] = $server;

        $registration = $this->registrar->resolve($server, $this->options);
        $scopes = $this->selectScopes($resource, $challenge, $metadata, $server, $additionalScopes);

        $redirect = AuthorizationRequest::build(
            $server,
            $registration->clientId,
            $this->options->redirectUri,
            $resource,
            $scopes,
        );

        $code = AuthorizationResponse::readCode($redirect, $this->userAuthorization->authorize($redirect));

        $token = $this->tokenEndpoint->exchangeCode(
            $server,
            $registration,
            $redirect,
            $code,
            $this->options->redirectUri,
            $resource,
        );
        $this->tokens->write($resource->value, $server->issuer, $token);

        $this->logger->info('Authorized {resource} at {issuer}.', [
            'resource' => $resource->value,
            'issuer' => $server->issuer,
        ]);

        return $token;
    }

    /**
     * The token already held for an MCP server, renewed when it is spent, or `null` when the client has
     * none it can still use.
     */
    public function fetchToken(ResourceIdentifier $resource): ?AccessToken
    {
        $server = $this->servers[$resource->value] ?? null;

        if (null === $server) {
            return null;
        }

        $token = $this->tokens->read($resource->value, $server->issuer);

        if (null === $token || ! self::hasExpired($token)) {
            return $token;
        }

        return $this->renew($resource, $server, $token);
    }

    /**
     * Drops the token held for an MCP server, so the next request authorizes again.
     */
    public function discard(ResourceIdentifier $resource): void
    {
        $server = $this->servers[$resource->value] ?? null;

        if (null !== $server) {
            $this->tokens->forget($resource->value, $server->issuer);
        }
    }

    private function renew(ResourceIdentifier $resource, AuthorizationServerMetadata $server, AccessToken $token): ?AccessToken
    {
        if (null === $token->refreshToken) {
            $this->tokens->forget($resource->value, $server->issuer);

            return null;
        }

        try {
            $renewed = $this->tokenEndpoint->refresh(
                $server,
                $this->registrar->resolve($server, $this->options),
                $token,
                $resource,
            );
        } catch (TokenRequestFailedException $e) {
            $this->logger->info('The refresh token for {resource} was refused, so a new authorization is needed. {reason}', [
                'resource' => $resource->value,
                'reason' => $e->getMessage(),
            ]);
            $this->tokens->forget($resource->value, $server->issuer);

            return null;
        }

        $this->tokens->write($resource->value, $server->issuer, $renewed);

        return $renewed;
    }

    private function selectScopes(
        ResourceIdentifier $resource,
        ?WwwAuthenticateChallenge $challenge,
        ProtectedResourceMetadata $metadata,
        AuthorizationServerMetadata $server,
        ScopeSet $additionalScopes,
    ): ScopeSet {
        $challenged = $challenge?->readParameter('scope');

        // A challenge is authoritative for the operation that provoked it. Absent one, the resource's own
        // advertised set stands in, and a resource that advertises none leaves the parameter off.
        $scopes = null !== $challenged
            ? ScopeSet::parse($challenged)
            : $metadata->scopesSupported ?? new ScopeSet();

        $scopes = $scopes->mergeWith($additionalScopes);
        $granted = $this->tokens->read($resource->value, $server->issuer);

        // Asking for only the challenged scopes would drop permissions other operations rely on.
        if (null !== $granted) {
            $scopes = $scopes->mergeWith(new ScopeSet($granted->scopes));
        }

        if ($this->options->requestOfflineAccess && \in_array(self::OFFLINE_ACCESS_SCOPE, $server->scopesSupported->values ?? [], true)) {
            $scopes = $scopes->mergeWith(new ScopeSet([self::OFFLINE_ACCESS_SCOPE]));
        }

        return $scopes;
    }

    private static function hasExpired(AccessToken $token): bool
    {
        return null !== $token->expiresAt && $token->expiresAt <= time() + self::EXPIRY_LEEWAY_SECONDS;
    }
}
