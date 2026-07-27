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

use Nexus\Mcp\Client\Exception\AuthorizationGrantRejectedException;
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
     * What discovery last found for each resource, so a step-up does not repeat it.
     *
     * @var array<string, DiscoveredResource>
     */
    private array $discovered = [];

    /**
     * @var SharedFlow<AccessToken>
     */
    private SharedFlow $authorizations;

    /**
     * @var SharedFlow<?AccessToken>
     */
    private SharedFlow $renewals;

    public function __construct(
        private readonly MetadataDiscovery $discovery,
        private readonly ClientRegistrar $registrar,
        private readonly TokenEndpoint $tokenEndpoint,
        private readonly UserAuthorizationInterface $userAuthorization,
        private readonly TokenStoreInterface $tokens,
        private readonly AuthorizationOptions $options,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {
        $this->authorizations = new SharedFlow();
        $this->renewals = new SharedFlow();
    }

    /**
     * Obtains a fresh token for an MCP server, running the full authorization flow, or joins the flow
     * already running for that server.
     *
     * @param ScopeSet $additionalScopes Scopes an insufficient-scope challenge asked for, accumulated onto
     *                                   the set already granted
     */
    public function authorize(
        ResourceIdentifier $resource,
        ?WwwAuthenticateChallenge $challenge = null,
        ScopeSet $additionalScopes = new ScopeSet(),
    ): AccessToken {
        return $this->authorizations->run(
            self::buildGrantKey($resource, $challenge, $additionalScopes),
            fn(): AccessToken => $this->runAuthorization($resource, $challenge, $additionalScopes),
        );
    }

    /**
     * The token already held for an MCP server, renewed when it is spent, or `null` when the client has
     * none it can still use.
     */
    public function fetchToken(ResourceIdentifier $resource): ?AccessToken
    {
        $token = $this->tokens->read($resource->value);

        if (null === $token || ! self::hasExpired($token)) {
            return $token;
        }

        return $this->renewals->run($resource->value, fn(): ?AccessToken => $this->renew($resource, $token));
    }

    /**
     * The scopes the token held for an MCP server was granted, empty when the client holds none.
     */
    public function readGrantedScopes(ResourceIdentifier $resource): ScopeSet
    {
        $token = $this->tokens->read($resource->value);

        return new ScopeSet(null === $token ? [] : $token->scopes);
    }

    /**
     * Drops what is held for an MCP server that rejected its token, reporting the scopes that token
     * carried. Discovery goes with it, so the next authorization can follow the resource to a different
     * authorization server.
     */
    public function discardCredentials(ResourceIdentifier $resource): ScopeSet
    {
        unset($this->discovered[$resource->value]);
        $token = $this->tokens->read($resource->value);

        if (null === $token) {
            return new ScopeSet();
        }

        $this->tokens->forget($resource->value);

        return new ScopeSet($token->scopes);
    }

    private function runAuthorization(
        ResourceIdentifier $resource,
        ?WwwAuthenticateChallenge $challenge,
        ScopeSet $additionalScopes,
    ): AccessToken {
        $discovered = $this->discover($resource, $challenge);
        $server = $discovered->server;

        $registration = $this->registrar->resolve($server, $this->options);
        $scopes = $this->selectScopes($resource, $challenge, $discovered, $additionalScopes);

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
        $this->tokens->write($resource->value, $token);

        $this->logger->info('Authorized {resource} at {issuer}.', [
            'resource' => $resource->value,
            'issuer' => $server->issuer,
        ]);

        return $token;
    }

    /**
     * Reads the metadata of an MCP server and of the authorization server it names, reusing what an earlier
     * round already found.
     */
    private function discover(ResourceIdentifier $resource, ?WwwAuthenticateChallenge $challenge): DiscoveredResource
    {
        $cached = $this->discovered[$resource->value] ?? null;

        if (null !== $cached) {
            return $cached;
        }

        $metadata = $this->discovery->discoverResource($resource, $challenge);

        // A resource may name several authorization servers and the choice is the client's. Taking the
        // first honours the order the resource published them in.
        $server = $this->discovery->discoverServer($metadata->authorizationServers[0]);
        $discovered = new DiscoveredResource($metadata, $server);
        $this->discovered[$resource->value] = $discovered;

        return $discovered;
    }

    private function renew(ResourceIdentifier $resource, AccessToken $token): ?AccessToken
    {
        if (null === $token->refreshToken) {
            $this->tokens->forget($resource->value);

            return null;
        }

        $server = $this->discover($resource, null)->server;

        // A token minted by a server the resource has since moved off cannot be renewed at the new one, and
        // must not be presented to it either.
        if ($server->issuer !== $token->issuer) {
            $this->logger->info('The token for {resource} was issued by {issuer}, which no longer serves it.', [
                'resource' => $resource->value,
                'issuer' => $token->issuer,
            ]);
            $this->tokens->forget($resource->value);

            return null;
        }

        try {
            $renewed = $this->tokenEndpoint->refresh(
                $server,
                $this->registrar->resolve($server, $this->options),
                $token,
                $resource,
            );
        } catch (AuthorizationGrantRejectedException $e) {
            $this->logger->info('The refresh token for {resource} was refused, so a new authorization is needed. {reason}', [
                'resource' => $resource->value,
                'reason' => $e->getMessage(),
            ]);
            $this->tokens->forget($resource->value);

            return null;
        }

        $this->tokens->write($resource->value, $renewed);

        return $renewed;
    }

    private function selectScopes(
        ResourceIdentifier $resource,
        ?WwwAuthenticateChallenge $challenge,
        DiscoveredResource $discovered,
        ScopeSet $additionalScopes,
    ): ScopeSet {
        $challenged = $challenge?->readParameter('scope');

        // A challenge is authoritative for the operation that provoked it. Absent one, the resource's own
        // advertised set stands in, and a resource that advertises none leaves the parameter off.
        $scopes = null !== $challenged
            ? ScopeSet::parse($challenged)
            : $discovered->metadata->scopesSupported ?? new ScopeSet();

        $scopes = $scopes->mergeWith($additionalScopes);
        $granted = $this->tokens->read($resource->value);

        // Asking for only the challenged scopes would drop permissions other operations rely on.
        if (null !== $granted) {
            $scopes = $scopes->mergeWith(new ScopeSet($granted->scopes));
        }

        if ($this->options->requestOfflineAccess && \in_array(self::OFFLINE_ACCESS_SCOPE, $discovered->server->scopesSupported->values ?? [], true)) {
            $scopes = $scopes->mergeWith(new ScopeSet([self::OFFLINE_ACCESS_SCOPE]));
        }

        return $scopes;
    }

    /**
     * Two callers share one grant only when they would ask the resource owner for the same thing. A joiner
     * whose demands the running flow does not cover would otherwise be handed a token that cannot serve it.
     */
    private static function buildGrantKey(
        ResourceIdentifier $resource,
        ?WwwAuthenticateChallenge $challenge,
        ScopeSet $additionalScopes,
    ): string {
        return implode("\n", [
            $resource->value,
            $challenge?->readParameter('scope') ?? '',
            implode(' ', $additionalScopes->values),
        ]);
    }

    private static function hasExpired(AccessToken $token): bool
    {
        return null !== $token->expiresAt && $token->expiresAt <= time() + self::EXPIRY_LEEWAY_SECONDS;
    }
}
