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
use Nexus\Mcp\Core\Exception\McpExceptionInterface;
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

    /**
     * What discovery last found for each resource, so a step-up does not repeat it.
     *
     * @var array<string, DiscoveredResource>
     */
    private array $discovered = [];

    /**
     * The scopes each resource has granted, kept apart from the token so dropping a spent or rejected one
     * does not narrow what the next grant asks for.
     *
     * @var array<string, ScopeSet>
     */
    private array $granted = [];

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
     * Everything an MCP server has granted this client, whether or not a token still holds it.
     */
    public function readGrantedScopes(ResourceIdentifier $resource): ScopeSet
    {
        $granted = $this->granted[$resource->value] ?? new ScopeSet();
        $token = $this->tokens->read($resource->value);

        return null === $token ? $granted : $granted->mergeWith(new ScopeSet($token->scopes));
    }

    /**
     * Drops what is held for an MCP server that rejected its token. Discovery goes with it, so the next
     * authorization can follow the resource to a different authorization server. What the server had
     * granted is remembered, so re-authorizing asks for it again rather than narrowing.
     */
    public function discardCredentials(ResourceIdentifier $resource): void
    {
        $this->granted[$resource->value] = $this->readGrantedScopes($resource);
        unset($this->discovered[$resource->value]);
        $this->tokens->forget($resource->value);
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
        $this->rememberGrant($resource, $token);

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
            $this->discardCredentials($resource);

            return null;
        }

        try {
            $server = $this->discover($resource, null)->server;
        } catch (McpExceptionInterface $e) {
            // Reaching no metadata says nothing about the token. Answering `null` sends the request bare,
            // and the challenge it draws is what re-authorization needs anyway.
            $this->logger->info('Renewing the token for {resource} found no metadata to renew it against. {reason}', [
                'resource' => $resource->value,
                'reason' => $e->getMessage(),
            ]);

            return null;
        }

        // A token minted by a server the resource has since moved off cannot be renewed at the new one, and
        // must not be presented to it either. Its scopes go with it: they were granted elsewhere.
        if ($server->issuer !== $token->issuer) {
            $this->logger->info('The token for {resource} was issued by {issuer}, which no longer serves it.', [
                'resource' => $resource->value,
                'issuer' => $token->issuer,
            ]);
            unset($this->granted[$resource->value], $this->discovered[$resource->value]);
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
            $this->discardCredentials($resource);

            return null;
        }

        $this->rememberGrant($resource, $renewed);

        return $renewed;
    }

    /**
     * Records what a token was granted, then stores it.
     */
    private function rememberGrant(ResourceIdentifier $resource, AccessToken $token): void
    {
        $this->granted[$resource->value] = $this->readGrantedScopes($resource)->mergeWith(new ScopeSet($token->scopes));
        $this->tokens->write($resource->value, $token);
    }

    private function selectScopes(
        ResourceIdentifier $resource,
        ?WwwAuthenticateChallenge $challenge,
        DiscoveredResource $discovered,
        ScopeSet $additionalScopes,
    ): ScopeSet {
        // Asking for only the challenged scopes would drop permissions other operations rely on.
        $scopes = $this->selectBaseline($challenge, $discovered->metadata->scopesSupported)
            ->mergeWith($additionalScopes)
            ->mergeWith($this->readGrantedScopes($resource))
        ;

        // Whether to hold a refresh token is the client's call alone, so the scope that asks for one is
        // decided here rather than inherited from a resource, a challenge, or an earlier grant.
        $offered = $discovered->server->scopesSupported ?? new ScopeSet();
        $scopes = $scopes->without(ScopeSet::OFFLINE_ACCESS);

        if ($this->options->requestOfflineAccess && $offered->contains(ScopeSet::OFFLINE_ACCESS)) {
            $scopes = $scopes->mergeWith(new ScopeSet([ScopeSet::OFFLINE_ACCESS]));
        }

        return $scopes;
    }

    /**
     * The set a grant starts from: a challenge is authoritative for the operation that provoked it, then
     * what the client declared it needs, then the resource's own advertised set. A resource that advertises
     * none leaves the parameter off.
     */
    private function selectBaseline(?WwwAuthenticateChallenge $challenge, ?ScopeSet $advertised): ScopeSet
    {
        // A challenge that carries `scope=""` names nothing, so it steers no better than one that carries
        // no `scope` at all.
        $challenged = ScopeSet::parse($challenge?->readParameter('scope'));

        return match (true) {
            [] !== $challenged->values => $challenged,
            [] !== $this->options->defaultScopes => new ScopeSet($this->options->defaultScopes),
            default => $advertised ?? new ScopeSet(),
        };
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
