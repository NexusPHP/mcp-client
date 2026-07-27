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

use Amp\Sync\LocalSemaphore;
use Nexus\Mcp\Client\Exception\AuthorizationGrantRejectedException;
use Nexus\Mcp\Client\Exception\MalformedAuthorizationResponseException;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\ScopeSet;
use Nexus\Mcp\Core\Auth\WwwAuthenticateChallenge;
use Nexus\Mcp\Core\Exception\McpExceptionInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

use function Amp\Sync\synchronized;

/**
 * Runs the OAuth 2.1 flow end to end for one MCP server: discovery, client registration, the user-agent round
 * trip, and the token exchange, then holds the resulting token for reuse.
 *
 * Everything that writes the token runs one at a time, so concurrent callers put the resource owner in front
 * of at most one consent screen.
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
     * What discovery last found, so a step-up does not repeat it.
     */
    private ?DiscoveredResource $discovered = null;

    /**
     * What the MCP server has granted, kept apart from the token so dropping a spent or refused one does not
     * narrow what the next grant asks for.
     */
    private ScopeSet $granted;

    /**
     * Held for the length of everything that writes the token, so no two callers run a flow at once.
     */
    private LocalSemaphore $lock;

    public function __construct(
        private readonly ResourceIdentifier $resource,
        private readonly MetadataDiscovery $discovery,
        private readonly ClientRegistrar $registrar,
        private readonly TokenEndpoint $tokenEndpoint,
        private readonly UserAuthorizationInterface $userAuthorization,
        private readonly TokenStoreInterface $tokens,
        private readonly AuthorizationOptions $options,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {
        $this->granted = new ScopeSet();
        $this->lock = new LocalSemaphore(1);
    }

    /**
     * The token already held, renewed when it is spent, or `null` when the client has none it can still use.
     */
    public function fetchToken(): ?AccessToken
    {
        $token = $this->readToken();

        if (null === $token || ! self::hasExpired($token)) {
            return $token;
        }

        return synchronized($this->lock, function () use ($token): ?AccessToken {
            $current = $this->readToken();

            // Another caller may have renewed it while this one waited its turn.
            if (null === $current || $current->value !== $token->value) {
                return $current;
            }

            return $this->renew($token);
        });
    }

    /**
     * Obtains a token after the MCP server refused the one presented. What is held is dropped first, so the
     * next grant can follow the resource to a different authorization server.
     *
     * @param ?AccessToken $refused The token the MCP server refused, or `null` when the request carried none
     */
    public function reauthorize(?AccessToken $refused, ?WwwAuthenticateChallenge $challenge): AccessToken
    {
        return synchronized($this->lock, function () use ($refused, $challenge): AccessToken {
            $current = $this->readToken();

            // Another caller may have replaced the refused token while this one waited its turn, and what it
            // obtained serves this one too.
            if (null !== $current && $current->value !== $refused?->value) {
                return $current;
            }

            $this->giveUpOnToken();

            return $this->runAuthorization($challenge, new ScopeSet());
        });
    }

    /**
     * Obtains a token carrying scopes beyond those the presented one held, after the MCP server answered that
     * they were insufficient.
     *
     * @param ?AccessToken $presented        The token the MCP server found too narrow, or `null` when the request carried none
     * @param ScopeSet     $additionalScopes Scopes the insufficient-scope challenges asked for, accumulated onto the set already granted
     */
    public function upgradeScopes(
        ?AccessToken $presented,
        ScopeSet $additionalScopes,
        ?WwwAuthenticateChallenge $challenge,
    ): AccessToken {
        return synchronized($this->lock, function () use ($presented, $additionalScopes, $challenge): AccessToken {
            $current = $this->readToken();

            // A token another caller obtained while this one waited its turn serves it too, but only once it
            // covers what this one was refused for.
            if (null !== $current
                && $current->value !== $presented?->value
                && new ScopeSet($current->scopes)->containsAll($additionalScopes)
            ) {
                return $current;
            }

            return $this->runAuthorization($challenge, $additionalScopes);
        });
    }

    /**
     * Everything the MCP server has granted this client, whether or not a token still holds it.
     */
    public function readGrantedScopes(): ScopeSet
    {
        $token = $this->readToken();

        return null === $token ? $this->granted : $this->granted->mergeWith(new ScopeSet($token->scopes));
    }

    private function readToken(): ?AccessToken
    {
        return $this->tokens->read($this->resource->value);
    }

    private function runAuthorization(?WwwAuthenticateChallenge $challenge, ScopeSet $additionalScopes): AccessToken
    {
        $discovered = $this->discover($challenge);
        $server = $discovered->server;

        $registration = $this->registrar->resolve($server, $this->options, $this->resource);
        $scopes = $this->selectScopes($challenge, $discovered, $additionalScopes);

        $redirect = AuthorizationRequest::build(
            $server,
            $registration->clientId,
            $this->options->redirectUri,
            $this->resource,
            $scopes,
        );

        $code = AuthorizationResponse::readCode($redirect, $this->userAuthorization->authorize($redirect));

        $token = $this->tokenEndpoint->exchangeCode(
            $server,
            $registration,
            $redirect,
            $code,
            $this->options->redirectUri,
            $this->resource,
        );
        $this->rememberGrant($token);

        $this->logger->info('Authorized {resource} at {issuer}.', [
            'resource' => $this->resource->value,
            'issuer' => $server->issuer,
        ]);

        return $token;
    }

    /**
     * Reads the metadata of the MCP server and of the authorization server it names, reusing what an earlier
     * round already found.
     */
    private function discover(?WwwAuthenticateChallenge $challenge): DiscoveredResource
    {
        $cached = $this->discovered;

        if (null !== $cached) {
            return $cached;
        }

        $metadata = $this->discovery->discoverResource($this->resource, $challenge);

        // A resource may name several authorization servers and the choice is the client's. Taking the
        // first honours the order the resource published them in.
        $server = $this->discovery->discoverServer($metadata->authorizationServers[0], $this->resource);
        $discovered = new DiscoveredResource($metadata, $server);
        $this->discovered = $discovered;

        return $discovered;
    }

    private function renew(AccessToken $token): ?AccessToken
    {
        if (null === $token->refreshToken) {
            $this->giveUpOnToken();

            return null;
        }

        try {
            $server = $this->discover(null)->server;
        } catch (McpExceptionInterface $e) {
            // Reaching no metadata says nothing about the token. Answering `null` sends the request bare,
            // and the challenge it draws is what re-authorization needs anyway.
            $this->logger->info('Renewing the token for {resource} found no metadata to renew it against. {reason}', [
                'resource' => $this->resource->value,
                'reason' => $e->getMessage(),
            ]);

            return null;
        }

        // A token minted by a server the resource has since moved off cannot be renewed at the new one, and
        // must not be presented to it either. Its scopes go with it: they were granted elsewhere.
        if ($server->issuer !== $token->issuer) {
            $this->logger->info('The token for {resource} was issued by {issuer}, which no longer serves it.', [
                'resource' => $this->resource->value,
                'issuer' => $token->issuer,
            ]);
            $this->granted = new ScopeSet();
            $this->discovered = null;
            $this->tokens->forget($this->resource->value);

            return null;
        }

        try {
            $renewed = $this->tokenEndpoint->refresh(
                $server,
                $this->registrar->resolve($server, $this->options, $this->resource),
                $token,
                $this->resource,
            );
        } catch (AuthorizationGrantRejectedException|MalformedAuthorizationResponseException $e) {
            $this->logger->info('The refresh token for {resource} could not be redeemed, so a new authorization is needed. {reason}', [
                'resource' => $this->resource->value,
                'reason' => $e->getMessage(),
            ]);
            $this->giveUpOnToken();

            return null;
        }

        $this->rememberGrant($renewed);

        return $renewed;
    }

    /**
     * Drops what is held for the MCP server, keeping what it had granted so re-authorizing asks for it again
     * rather than narrowing. Discovery goes with it, so the next grant can follow the resource to a different
     * authorization server.
     */
    private function giveUpOnToken(): void
    {
        $this->granted = $this->readGrantedScopes();
        $this->discovered = null;
        $this->tokens->forget($this->resource->value);
    }

    /**
     * Records what a token was granted, then stores it.
     */
    private function rememberGrant(AccessToken $token): void
    {
        $this->granted = $this->readGrantedScopes()->mergeWith(new ScopeSet($token->scopes));
        $this->tokens->write($this->resource->value, $token);
    }

    private function selectScopes(
        ?WwwAuthenticateChallenge $challenge,
        DiscoveredResource $discovered,
        ScopeSet $additionalScopes,
    ): ScopeSet {
        // Asking for only the challenged scopes would drop permissions other operations rely on.
        $scopes = $this->selectBaseline($challenge, $discovered->metadata->scopesSupported)
            ->mergeWith($additionalScopes)
            ->mergeWith($this->readGrantedScopes())
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

    private static function hasExpired(AccessToken $token): bool
    {
        return null !== $token->expiresAt && $token->expiresAt <= time() + self::EXPIRY_LEEWAY_SECONDS;
    }
}
