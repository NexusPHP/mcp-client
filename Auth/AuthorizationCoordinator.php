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
use Amp\Future;
use Amp\Http\Client\DelegateHttpClient;
use Amp\Sync\LocalSemaphore;
use Amp\Sync\Lock;
use Nexus\Mcp\Client\Exception\AuthorizationGrantRejectedException;
use Nexus\Mcp\Client\Exception\ClientRegistrationRejectedException;
use Nexus\Mcp\Client\Exception\MalformedAuthorizationResponseException;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\ScopeSet;
use Nexus\Mcp\Core\Auth\WwwAuthenticateChallenge;
use Nexus\Mcp\Core\Exception\McpExceptionInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Revolt\EventLoop\FiberLocal;

use function Amp\async;

/**
 * Runs the OAuth 2.1 flow end to end for one MCP server: discovery, the grant the configured strategy runs,
 * and holding the resulting token for reuse.
 *
 * Everything that writes the token runs one at a time, so concurrent callers put the resource owner in front
 * of at most one consent screen.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-flow-steps
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
     * What the most recent grant granted, kept apart from the token so dropping a spent or refused one does
     * not narrow what the next grant asks for.
     */
    private ScopeSet $granted;

    /**
     * Held for the length of everything that writes the token, so no two callers run a flow at once.
     */
    private LocalSemaphore $lock;

    /**
     * Whether the fiber running this call already holds the lock.
     *
     * @var FiberLocal<bool>
     */
    private FiberLocal $reentrant;

    public function __construct(
        private readonly ResourceIdentifier $resource,
        private readonly MetadataDiscovery $discovery,
        private readonly ClientRegistrar $registrar,
        private readonly TokenEndpoint $tokenEndpoint,
        private readonly DelegateHttpClient $httpClient,
        private readonly GrantStrategyInterface $strategy,
        private readonly TokenStoreInterface $tokens,
        private readonly AuthorizationOptions $options,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {
        $this->granted = new ScopeSet();
        $this->lock = new LocalSemaphore(1);
        $this->reentrant = new FiberLocal(static fn(): bool => false);
    }

    /**
     * The token already held, renewed when it is spent, or `null` when the client has none it can still use.
     */
    public function fetchToken(Cancellation $cancellation): ?AccessToken
    {
        $token = $this->readToken();

        if (null === $token) {
            return null;
        }

        // A token read back from a store may have been minted by a server the resource has since moved off,
        // and the spec forbids presenting it to the new one. A store shared with another process can hand
        // this one a token discovery never saw, so the issuer is compared here and not once at the grant.
        if ($this->discovered?->server->issuer === $token->issuer && ! self::hasExpired($token)) {
            return $token;
        }

        return $this->runExclusively($cancellation, function () use ($cancellation): ?AccessToken {
            // Another caller may have replaced it while this one waited its turn, and what it obtained is
            // held to the same checks rather than trusted for having arrived first.
            $current = $this->readToken();

            return null === $current ? null : $this->prepareToken($current, $cancellation);
        });
    }

    /**
     * Obtains a token after the MCP server refused the one presented. What is held is dropped first, so the
     * next grant can follow the resource to a different authorization server.
     *
     * @param null|AccessToken $refused The token the MCP server refused, or `null` when the request carried none
     */
    public function reauthorize(
        ?AccessToken $refused,
        ?WwwAuthenticateChallenge $challenge,
        Cancellation $cancellation,
    ): AccessToken {
        return $this->runExclusively($cancellation, function () use ($refused, $challenge, $cancellation): AccessToken {
            $current = $this->readToken();

            // Another caller may have replaced the refused token while this one waited its turn, and what it
            // obtained serves this one too. A token held while discovery has never succeeded is not that: it
            // was never presented, and this challenge is the first thing that can say where to check it.
            if (null !== $this->discovered && null !== $current && $current->value !== $refused?->value) {
                return $current;
            }

            $this->giveUpOnToken();

            return $this->runAuthorization($challenge, new ScopeSet(), $cancellation);
        });
    }

    /**
     * Obtains a token carrying scopes beyond those the presented one held, after the MCP server answered that
     * they were insufficient.
     *
     * @param null|AccessToken $presented        The token the MCP server found too narrow, or `null` when the request carried none
     * @param ScopeSet         $additionalScopes Scopes the insufficient-scope challenges asked for, accumulated onto the set already granted
     */
    public function upgradeScopes(
        ?AccessToken $presented,
        ScopeSet $additionalScopes,
        ?WwwAuthenticateChallenge $challenge,
        Cancellation $cancellation,
    ): AccessToken {
        return $this->runExclusively($cancellation, function () use ($presented, $additionalScopes, $challenge, $cancellation): AccessToken {
            $current = $this->readToken();

            // A token another caller obtained while this one waited its turn serves it too, but only once it
            // covers what this one was refused for. A token held while discovery has never succeeded is not
            // that: it was never checked against the resource, so it cannot stand in for a grant.
            if (null !== $this->discovered
                && null !== $current
                && $current->value !== $presented?->value
                && (new ScopeSet($current->scopes))->containsAll($additionalScopes)
            ) {
                return $current;
            }

            return $this->runAuthorization($challenge, $additionalScopes, $cancellation);
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

    /**
     * Runs an operation with the lock held, waiting for it no longer than the caller's own cancellation.
     *
     * @template T
     *
     * @param \Closure(): T $operation
     *
     * @return T
     */
    private function runExclusively(Cancellation $cancellation, \Closure $operation): mixed
    {
        if ($this->reentrant->get()) {
            return $operation();
        }

        $lock = $this->acquireLock($cancellation);
        $this->reentrant->set(true);

        try {
            return $operation();
        } finally {
            $this->reentrant->set(false);
            $lock->release();
        }
    }

    private function acquireLock(Cancellation $cancellation): Lock
    {
        // A queued waiter cannot be withdrawn from the semaphore, so one that gives up keeps its place in
        // line. The lock it is eventually handed frees itself once nothing holds it, which is what lets the
        // caller behind it through.
        /** @var Future<Lock> $pending */
        $pending = async(fn(): Lock => $this->lock->acquire());

        return $pending->await($cancellation);
    }

    private function runAuthorization(
        ?WwwAuthenticateChallenge $challenge,
        ScopeSet $additionalScopes,
        Cancellation $cancellation,
    ): AccessToken {
        $discovered = $this->discover($challenge, $cancellation);
        $server = $discovered->server;

        $context = new GrantContext(
            $discovered,
            $this->resource,
            $this->selectScopes($challenge, $discovered, $additionalScopes),
            $this->options,
            $this->httpClient,
            $this->logger,
            $this->registrar,
            $this->tokenEndpoint,
        );

        try {
            $token = $this->strategy->grant($context, $cancellation);
        } catch (ClientRegistrationRejectedException $e) {
            // The grant is bound to the identifier that is spent, so it cannot be salvaged. Dropping the
            // registration is what stops the next one from presenting it again.
            $this->registrar->forget($server->issuer);

            throw $e;
        }

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
    private function discover(?WwwAuthenticateChallenge $challenge, Cancellation $cancellation): DiscoveredResource
    {
        $cached = $this->discovered;

        if (null !== $cached) {
            return $cached;
        }

        $metadata = $this->discovery->discoverResource($this->resource, $challenge, $cancellation);

        // A resource may name several authorization servers and the choice is the client's. Taking the
        // first honours the order the resource published them in.
        $server = $this->discovery->discoverServer($metadata->authorizationServers[0], $cancellation);
        $discovered = new DiscoveredResource($metadata, $server);
        $this->discovered = $discovered;

        return $discovered;
    }

    /**
     * Makes a held token fit to present: its issuer is confirmed to be the one the resource still names, and
     * a spent one is renewed. Answers `null` when neither holds, which sends the request bare.
     */
    private function prepareToken(AccessToken $token, Cancellation $cancellation): ?AccessToken
    {
        try {
            $discovered = $this->discover(null, $cancellation);
        } catch (McpExceptionInterface $e) {
            // Reaching no metadata says nothing about the token. Answering `null` sends the request bare,
            // and the challenge it draws is what re-authorization needs anyway.
            $this->logger->info('The token for {resource} could not be checked against any metadata. {reason}', [
                'resource' => $this->resource->value,
                'reason' => $e->getMessage(),
            ]);

            return null;
        }

        $server = $discovered->server;

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

        if (! self::hasExpired($token)) {
            return $token;
        }

        // An unattended grant is renewed here and now, whether or not a refresh token came with it: the
        // registration a refresh resolves is never the one such a strategy authenticates with. The lock is
        // already held, so the rerun cannot race another caller.
        if ($this->strategy->renewsByFreshGrant()) {
            $this->giveUpOnToken();
            // The grant reuses the discovery that just confirmed this token's issuer. Discovering again
            // without a challenge cannot reach a resource document that only a challenge names.
            $this->discovered = $discovered;

            return $this->runAuthorization(null, new ScopeSet(), $cancellation);
        }

        if (null === $token->refreshToken) {
            $this->giveUpOnToken();

            return null;
        }

        try {
            $renewed = $this->tokenEndpoint->refresh(
                $server,
                $this->registrar->resolve($server, $this->options, $cancellation),
                $token,
                $this->resource,
                $cancellation,
            );
        } catch (AuthorizationGrantRejectedException|ClientRegistrationRejectedException|MalformedAuthorizationResponseException $e) {
            if ($e instanceof ClientRegistrationRejectedException) {
                $this->registrar->forget($server->issuer);
            }

            $this->logger->info('The token for {resource} could not be renewed, so a new authorization is needed. {reason}', [
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
     * Records what a token was granted, then stores it. A grant that omits a scope the authorization server
     * had granted earlier is what withdraws it, so this replaces the set rather than adding to it.
     */
    private function rememberGrant(AccessToken $token): void
    {
        $this->granted = new ScopeSet($token->scopes);
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
