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
use Amp\CancelledException;
use Amp\Future;
use Amp\Http\Client\DelegateHttpClient;
use Amp\Sync\LocalSemaphore;
use Amp\Sync\Lock;
use Amp\Sync\Semaphore;
use Nexus\Mcp\Client\Exception\AuthorizationGrantRejectedException;
use Nexus\Mcp\Client\Exception\ClientRegistrationRejectedException;
use Nexus\Mcp\Client\Exception\MalformedAuthorizationResponseException;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\ScopeSet;
use Nexus\Mcp\Core\Auth\WwwAuthenticateChallenge;
use Nexus\Mcp\Core\Exception\McpExceptionInterface;
use Nexus\Mcp\Core\SafeDisplay;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Revolt\EventLoop\FiberLocal;

use function Amp\async;

/**
 * Coordinator for one MCP server's OAuth 2.1 flow.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-flow-steps
 */
final class AuthorizationCoordinator
{
    private const int EXPIRY_LEEWAY_SECONDS = 30;

    private ?DiscoveredResource $discovered = null;
    private ScopeSet $granted;

    /**
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
        private readonly Semaphore $lock = new LocalSemaphore(1),
    ) {
        $this->granted = new ScopeSet();
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

        if ($this->discovered?->server->issuer === $token->issuer && ! self::hasExpired($token)) {
            return $token;
        }

        return $this->runExclusively($cancellation, function () use ($cancellation): ?AccessToken {
            $current = $this->readToken();

            return null === $current ? null : $this->prepareToken($current, $cancellation);
        });
    }

    /**
     * Obtains a token after the MCP server refused the one presented.
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

            if (null !== $this->discovered && null !== $current && $current->value !== $refused?->value) {
                return $current;
            }

            $this->giveUpOnToken();

            return $this->runAuthorization($challenge, new ScopeSet(), $cancellation);
        });
    }

    /**
     * Obtains a token carrying scopes beyond those the presented one held.
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
        /** @var Future<Lock> $pending */
        $pending = async(fn(): Lock => $this->lock->acquire());

        try {
            return $pending->await($cancellation);
        } catch (CancelledException $e) {
            // The abandoned acquisition stays queued and is eventually handed a permit, which must not wait on collection to return.
            $pending->map(static function (Lock $lock): void { $lock->release(); })->ignore();

            throw $e;
        }
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
            $this->registrar->forget($server->issuer);

            throw $e;
        }

        $this->rememberGrant($token);

        $this->logger->info('Authorized {resource} at {issuer}.', [
            'resource' => $this->resource->value,
            'issuer' => SafeDisplay::sanitiseCause($server->issuer),
        ]);

        return $token;
    }

    private function discover(?WwwAuthenticateChallenge $challenge, Cancellation $cancellation): DiscoveredResource
    {
        $cached = $this->discovered;

        if (null !== $cached) {
            return $cached;
        }

        $metadata = $this->discovery->discoverResource($this->resource, $challenge, $cancellation);

        $server = $this->discovery->discoverServer($metadata->authorizationServers[0], $cancellation);
        $discovered = new DiscoveredResource($metadata, $server);
        $this->discovered = $discovered;

        return $discovered;
    }

    /**
     * Makes a held token fit to present, or `null` when the request should be sent bare.
     */
    private function prepareToken(AccessToken $token, Cancellation $cancellation): ?AccessToken
    {
        try {
            $discovered = $this->discover(null, $cancellation);
        } catch (McpExceptionInterface $e) {
            $this->logger->info('The token for {resource} could not be checked against any metadata. {reason}', [
                'resource' => $this->resource->value,
                'reason' => SafeDisplay::sanitiseCause($e->getMessage()),
            ]);

            return null;
        }

        $server = $discovered->server;

        if ($server->issuer !== $token->issuer) {
            $this->logger->info('The token for {resource} was issued by {issuer}, which no longer serves it.', [
                'resource' => $this->resource->value,
                'issuer' => SafeDisplay::sanitiseCause($token->issuer),
            ]);
            $this->granted = new ScopeSet();
            $this->discovered = null;
            $this->tokens->forget($this->resource->value);

            return null;
        }

        if (! self::hasExpired($token)) {
            return $token;
        }

        if ($this->strategy->renewsByFreshGrant()) {
            $this->giveUpOnToken();
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
                'reason' => SafeDisplay::sanitiseCause($e->getMessage()),
            ]);
            $this->giveUpOnToken();

            return null;
        }

        $this->rememberGrant($renewed);

        return $renewed;
    }

    /**
     * Drops the token and the discovery held for the MCP server, keeping the granted scopes.
     */
    private function giveUpOnToken(): void
    {
        $this->granted = $this->readGrantedScopes();
        $this->discovered = null;
        $this->tokens->forget($this->resource->value);
    }

    /**
     * Records what a token was granted, replacing the granted scopes rather than merging into them.
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
        $scopes = $this->selectBaseline($challenge, $discovered->metadata->scopesSupported)
            ->mergeWith($additionalScopes)
            ->mergeWith($this->readGrantedScopes())
        ;

        $offered = $discovered->server->scopesSupported ?? new ScopeSet();
        $scopes = $scopes->without(ScopeSet::OFFLINE_ACCESS);

        if ($this->options->requestOfflineAccess && $offered->contains(ScopeSet::OFFLINE_ACCESS)) {
            $scopes = $scopes->mergeWith(new ScopeSet([ScopeSet::OFFLINE_ACCESS]));
        }

        return $scopes;
    }

    /**
     * The scope set a grant starts from: a challenge first, then the client's declared defaults, then the
     * resource's advertised set.
     */
    private function selectBaseline(?WwwAuthenticateChallenge $challenge, ?ScopeSet $advertised): ScopeSet
    {
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
