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

use Amp\ByteStream\StreamException;
use Amp\Cancellation;
use Amp\Http\Client\DelegateHttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\HttpException;
use Amp\Http\Client\Interceptor\FollowRedirects;
use Amp\Http\Client\Interceptor\TooManyRedirectsException;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
use Amp\Sync\LocalSemaphore;
use Amp\Sync\Semaphore;
use Nexus\Assert\Assert;
use Nexus\Mcp\Client\Exception\InsufficientScopeException;
use Nexus\Mcp\Client\Exception\RedirectRefusedException;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\ScopeSet;
use Nexus\Mcp\Core\Auth\WwwAuthenticateChallenge;
use Nexus\Mcp\Core\Http\HttpStatus;
use Nexus\Mcp\Core\SafeDisplay;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * HTTP client decorator that presents an OAuth 2.1 bearer token to a protected MCP server.
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#access-token-usage
 */
final class AuthorizedHttpClient implements DelegateHttpClient
{
    private const string INSUFFICIENT_SCOPE = 'insufficient_scope';
    private const int MAX_CHALLENGE_BODY_BYTES = 8_192;
    private const int MAX_REDIRECTS = 10;

    private readonly ResourceIdentifier $resource;
    private readonly AuthorizationCoordinator $coordinator;
    private readonly DelegateHttpClient $client;
    private readonly DelegateHttpClient $sealedClient;

    /**
     * @param string                                $resource          Absolute URL of the MCP endpoint this client talks to
     * @param null|UserAuthorizationInterface       $userAuthorization Puts the resource owner in front of the authorization server on the authorization-code grant. `null` when a grant strategy runs instead
     * @param HttpClientBuilder                     $clientBuilder     Builds the inner clients. Credentialed traffic runs on a derived client that never follows a redirect, so a hop can be refused before the credential travels
     * @param null|TokenStoreInterface              $tokens            Defaults to a store that lives only as long as the process
     * @param null|ClientRegistrationStoreInterface $registrations     Defaults to a store that lives only as long as the process
     * @param null|GrantStrategyInterface           $grantStrategy     An unattended grant run in place of the authorization-code round trip
     * @param null|Semaphore                        $lock              Serialises grants and renewals, defaulting to one that spans this process only
     */
    public function __construct(
        string $resource,
        private readonly AuthorizationOptions $options,
        ?UserAuthorizationInterface $userAuthorization,
        HttpClientBuilder $clientBuilder,
        ?TokenStoreInterface $tokens = null,
        ?ClientRegistrationStoreInterface $registrations = null,
        private readonly LoggerInterface $logger = new NullLogger(),
        ?GrantStrategyInterface $grantStrategy = null,
        ?Semaphore $lock = null,
    ) {
        if (null !== $userAuthorization) {
            Assert::that($grantStrategy)->isNull('A user authorization and a grant strategy were both given, and the client can run only one.');
            Assert::that($options->redirectUri)->isNonEmptyString('A user authorization needs a redirect URI, and the authorization options carry none.');
            $strategy = new AuthorizationCodeGrantStrategy($userAuthorization);
        } else {
            Assert::that($grantStrategy)->isInstanceOf(GrantStrategyInterface::class, 'The client needs a user authorization or a grant strategy to obtain tokens, and neither was given.');
            $strategy = $grantStrategy;
        }

        $this->resource = new ResourceIdentifier($resource);

        $this->client = $clientBuilder->build();
        $this->sealedClient = $clientBuilder->followRedirects(0)->build();

        $secureEndpoint = new SecureEndpoint($this->options->allowInsecureLoopback);
        $this->coordinator = new AuthorizationCoordinator(
            $this->resource,
            new MetadataDiscovery($this->sealedClient, $this->options->timeout, $secureEndpoint),
            new ClientRegistrar(
                $this->sealedClient,
                $registrations ?? new InMemoryClientRegistrationStore(),
                $this->options->timeout,
                $secureEndpoint,
            ),
            new TokenEndpoint($this->sealedClient, $this->options->timeout, $secureEndpoint),
            $this->sealedClient,
            $strategy,
            $tokens ?? new InMemoryTokenStore(),
            $this->options,
            $this->logger,
            $lock ?? new LocalSemaphore(1),
        );
    }

    #[\Override]
    public function request(Request $request, Cancellation $cancellation): Response
    {
        $additionalScopes = new ScopeSet();
        $scopeUpgrades = 0;
        $reauthorized = false;

        $bearsToken = $this->resource->covers((string) $request->getUri());

        while (true) {
            $token = $bearsToken ? $this->coordinator->fetchToken($cancellation) : null;
            $attempt = $this->authorizeRequest($request, $token);
            $response = $bearsToken
                ? $this->followWithinResource($attempt, $cancellation)
                : $this->client->request($attempt, $cancellation);

            if (! $bearsToken) {
                return $response;
            }

            $status = $response->getStatus();

            if (HttpStatus::Unauthorized->value !== $status && HttpStatus::Forbidden->value !== $status) {
                return $response;
            }

            $challenge = $this->readChallenge($response);

            if (HttpStatus::Forbidden->value === $status) {
                if (null === $challenge || self::INSUFFICIENT_SCOPE !== $challenge->readParameter('error')) {
                    return $response;
                }

                $declaredScope = $challenge->readParameter('scope');
                $challenged = ScopeSet::parse($declaredScope);

                if (InsufficientScopePolicy::Fail === $this->options->onInsufficientScope) {
                    $this->reportInsufficientScope($response, $challenged, $cancellation, null !== $declaredScope);
                }

                if ($scopeUpgrades >= $this->options->maxScopeUpgrades) {
                    $this->logger->warning('Giving up on {resource} after {attempts} scope upgrades.', [
                        'resource' => $this->resource->value,
                        'attempts' => $scopeUpgrades,
                    ]);

                    $this->reportInsufficientScope($response, $additionalScopes->mergeWith($challenged), $cancellation, null !== $declaredScope);
                }

                if ((new ScopeSet($token->scopes ?? []))->containsAll($challenged)) {
                    $this->logger->warning('The scope challenge from {resource} names {scopes}.', [
                        'resource' => $this->resource->value,
                        'scopes' => SafeDisplay::sanitiseCause(
                            $challenged->toParameter() ?? $this->describeUnusableChallenge($declaredScope),
                        ),
                    ]);

                    $this->reportInsufficientScope($response, $challenged, $cancellation, null !== $declaredScope);
                }

                ++$scopeUpgrades;
                $additionalScopes = $additionalScopes->mergeWith($challenged);
                $this->drain($response, $cancellation);
                $this->coordinator->upgradeScopes($token, $additionalScopes, $challenge, $cancellation);

                continue;
            }

            if ($reauthorized) {
                return $response;
            }

            $reauthorized = true;
            $this->drain($response, $cancellation);
            $this->coordinator->reauthorize($token, $challenge, $cancellation);
        }
    }

    /**
     * @throws RedirectRefusedException
     */
    private function followWithinResource(Request $request, Cancellation $cancellation): Response
    {
        $from = (string) $request->getUri();
        $previous = null;
        $response = null;

        for ($hop = 0; $hop <= self::MAX_REDIRECTS; ++$hop) {
            $response = $this->sealedClient->request($request, $cancellation);
            $response->setPreviousResponse($previous);
            $location = $this->readRedirectTarget($response, $request);

            if (null === $location) {
                return $response;
            }

            if (! $this->resource->covers($location)) {
                $this->drain($response, $cancellation);

                throw new RedirectRefusedException($from, $location);
            }

            $this->drain($response, $cancellation);
            $previous = $response;
            $request = $this->cloneForRedirect($request, $location);
        }

        \assert($response instanceof Response);

        throw new TooManyRedirectsException($response);
    }

    private function readRedirectTarget(Response $response, Request $request): ?string
    {
        $status = $response->getStatus();

        if (! \in_array($status, [301, 302, 303, 307, 308], true)) {
            return null;
        }

        if ($request->getMethod() !== 'GET' && \in_array($status, [307, 308], true)) {
            return null;
        }

        $locations = $response->getHeaderArray('location');

        if (\count($locations) !== 1) {
            return null;
        }

        $location = $locations[0];

        try {
            $target = new Request($location);
        } catch (\Exception) {
            return null;
        }

        return (string) FollowRedirects::resolve($request->getUri(), $target->getUri());
    }

    private function cloneForRedirect(Request $request, string $location): Request
    {
        $redirected = clone $request;
        $redirected->setUri($location);
        $redirected->setMethod('GET');
        $redirected->removeHeader('transfer-encoding');
        $redirected->removeHeader('content-length');
        $redirected->removeHeader('content-type');

        return $redirected;
    }

    /**
     * @return non-empty-string
     */
    private function describeUnusableChallenge(?string $declaredScope): string
    {
        return null === $declaredScope ? 'no scope at all' : 'only scopes that are not RFC 6749 scope-tokens';
    }

    private function reportInsufficientScope(Response $response, ScopeSet $challenged, Cancellation $cancellation, bool $named): never
    {
        $this->drain($response, $cancellation);

        throw new InsufficientScopeException($challenged->values, $named);
    }

    private function drain(Response $response, Cancellation $cancellation): void
    {
        try {
            $response->getBody()->buffer($cancellation, limit: self::MAX_CHALLENGE_BODY_BYTES);
        } catch (HttpException|StreamException) {
            // Losing a challenge body is no reason to abandon the recovery it asked for, where a cancellation propagates instead.
        }
    }

    private function authorizeRequest(Request $request, ?AccessToken $token): Request
    {
        // The request is cloned per attempt so a retry never carries the header a spent token set.
        $attempt = clone $request;

        if (null !== $token) {
            $attempt->setHeader('Authorization', \sprintf('%s %s', WwwAuthenticateChallenge::BEARER_SCHEME, $token->value));
        }

        return $attempt;
    }

    private function readChallenge(Response $response): ?WwwAuthenticateChallenge
    {
        $header = $response->getHeader('WWW-Authenticate');

        return null === $header ? null : WwwAuthenticateChallenge::findBearer($header);
    }
}
