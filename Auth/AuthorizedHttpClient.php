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
use Nexus\Assert\Assert;
use Nexus\Mcp\Client\Exception\InsufficientScopeException;
use Nexus\Mcp\Client\Exception\RedirectRefusedException;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\ScopeSet;
use Nexus\Mcp\Core\Auth\WwwAuthenticateChallenge;
use Nexus\Mcp\Core\Http\HttpStatus;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * HTTP client decorator that presents an OAuth 2.1 bearer token to a protected MCP server, obtains one when
 * challenged, and steps its scopes up when the server says they are insufficient.
 *
 * Hand it to `StreamableHttpClientTransport` in place of the default client.
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#access-token-usage
 */
final class AuthorizedHttpClient implements DelegateHttpClient
{
    private const string INSUFFICIENT_SCOPE = 'insufficient_scope';

    /**
     * Bytes of a challenge body drained before the connection carrying it is given up on instead.
     */
    private const int MAX_CHALLENGE_BODY_BYTES = 8_192;

    /**
     * Matches the redirect budget `HttpClientBuilder::buildDefault()` applies to uncredentialed traffic.
     */
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

        // Metadata is public, so following a redirect to it leaks nothing. Everything that carries a
        // credential runs on the sealed client instead, which hands a 3xx back rather than replaying the
        // request against wherever it points.
        $this->client = $clientBuilder->build();
        $this->sealedClient = $clientBuilder->followRedirects(0)->build();

        $this->coordinator = new AuthorizationCoordinator(
            $this->resource,
            new MetadataDiscovery($this->client, $this->options->timeout, $this->options->allowInsecureLoopback),
            new ClientRegistrar(
                $this->sealedClient,
                $registrations ?? new InMemoryClientRegistrationStore(),
                $this->options->timeout,
                $this->options->allowInsecureLoopback,
            ),
            new TokenEndpoint($this->sealedClient, $this->options->timeout, $this->options->allowInsecureLoopback),
            $this->sealedClient,
            $strategy,
            $tokens ?? new InMemoryTokenStore(),
            $this->options,
            $this->logger,
        );
    }

    #[\Override]
    public function request(Request $request, Cancellation $cancellation): Response
    {
        $additionalScopes = new ScopeSet();
        $scopeUpgrades = 0;
        $reauthorized = false;

        // A token is minted for one MCP server, and a caller may hand this decorator a request aimed
        // anywhere, so the header goes on only where the token belongs.
        $bearsToken = $this->resource->sharesOriginWith((string) $request->getUri());

        while (true) {
            $token = $bearsToken ? $this->coordinator->fetchToken($cancellation) : null;
            $attempt = self::authorizeRequest($request, $token);
            // Control of the hops belongs to this origin, not to whether a token happened to be ready.
            // The bare first request carries whatever headers the caller set, and the challenge it comes
            // back with steers the grant, so both need the same seal.
            $response = $bearsToken
                ? $this->followWithinOrigin($attempt, $cancellation)
                : $this->client->request($attempt, $cancellation);

            if (! $bearsToken) {
                // A challenge from anywhere but this MCP server steers nothing here. Its scopes would reach
                // the consent screen at the real authorization server, and the token that consent granted
                // would replace the one held for this one.
                return $response;
            }

            $status = $response->getStatus();

            if (HttpStatus::Unauthorized->value !== $status && HttpStatus::Forbidden->value !== $status) {
                return $response;
            }

            $challenge = self::readChallenge($response);

            if (HttpStatus::Forbidden->value === $status) {
                // Only an insufficient-scope challenge is recoverable. Every other 403 is the server's answer.
                if (null === $challenge || self::INSUFFICIENT_SCOPE !== $challenge->readParameter('error')) {
                    return $response;
                }

                $challenged = ScopeSet::parse($challenge->readParameter('scope'));

                // The caller asked to be told rather than asked, so neither the retry budget nor whether
                // another round would help has any bearing on what happens next.
                if (InsufficientScopePolicy::Fail === $this->options->onInsufficientScope) {
                    self::report($response, $challenged, $cancellation);
                }

                if ($scopeUpgrades >= $this->options->maxScopeUpgrades) {
                    $this->logger->warning('Giving up on {resource} after {attempts} scope upgrades.', [
                        'resource' => $this->resource->value,
                        'attempts' => $scopeUpgrades,
                    ]);

                    // The union across every round is what a fresh grant would actually need. Reporting
                    // only the last challenge would send a re-requesting caller after a narrower token.
                    self::report($response, $additionalScopes->mergeWith($challenged), $cancellation);
                }

                // Granting again would produce the same token and the same answer, so the only thing another
                // round buys is a second consent screen. What settles that is the token this attempt
                // presented: what the client was granted at some point says nothing about what it holds now.
                if ((new ScopeSet($token->scopes ?? []))->containsAll($challenged)) {
                    $this->logger->warning('The scope challenge from {resource} names {scopes}.', [
                        'resource' => $this->resource->value,
                        'scopes' => $challenged->toParameter() ?? 'no scope at all',
                    ]);

                    self::report($response, $challenged, $cancellation);
                }

                ++$scopeUpgrades;
                $additionalScopes = $additionalScopes->mergeWith($challenged);
                self::drain($response, $cancellation);
                $this->coordinator->upgradeScopes($token, $additionalScopes, $challenge, $cancellation);

                continue;
            }

            // A second challenge to a token just obtained is the server's answer, not a stale token.
            if ($reauthorized) {
                return $response;
            }

            $reauthorized = true;
            self::drain($response, $cancellation);
            $this->coordinator->reauthorize($token, $challenge, $cancellation);
        }
    }

    /**
     * Sends a credentialed request, resolving redirects here rather than letting the client replay the
     * credential wherever a `Location` points. An origin carries its scheme, so a downgrade to cleartext is
     * a hop off origin like any other and is refused before anything travels.
     *
     * @throws RedirectRefusedException
     */
    private function followWithinOrigin(Request $request, Cancellation $cancellation): Response
    {
        $origin = (string) $request->getUri();
        $previous = null;
        $response = null;

        for ($hop = 0; $hop <= self::MAX_REDIRECTS; ++$hop) {
            $response = $this->sealedClient->request($request, $cancellation);
            $response->setPreviousResponse($previous);
            $location = self::readRedirectTarget($response, $request);

            if (null === $location) {
                return $response;
            }

            if (! $this->resource->sharesOriginWith($location)) {
                self::drain($response, $cancellation);

                throw new RedirectRefusedException($origin, $location);
            }

            self::drain($response, $cancellation);
            $previous = $response;
            $request = self::cloneForRedirect($request, $location);
        }

        \assert($response instanceof Response);

        throw new TooManyRedirectsException($response);
    }

    /**
     * Resolves a redirect answer's target against the request that produced it, or `null` when the answer
     * is not a redirect.
     */
    private static function readRedirectTarget(Response $response, Request $request): ?string
    {
        $status = $response->getStatus();

        // The rules `FollowRedirects` applies, so sealing the client changes which client resolves a hop
        // rather than which answers count as one. A 307 or 308 preserves the method, which the spec forbids
        // replaying without asking, so neither is followed for anything but a GET.
        if (! \in_array($status, [301, 302, 303, 307, 308], true)) {
            return null;
        }

        if ($request->getMethod() !== 'GET' && \in_array($status, [307, 308], true)) {
            return null;
        }

        if (\count($response->getHeaderArray('location')) !== 1) {
            return null;
        }

        $location = $response->getHeader('location');
        \assert(null !== $location);

        try {
            // `Request` parses the target with the same URI implementation the client uses, and its own
            // resolver settles a relative one, so a sealed hop lands where an unsealed one would.
            $target = new Request($location);
        } catch (\Exception) {
            return null;
        }

        return (string) FollowRedirects::resolve($request->getUri(), $target->getUri());
    }

    /**
     * Rewrites a request for its redirect target: the hop is a GET carrying none of the body framing the
     * original had. No `Referer` is added, where the client's own follower would.
     */
    private static function cloneForRedirect(Request $request, string $location): Request
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
     * Drains the unwinnable challenge and reports it to the caller.
     */
    private static function report(Response $response, ScopeSet $challenged, Cancellation $cancellation): never
    {
        self::drain($response, $cancellation);

        throw new InsufficientScopeException($challenged->values);
    }

    /**
     * Reads a challenge body to its end so its connection returns to the pool. An undrained body cancels
     * instead, which tears the connection down for the whole of the authorization flow, user included.
     */
    private static function drain(Response $response, Cancellation $cancellation): void
    {
        try {
            $response->getBody()->buffer($cancellation, limit: self::MAX_CHALLENGE_BODY_BYTES);
        } catch (HttpException|StreamException) {
            // Losing the body of a challenge is never a reason to abandon the recovery it asked for. A
            // cancellation propagates instead: the caller stopped waiting, and the recovery goes with it.
        }
    }

    private static function authorizeRequest(Request $request, ?AccessToken $token): Request
    {
        // The request is cloned per attempt so a retry never carries the header a spent token set.
        $attempt = clone $request;

        if (null !== $token) {
            $attempt->setHeader('Authorization', \sprintf('%s %s', WwwAuthenticateChallenge::BEARER_SCHEME, $token->value));
        }

        return $attempt;
    }

    private static function readChallenge(Response $response): ?WwwAuthenticateChallenge
    {
        $header = $response->getHeader('WWW-Authenticate');

        return null === $header ? null : WwwAuthenticateChallenge::findBearer($header);
    }
}
