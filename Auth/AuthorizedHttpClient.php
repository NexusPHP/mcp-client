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
use Amp\Http\Client\HttpException;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
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
 * @see https://modelcontextprotocol.io/specification/draft/basic/authorization#access-token-usage
 */
final class AuthorizedHttpClient implements DelegateHttpClient
{
    private const string INSUFFICIENT_SCOPE = 'insufficient_scope';

    /**
     * Bytes of a challenge body drained before the connection carrying it is given up on instead.
     */
    private const int MAX_CHALLENGE_BODY_BYTES = 8192;

    private readonly ResourceIdentifier $resource;
    private readonly DelegateHttpClient $client;
    private readonly AuthorizationCoordinator $coordinator;

    /**
     * @param string                            $resource      Absolute URL of the MCP endpoint this client talks to
     * @param DelegateHttpClient                $client        Inner client, which carries the authorization traffic as well as the MCP traffic
     * @param ?TokenStoreInterface              $tokens        Defaults to a store that lives only as long as the process
     * @param ?ClientRegistrationStoreInterface $registrations Defaults to a store that lives only as long as the process
     */
    public function __construct(
        string $resource,
        private readonly AuthorizationOptions $options,
        UserAuthorizationInterface $userAuthorization,
        DelegateHttpClient $client,
        ?TokenStoreInterface $tokens = null,
        ?ClientRegistrationStoreInterface $registrations = null,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {
        $this->resource = new ResourceIdentifier($resource);
        $this->client = $client;
        $this->coordinator = new AuthorizationCoordinator(
            $this->resource,
            new MetadataDiscovery($this->client, $this->options->timeout, $this->options->allowInsecureLoopback),
            new ClientRegistrar($this->client, $registrations ?? new InMemoryClientRegistrationStore(), $this->options->timeout, $this->options->allowInsecureLoopback),
            new TokenEndpoint($this->client, $this->options->timeout, $this->options->allowInsecureLoopback),
            $userAuthorization,
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
            $response = $this->client->request($attempt, $cancellation);
            $strayed = null === $token ? null : $this->findHopOffOrigin($response);

            if (null !== $strayed) {
                self::drain($response);

                throw new RedirectRefusedException((string) $attempt->getUri(), $strayed);
            }

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
                    self::drain($response);

                    throw new InsufficientScopeException($challenged->values);
                }

                if ($scopeUpgrades >= $this->options->maxScopeUpgrades) {
                    $this->logger->warning('Giving up on {resource} after {attempts} scope upgrades.', [
                        'resource' => $this->resource->value,
                        'attempts' => $scopeUpgrades,
                    ]);

                    return $response;
                }

                // Granting again would produce the same token and the same answer, so the only thing another
                // round buys is a second consent screen. What settles that is the token this attempt
                // presented: what the client was granted at some point says nothing about what it holds now.
                if (new ScopeSet($token->scopes ?? [])->containsAll($challenged)) {
                    $this->logger->warning('The scope challenge from {resource} names {scopes}.', [
                        'resource' => $this->resource->value,
                        'scopes' => $challenged->toParameter() ?? 'no scope at all',
                    ]);

                    return $response;
                }

                ++$scopeUpgrades;
                $additionalScopes = $additionalScopes->mergeWith($challenged);
                self::drain($response);
                $this->coordinator->upgradeScopes($token, $additionalScopes, $challenge, $cancellation);

                continue;
            }

            // A second challenge to a token just obtained is the server's answer, not a stale token.
            if ($reauthorized) {
                return $response;
            }

            $reauthorized = true;
            self::drain($response);
            $this->coordinator->reauthorize($token, $challenge, $cancellation);
        }
    }

    /**
     * The URL of the hop that left this MCP server's origin, walking a redirect chain back from the answer,
     * or `null` when every hop stayed on it.
     *
     * An HTTP client that follows redirects strips credentials only when the authority changes, and an
     * authority carries no scheme, so a hop from HTTPS to cleartext on the same host takes the bearer token
     * with it. Checking only where the chain ended would miss exactly that hop.
     */
    private function findHopOffOrigin(Response $response): ?string
    {
        for ($hop = $response; null !== $hop; $hop = $hop->getPreviousResponse()) {
            $url = (string) $hop->getRequest()->getUri();

            if (! $this->resource->sharesOriginWith($url)) {
                return $url;
            }
        }

        return null;
    }

    /**
     * Reads a challenge body to its end so its connection returns to the pool. An undrained body cancels
     * instead, which tears the connection down for the whole of the authorization flow, user included.
     */
    private static function drain(Response $response): void
    {
        try {
            $response->getBody()->buffer(limit: self::MAX_CHALLENGE_BODY_BYTES);
        } catch (HttpException|StreamException) {
            // Losing the body of a challenge is never a reason to abandon the recovery it asked for. This
            // covers the oversized case, a connection that dies partway through it, and a body the server
            // framed so badly that the parser gives up on it.
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
