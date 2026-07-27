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
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
use Nexus\Mcp\Client\Exception\InsufficientScopeException;
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
            new MetadataDiscovery($this->client, $this->options->timeout),
            new ClientRegistrar($this->client, $registrations ?? new InMemoryClientRegistrationStore(), $this->options->timeout),
            new TokenEndpoint($this->client, $this->options->timeout),
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

        while (true) {
            $token = $this->coordinator->fetchToken($cancellation);
            $response = $this->client->request(self::authorizeRequest($request, $token), $cancellation);
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
                // round buys is a second consent screen.
                if ($this->coordinator->readGrantedScopes()->containsAll($challenged)) {
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
            } else {
                // A second challenge to a token just obtained is the server's answer, not a stale token.
                if ($reauthorized) {
                    return $response;
                }

                $reauthorized = true;
                self::drain($response);
                $this->coordinator->reauthorize($token, $challenge, $cancellation);
            }
        }
    }

    /**
     * Reads a challenge body to its end so its connection returns to the pool. An undrained body cancels
     * instead, which tears the connection down for the whole of the authorization flow, user included.
     */
    private static function drain(Response $response): void
    {
        try {
            $response->getBody()->buffer(limit: self::MAX_CHALLENGE_BODY_BYTES);
        } catch (StreamException) {
            // Losing the body of a challenge is never a reason to abandon the recovery it asked for. This
            // covers the oversized case and a connection that dies partway through it alike.
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
