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
use Amp\Http\Client\DelegateHttpClient;
use Nexus\Mcp\Client\Exception\AuthorizationServerMismatchException;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\ScopeSet;
use Psr\Log\LoggerInterface;

/**
 * What a grant strategy may draw on to obtain a token: what discovery found, the resource the token is for,
 * the scopes to ask for, and the two authorization-server calls a grant is built from.
 */
final readonly class GrantContext
{
    /**
     * @internal Built by the authorization coordinator and handed to a strategy, never constructed by one
     */
    public function __construct(
        public DiscoveredResource $discovered,
        public ResourceIdentifier $resource,
        public ScopeSet $scopes,
        public AuthorizationOptions $options,
        public DelegateHttpClient $httpClient,
        public LoggerInterface $logger,
        private ClientRegistrar $registrar,
        private TokenEndpoint $tokenEndpoint,
    ) {
    }

    /**
     * Resolves the `client_id` to present, walking the mechanisms in the priority order the spec fixes:
     * pre-registered credentials, then a Client ID Metadata Document, then Dynamic Client Registration.
     *
     * @throws AuthorizationServerMismatchException
     */
    public function resolveRegistration(Cancellation $cancellation): ClientRegistration
    {
        return $this->registrar->resolve($this->discovered->server, $this->options, $cancellation);
    }

    /**
     * Redeems a grant at the discovered authorization server's token endpoint, applying client
     * authentication, RFC 6749 error triage, and the token read the built-in grants use.
     *
     * @param array<string, string> $parameters      Full form body of the grant, `grant_type` included
     * @param null|ScopeSet         $requestedScopes Scopes the token carries when the response names none, defaulting to the context's
     */
    public function requestToken(
        ClientRegistration $registration,
        array $parameters,
        Cancellation $cancellation,
        ?ScopeSet $requestedScopes = null,
    ): AccessToken {
        return $this->tokenEndpoint->requestToken(
            $this->discovered->server,
            $registration,
            $parameters,
            $requestedScopes ?? $this->scopes,
            $cancellation,
        );
    }
}
