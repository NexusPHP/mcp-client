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

use Nexus\Mcp\Core\Auth\ScopeSet;

/**
 * An authorization request awaiting the user-agent: the URL to open, plus the per-request state the client
 * records before redirecting so it can validate the response.
 */
final readonly class AuthorizationRedirect
{
    /**
     * @param string $url                     Authorization URL to open in a user-agent
     * @param string $state                   Opaque value the authorization response must echo
     * @param string $expectedIssuer          Issuer the authorization response's `iss` is compared against
     * @param bool   $issuerParameterRequired Whether the authorization server advertises that it emits `iss`
     */
    public function __construct(
        public string $url,
        public string $state,
        public string $expectedIssuer,
        public bool $issuerParameterRequired,
        public PkcePair $pkce,
        public ScopeSet $requestedScopes,
    ) {
    }
}
