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

use Nexus\Mcp\Core\Auth\TokenEndpointAuthMethod;

/**
 * An OAuth client identifier bound to the authorization server that honours it.
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#authorization-server-binding
 */
final readonly class ClientRegistration
{
    /**
     * @param string           $clientId              The `client_id`, either pre-registered, dynamically registered, or a Client ID Metadata Document URL
     * @param null|string      $issuer                The authorization server this identifier belongs to, or null to leave it unbound.
     * @param null|int<0, max> $clientSecretExpiresAt Seconds since the epoch at which `client_secret` expires, `0` when it never does, or null when the server named none.
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1
     */
    public function __construct(
        public string $clientId,
        public ?string $issuer = null,
        public ?string $clientSecret = null,
        public TokenEndpointAuthMethod $tokenEndpointAuthMethod = TokenEndpointAuthMethod::None,
        public ?int $clientSecretExpiresAt = null,
    ) {
    }
}
