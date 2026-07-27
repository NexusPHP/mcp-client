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

/**
 * A bearer access token an authorization server issued for one MCP server.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
 */
final readonly class AccessToken
{
    /**
     * @param string                 $value        The `access_token` value sent in the `Authorization` header
     * @param ?int                   $expiresAt    Unix timestamp the token expires at, or `null` when the server named no lifetime
     * @param ?string                $refreshToken The `refresh_token`, when the server issued one
     * @param list<non-empty-string> $scopes       Scopes the token was granted
     */
    public function __construct(
        public string $value,
        public ?int $expiresAt = null,
        public ?string $refreshToken = null,
        public array $scopes = [],
    ) {
    }
}
