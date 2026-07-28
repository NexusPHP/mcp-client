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
 * Holds the access tokens a client has obtained, keyed by the MCP server each token is bound to. The issuer
 * that minted a token travels on the token itself. Implementations are responsible for storing tokens
 * confidentially.
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#token-theft
 */
interface TokenStoreInterface
{
    /**
     * @param string $resource Canonical URI of the MCP server the token is bound to
     */
    public function read(string $resource): ?AccessToken;

    public function write(string $resource, AccessToken $token): void;

    public function forget(string $resource): void;
}
