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
 * Holds the access tokens a client has obtained, keyed by the MCP server the token is bound to and the
 * authorization server that issued it. Implementations are responsible for storing tokens confidentially.
 *
 * @see https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations#token-theft
 */
interface TokenStoreInterface
{
    /**
     * @param string $resource Canonical URI of the MCP server the token is bound to
     * @param string $issuer   Issuer identifier of the authorization server that issued the token
     */
    public function read(string $resource, string $issuer): ?AccessToken;

    public function write(string $resource, string $issuer, AccessToken $token): void;

    public function forget(string $resource, string $issuer): void;
}
