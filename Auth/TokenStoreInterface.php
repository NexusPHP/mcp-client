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
 * Store for access tokens, keyed by the MCP server each is bound to.
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
