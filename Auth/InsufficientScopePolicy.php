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
 * What a client does when an MCP server answers that the scopes its token carries are insufficient.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
 */
enum InsufficientScopePolicy
{
    /**
     * Ask the resource owner to grant the challenged scopes as well, then retry the request.
     */
    case Reauthorize;

    /**
     * Raise `InsufficientScopeException` naming the scopes the server asked for, leaving the decision to
     * the caller.
     */
    case Fail;
}
