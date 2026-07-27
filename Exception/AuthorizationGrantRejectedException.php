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

namespace Nexus\Mcp\Client\Exception;

/**
 * Thrown when an authorization server refuses a token request because the grant presented is spent, so the
 * resource owner has to grant again.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
final class AuthorizationGrantRejectedException extends TokenRequestFailedException
{
}
