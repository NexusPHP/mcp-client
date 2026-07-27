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
 * The one leg of the OAuth flow the SDK cannot perform: putting the authorization URL in front of a
 * resource owner and collecting the redirect the user-agent lands on.
 *
 * The SDK owns PKCE, the `state` value, the expected issuer, the URL it builds, and every validation of the
 * response. An implementation only has to open `$redirect->url` and return where the user-agent ended up.
 */
interface UserAuthorizationInterface
{
    /**
     * Blocks until the resource owner has answered, then reports the redirect URI the user-agent arrived at.
     */
    public function authorize(AuthorizationRedirect $redirect): AuthorizationCallback;
}
