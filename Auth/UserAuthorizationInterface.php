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
     * Reports the redirect URI the user-agent arrived at once the resource owner has answered.
     *
     * The implementation yields to the event loop while it waits rather than blocking it, and gives up when
     * `$cancellation` fires, which happens when the request that needs the token is abandoned.
     */
    public function authorize(AuthorizationRedirect $redirect, Cancellation $cancellation): AuthorizationCallback;
}
