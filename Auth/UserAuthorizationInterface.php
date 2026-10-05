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
 * The one leg of the OAuth flow that the SDK cannot perform, putting a resource owner in front of the authorization
 * server.
 */
interface UserAuthorizationInterface
{
    /**
     * Reports the redirect URI where the user-agent arrived, yielding to the event loop while it waits and
     * giving up when `$cancellation` fires.
     */
    public function authorize(AuthorizationRedirect $redirect, Cancellation $cancellation): AuthorizationCallback;
}
