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
 * Strategy for obtaining an access token once discovery has run.
 */
interface GrantStrategyInterface
{
    /**
     * Obtains a fresh access token for the resource the context describes.
     */
    public function grant(GrantContext $context, Cancellation $cancellation): AccessToken;

    /**
     * Whether an expired token that carries no refresh token is renewed by running the grant again.
     */
    public function renewsByFreshGrant(): bool;
}
