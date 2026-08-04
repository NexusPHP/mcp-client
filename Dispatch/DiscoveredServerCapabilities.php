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

namespace Nexus\Mcp\Client\Dispatch;

use Nexus\Mcp\Core\Schema\ServerCapabilities;

/**
 * Holds the capabilities the last `server/discover` advertised, shared between
 * the client and the handlers that gate on them.
 *
 * @internal
 */
final class DiscoveredServerCapabilities
{
    private ?ServerCapabilities $capabilities = null;

    public function record(?ServerCapabilities $capabilities): void
    {
        $this->capabilities = $capabilities;
    }

    public function current(): ?ServerCapabilities
    {
        return $this->capabilities;
    }
}
