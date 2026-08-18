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

namespace Nexus\Mcp\Client\Extension;

use Nexus\Mcp\Client\ClientContext;
use Nexus\Mcp\Core\Extension\ExtensionInterface;

/**
 * An extension the client participates in.
 *
 * @extends ExtensionInterface<ClientContext>
 */
interface ClientExtensionInterface extends ExtensionInterface
{
    /**
     * The client-to-server request methods this extension invokes.
     *
     * @return list<non-empty-string>
     */
    public function getOutboundRequests(): array;
}
