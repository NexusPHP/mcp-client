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

use Nexus\Mcp\Core\Auth\AuthorizationServerMetadata;
use Nexus\Mcp\Core\Auth\ProtectedResourceMetadata;

/**
 * One MCP server's Protected Resource Metadata paired with the metadata of the authorization server it names.
 */
final readonly class DiscoveredResource
{
    public function __construct(
        public ProtectedResourceMetadata $metadata,
        public AuthorizationServerMetadata $server,
    ) {
    }
}
