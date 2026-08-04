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

namespace Nexus\Mcp\Client;

use Nexus\Mcp\Core\Extension\ExtensionInterface;

/**
 * Declares an extension the client participates in, enabled via `ClientBuilder::enableExtension()`.
 *
 * @extends ExtensionInterface<ClientContext>
 */
interface ClientExtensionInterface extends ExtensionInterface
{
    /**
     * The client-to-server request methods this extension invokes, used to
     * refuse a send to a server that did not advertise the extension.
     *
     * @return list<non-empty-string>
     */
    public function getOutboundRequests(): array;
}
