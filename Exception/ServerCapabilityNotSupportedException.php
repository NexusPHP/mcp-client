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

use Nexus\Mcp\Core\Exception\McpExceptionInterface;

/**
 * Thrown when a request targets a capability the server did not advertise during
 * the initialize handshake.
 */
final class ServerCapabilityNotSupportedException extends \LogicException implements McpExceptionInterface
{
    public function __construct(string $method)
    {
        parent::__construct(\sprintf(
            'Request method "%s" requires a server capability that was not advertised during initialize.',
            $method,
        ));
    }
}
