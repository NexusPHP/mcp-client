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
 * Thrown when an operation requires a transport but `connect()` has not been called.
 */
final class ClientNotConnectedException extends \LogicException implements McpExceptionInterface
{
    public function __construct()
    {
        parent::__construct('Client is not connected. Call connect() first.');
    }
}
