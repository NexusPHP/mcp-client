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
 * Thrown when `initialize()` is called after the handshake has already started or completed.
 */
final class ClientAlreadyInitializedException extends \LogicException implements McpExceptionInterface
{
    public function __construct()
    {
        parent::__construct('Client handshake already started or completed.');
    }
}
