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
use Nexus\Mcp\Core\Schema\ProtocolVersion;

/**
 * Thrown when the server's `initialize` response advertises a protocol version
 * this client does not support, aborting the handshake before it is confirmed.
 */
final class UnsupportedProtocolVersionException extends \RuntimeException implements McpExceptionInterface
{
    public function __construct(public readonly ProtocolVersion $negotiated)
    {
        parent::__construct(\sprintf(
            'Server responded with unsupported protocol version "%s". This client supports "%s".',
            $negotiated->version,
            ProtocolVersion::LATEST_VERSION,
        ));
    }
}
