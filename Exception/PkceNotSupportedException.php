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
 * Thrown when an authorization server does not advertise the `S256` code challenge method MCP clients must have.
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#authorization-code-protection
 */
final class PkceNotSupportedException extends \RuntimeException implements McpExceptionInterface
{
    public function __construct(string $issuer)
    {
        parent::__construct(\sprintf(
            'The authorization server "%s" does not advertise the S256 code challenge method, so authorization cannot proceed.',
            $issuer,
        ));
    }
}
