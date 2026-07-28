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
 * Thrown when an authorization endpoint would be contacted over plain HTTP from a host that is not loopback.
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#communication-security
 */
final class InsecureAuthorizationEndpointException extends \RuntimeException implements McpExceptionInterface
{
    public function __construct(string $label, string $url)
    {
        parent::__construct(\sprintf('The %s must be served over HTTPS or from a loopback host, "%s" given.', $label, $url));
    }
}
