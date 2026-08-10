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
use Nexus\Mcp\Core\SafeDisplay;

/**
 * Thrown when supplied client credentials belong to an authorization server other than the one the protected
 * resource now names.
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#authorization-server-binding
 */
final class AuthorizationServerMismatchException extends \RuntimeException implements McpExceptionInterface
{
    public function __construct(string $registeredIssuer, string $currentIssuer)
    {
        parent::__construct(\sprintf(
            'The supplied client credentials were registered with "%s" but the protected resource now names "%s", and credentials are not portable between authorization servers.',
            $registeredIssuer,
            SafeDisplay::sanitiseCause($currentIssuer),
        ));
    }
}
