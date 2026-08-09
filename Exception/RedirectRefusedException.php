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
 * Thrown when a response arrived from a URL other than the one the request was sent to.
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#communication-security
 */
final class RedirectRefusedException extends \RuntimeException implements McpExceptionInterface
{
    public function __construct(string $sent, string $answered)
    {
        parent::__construct(\sprintf(
            'The request to "%s" was answered from "%s" after a redirect. Credentials are never carried across one.',
            $sent,
            $answered,
        ));
    }
}
