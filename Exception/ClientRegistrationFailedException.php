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
 * Thrown when Dynamic Client Registration is refused, or succeeds on terms the client cannot honour.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2
 */
final class ClientRegistrationFailedException extends \RuntimeException implements McpExceptionInterface
{
    public function __construct(public readonly string $error, ?string $description = null)
    {
        parent::__construct(\sprintf(
            'Dynamic Client Registration failed with "%s"%s',
            $error,
            null === $description ? '.' : \sprintf(': %s', $description),
        ));
    }
}
