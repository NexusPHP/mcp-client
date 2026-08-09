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
 * Thrown when an authorization or metadata endpoint answers with something other than a JSON object.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
final class MalformedAuthorizationResponseException extends \RuntimeException implements McpExceptionInterface
{
    public function __construct(string $label, ?\Throwable $previous = null)
    {
        parent::__construct(
            \sprintf('The %s answered with a payload that is not a JSON object.', $label),
            previous: $previous,
        );
    }
}
