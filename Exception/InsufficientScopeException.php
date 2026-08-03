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
 * Thrown when an MCP server answers that the token's scopes are insufficient and asking the resource owner
 * for more is not an option: the client is configured to report instead, the upgrade budget is spent, or the
 * token already carries everything the challenge names.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
 */
final class InsufficientScopeException extends \RuntimeException implements McpExceptionInterface
{
    /**
     * @param list<non-empty-string> $required Scopes the challenge named, empty when it named none
     */
    public function __construct(public readonly array $required)
    {
        parent::__construct([] === $required
            ? 'The MCP server answered insufficient_scope without naming a scope.'
            : \sprintf('The MCP server requires the scope "%s".', implode(' ', $required)));
    }
}
