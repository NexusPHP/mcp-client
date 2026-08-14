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
 * Thrown when an MCP server answers that the token's scopes are insufficient and no scope upgrade is available.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
 */
final class InsufficientScopeException extends \RuntimeException implements McpExceptionInterface
{
    /**
     * @param list<non-empty-string> $required Scopes the challenge named that this client can use
     * @param bool                   $named    Whether the challenge named a scope at all
     */
    public function __construct(
        public readonly array $required,
        bool $named = false,
    ) {
        parent::__construct(match (true) {
            [] !== $required => \sprintf('The MCP server requires the scope "%s".', SafeDisplay::sanitiseCause(implode(' ', $required))),
            $named => 'The MCP server named only scopes that are not RFC 6749 scope-tokens, so none can be requested.',
            default => 'The MCP server answered insufficient_scope without naming a scope.',
        });
    }
}
