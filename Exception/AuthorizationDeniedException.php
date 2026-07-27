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
 * Thrown when an authorization server answers an authorization request with an OAuth error rather than a
 * code.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
 */
final class AuthorizationDeniedException extends \RuntimeException implements McpExceptionInterface
{
    public function __construct(public readonly string $error, ?string $description = null)
    {
        parent::__construct(\sprintf(
            'The authorization server denied the request with "%s"%s',
            $error,
            null === $description ? '.' : \sprintf(': %s', $description),
        ));
    }
}
