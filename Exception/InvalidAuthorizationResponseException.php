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
 * Thrown when an authorization response cannot be trusted.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9207#section-2.4
 */
final class InvalidAuthorizationResponseException extends \RuntimeException implements McpExceptionInterface
{
    public function __construct(string $reason)
    {
        parent::__construct(\sprintf('The authorization response cannot be used because %s', $reason));
    }
}
