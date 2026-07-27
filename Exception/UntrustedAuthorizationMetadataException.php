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
 * Thrown when a metadata document names a subject other than the one whose URL served it, which is how a
 * hostile server tries to redirect a client to an authorization server it controls.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8414#section-3.3
 */
final class UntrustedAuthorizationMetadataException extends \RuntimeException implements McpExceptionInterface
{
    public function __construct(string $reason)
    {
        parent::__construct(\sprintf('The authorization metadata cannot be trusted because %s', $reason));
    }
}
