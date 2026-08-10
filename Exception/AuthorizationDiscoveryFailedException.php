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
 * Thrown when none of the well-known URLs a client probes serves the metadata document it needs.
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery
 */
final class AuthorizationDiscoveryFailedException extends \RuntimeException implements McpExceptionInterface
{
    /**
     * @param list<string> $probed
     */
    public function __construct(string $document, string $subject, array $probed)
    {
        parent::__construct(\sprintf(
            'No %s was served for "%s". Probed: %s.',
            $document,
            SafeDisplay::sanitiseCause($subject),
            implode(', ', array_map(static fn(string $url): string => SafeDisplay::sanitiseCause($url), $probed)),
        ));
    }
}
