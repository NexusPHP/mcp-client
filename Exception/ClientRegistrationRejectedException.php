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
 * Thrown when an authorization server does not recognise the client identifier presented to it.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
final class ClientRegistrationRejectedException extends \RuntimeException implements McpExceptionInterface
{
    public function __construct(?string $description = null)
    {
        parent::__construct(\sprintf(
            'The authorization server does not recognise the client identifier presented to it, so the client must register again%s',
            null === $description ? '.' : \sprintf(': %s', $description),
        ));
    }
}
