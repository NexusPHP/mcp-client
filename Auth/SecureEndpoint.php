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

namespace Nexus\Mcp\Client\Auth;

use Nexus\Mcp\Client\Exception\InsecureAuthorizationEndpointException;

/**
 * Holds every authorization endpoint an MCP client contacts to HTTPS, exempting loopback hosts so a local
 * development authorization server stays reachable.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations#communication-security
 */
final class SecureEndpoint
{
    public static function verify(string $url, string $label): void
    {
        $parts = parse_url($url);

        if (false === $parts || ! isset($parts['scheme'], $parts['host'])) {
            throw new \InvalidArgumentException(\sprintf('The %s must be an absolute URL, "%s" given.', $label, $url));
        }

        if (strtolower($parts['scheme']) === 'https' || self::isLoopback($parts['host'])) {
            return;
        }

        throw new InsecureAuthorizationEndpointException($label, $url);
    }

    private static function isLoopback(string $host): bool
    {
        // A bracketed IPv6 literal reaches here with its delimiters still attached.
        $host = strtolower(trim($host, '[]'));

        return 'localhost' === $host
            || '::1' === $host
            || preg_match('/^127(?:\.\d{1,3}){3}$/', $host) === 1;
    }
}
