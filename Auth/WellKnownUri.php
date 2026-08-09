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

/**
 * Builder for the well-known metadata URLs an MCP client probes.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery
 */
final class WellKnownUri
{
    private const string PROTECTED_RESOURCE = '/.well-known/oauth-protected-resource';
    private const string AUTHORIZATION_SERVER = '/.well-known/oauth-authorization-server';
    private const string OPENID_CONFIGURATION = '/.well-known/openid-configuration';

    /**
     * The Protected Resource Metadata URLs for an MCP endpoint, the path-scoped one first and the only one
     * keeping the resource identifier's query.
     *
     * @return list<string>
     */
    public static function forProtectedResource(string $resource): array
    {
        [$origin, $path, $query] = self::splitOrigin($resource);

        if ('' === $path) {
            return [$origin.self::PROTECTED_RESOURCE.$query];
        }

        return [
            $origin.self::PROTECTED_RESOURCE.$path.$query,
            $origin.self::PROTECTED_RESOURCE,
        ];
    }

    /**
     * The Authorization Server Metadata URLs for an issuer, RFC 8414 before OpenID Connect Discovery and
     * path insertion before path appending.
     *
     * @return list<string>
     */
    public static function forAuthorizationServer(string $issuer): array
    {
        [$origin, $path] = self::splitOrigin($issuer);

        if ('' === $path) {
            return [
                $origin.self::AUTHORIZATION_SERVER,
                $origin.self::OPENID_CONFIGURATION,
            ];
        }

        return [
            $origin.self::AUTHORIZATION_SERVER.$path,
            $origin.self::OPENID_CONFIGURATION.$path,
            $origin.$path.self::OPENID_CONFIGURATION,
        ];
    }

    public static function originOf(string $uri): string
    {
        return self::splitOrigin($uri)[0];
    }

    /**
     * @return array{string, string, string}
     */
    private static function splitOrigin(string $uri): array
    {
        $parts = parse_url($uri);

        if (false === $parts || ! isset($parts['scheme'], $parts['host'])) {
            throw new \InvalidArgumentException(\sprintf(
                'A well-known metadata URL cannot be built from "%s", which is not an absolute URI.',
                $uri,
            ));
        }

        return [
            \sprintf(
                '%s://%s%s',
                strtolower($parts['scheme']),
                strtolower($parts['host']),
                isset($parts['port']) ? ':'.$parts['port'] : '',
            ),
            rtrim($parts['path'] ?? '', '/'),
            isset($parts['query']) ? '?'.$parts['query'] : '',
        ];
    }
}
