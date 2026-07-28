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
 * Builds the well-known metadata URLs an MCP client probes, in the priority order the spec fixes.
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
     * The Protected Resource Metadata URLs for an MCP endpoint, the path-scoped one first. An endpoint at
     * the root has only the root form, and only that form keeps the resource identifier's query.
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
            // The root form is the URL RFC 9728 assigns to the resource at this origin's root. Carrying a
            // path-scoped resource's query onto it would ask for the document of a different resource.
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
        // RFC 8414 forbids a query on an issuer identifier, so only the resource half carries one.
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

    /**
     * The resource identifier the origin-root well-known URL describes: the scheme, host and port of
     * the given URI, without its path or query.
     */
    public static function originOf(string $uri): string
    {
        return self::splitOrigin($uri)[0];
    }

    /**
     * @return array{string, string, string} The origin, the path and the query, each empty when the URI
     *                                       carries none. A resource identifier keeps its query, so the
     *                                       document that describes it is asked for under the same one.
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
