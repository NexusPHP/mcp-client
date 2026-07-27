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
use Nexus\Mcp\Client\Exception\UntrustedAuthorizationMetadataException;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;

/**
 * Holds every authorization endpoint an MCP client contacts to HTTPS, exempting loopback hosts where the
 * operator chose the URL or the MCP server is itself on loopback.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations#communication-security
 */
final class SecureEndpoint
{
    /**
     * Verifies the redirect URI the operator configured, which may address a loopback listener.
     */
    public static function verifyRedirectUri(string $url): void
    {
        $label = 'redirect URI';
        $parts = self::parse($url, $label);

        if ('https' === $parts['scheme'] || self::isLoopback($parts['host'])) {
            return;
        }

        throw new InsecureAuthorizationEndpointException($label, $url);
    }

    /**
     * Verifies a URL an MCP server or an authorization server advertised. Plain HTTP is admitted only when
     * the MCP server is itself on loopback, so a peer reached over the public internet cannot steer the
     * client at a loopback or private-network address it could not otherwise reach.
     */
    public static function verifyAdvertised(string $url, string $label, ResourceIdentifier $resource): void
    {
        $parts = self::parse($url, $label);

        if ('https' === $parts['scheme']) {
            return;
        }

        if (self::isLoopback($parts['host']) && self::isLoopback($resource->host)) {
            return;
        }

        throw new UntrustedAuthorizationMetadataException(\sprintf('the %s "%s" is not served over HTTPS.', $label, $url));
    }

    /**
     * Verifies that an advertised URL shares the MCP server's origin, which is what stops a hostile server
     * from naming a metadata document it does not own.
     */
    public static function verifySameOrigin(string $url, string $label, ResourceIdentifier $resource): void
    {
        if ($resource->sharesOriginWith($url)) {
            return;
        }

        throw new UntrustedAuthorizationMetadataException(\sprintf(
            'the %s "%s" is not served by the MCP server it describes.',
            $label,
            $url,
        ));
    }

    /**
     * Verifies a Client ID Metadata Document URL, which the spec holds to HTTPS and to carrying a path so
     * one host can serve more than one document.
     *
     * @see https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration
     */
    public static function verifyClientIdMetadataDocumentUrl(string $url): void
    {
        $label = 'Client ID Metadata Document URL';
        $parts = self::parse($url, $label);

        if ('https' !== $parts['scheme'] || '' === $parts['path'] || '/' === $parts['path']) {
            throw new \InvalidArgumentException(\sprintf(
                'The %s must be an HTTPS URL carrying a path component, "%s" given.',
                $label,
                $url,
            ));
        }
    }

    /**
     * @return array{scheme: string, host: string, path: string}
     */
    private static function parse(string $url, string $label): array
    {
        $parts = parse_url($url);

        if (false === $parts || ! isset($parts['scheme'], $parts['host'])) {
            throw new \InvalidArgumentException(\sprintf('The %s must be an absolute URL, "%s" given.', $label, $url));
        }

        return [
            'scheme' => strtolower($parts['scheme']),
            'host' => strtolower($parts['host']),
            'path' => $parts['path'] ?? '',
        ];
    }

    private static function isLoopback(string $host): bool
    {
        // A bracketed IPv6 literal reaches here with its delimiters still attached.
        $host = trim($host, '[]');

        return 'localhost' === $host
            || '::1' === $host
            || preg_match('/^127(?:\.\d{1,3}){3}$/', $host) === 1;
    }
}
