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
use Nexus\Mcp\Core\SafeDisplay;

/**
 * Transport-security checks for the URLs an MCP client is steered at.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#communication-security
 */
final class SecureEndpoint
{
    /**
     * Verifies the redirect URI, the one URL the spec lets address a loopback listener over plain HTTP.
     */
    public static function verifyRedirectUri(string $url): void
    {
        $label = 'redirect URI';
        $parts = self::parse($url) ?? throw new \InvalidArgumentException(\sprintf(
            'The %s must be an absolute URL, "%s" given.',
            $label,
            $url,
        ));

        if ('https' === $parts['scheme'] || self::isLoopback($parts['host'])) {
            return;
        }

        throw new InsecureAuthorizationEndpointException($label, $url);
    }

    /**
     * @param bool $allowLoopback Admits cleartext on a loopback host, which the spec does not exempt. Off
     *                            unless the caller opted in through `AuthorizationOptions`.
     */
    public static function verifyAuthorizationServerUrl(string $url, string $label, bool $allowLoopback = false): void
    {
        $parts = self::parse($url);

        if (null === $parts || ! self::isSecureScheme($parts, $allowLoopback)) {
            throw new UntrustedAuthorizationMetadataException(\sprintf(
                'the %s "%s" is not an absolute HTTPS URL.',
                $label,
                SafeDisplay::sanitiseCause($url),
            ));
        }

        if ('' !== $parts['fragment']) {
            throw new UntrustedAuthorizationMetadataException(\sprintf(
                'the %s "%s" carries a fragment.',
                $label,
                SafeDisplay::sanitiseCause($url),
            ));
        }
    }

    /**
     * Verifies a Client ID Metadata Document URL, which the spec holds to HTTPS and to carrying a path.
     *
     * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration
     */
    public static function verifyClientIdMetadataDocumentUrl(string $url): void
    {
        $label = 'Client ID Metadata Document URL';
        $parts = self::parse($url) ?? throw new \InvalidArgumentException(\sprintf(
            'The %s must be an absolute URL, "%s" given.',
            $label,
            $url,
        ));

        if ('https' !== $parts['scheme'] || '' === $parts['path'] || '/' === $parts['path']) {
            throw new \InvalidArgumentException(\sprintf(
                'The %s must be an HTTPS URL carrying a path component, "%s" given.',
                $label,
                $url,
            ));
        }
    }

    /**
     * @return null|array{scheme: string, host: string, path: string, fragment: string}
     */
    private static function parse(string $url): ?array
    {
        $parts = parse_url($url);

        if (false === $parts || ! isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        return [
            'scheme' => strtolower($parts['scheme']),
            'host' => strtolower($parts['host']),
            'path' => $parts['path'] ?? '',
            'fragment' => $parts['fragment'] ?? '',
        ];
    }

    /**
     * @param array{scheme: string, host: string, path: string, fragment: string} $parts
     */
    private static function isSecureScheme(array $parts, bool $allowLoopback): bool
    {
        if ('https' === $parts['scheme']) {
            return true;
        }

        return $allowLoopback && 'http' === $parts['scheme'] && self::isLoopback($parts['host']);
    }

    private static function isLoopback(string $host): bool
    {
        $host = trim($host, '[]');

        return 'localhost' === $host
            || '::1' === $host
            || preg_match('/^127(?:\.\d{1,3}){3}$/', $host) === 1;
    }
}
