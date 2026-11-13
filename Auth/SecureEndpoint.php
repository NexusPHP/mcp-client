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
use Nexus\Mcp\Core\Validation\Rfc3986UriValidator;

/**
 * Transport-security checks for the URLs that an MCP client is steered at.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations#communication-security
 */
final readonly class SecureEndpoint
{
    /**
     * @param bool $allowLoopback Admits cleartext on a loopback host, which the spec does not exempt. Off
     *                            unless the caller opted in through `AuthorizationOptions`.
     */
    public function __construct(private bool $allowLoopback = false)
    {
    }

    /**
     * Verifies the redirect URI, the one URL that the spec lets address a loopback listener over plain
     * HTTP unconditionally, so the loopback opt-in plays no part.
     */
    public function verifyRedirectUri(string $url): void
    {
        $label = 'redirect URI';
        $parts = $this->parse($url) ?? throw new \InvalidArgumentException(\sprintf(
            'The %s must be an absolute URL, "%s" given.',
            $label,
            $url,
        ));

        if ('https' === $parts['scheme'] || ('http' === $parts['scheme'] && $this->isLoopback($parts['host']))) {
            return;
        }

        throw new InsecureAuthorizationEndpointException($label, $url);
    }

    public function verifyAuthorizationServerUrl(string $url, string $label): void
    {
        $parts = $this->parse($url);

        if (null === $parts || ! $this->isSecureScheme($parts, $this->allowLoopback)) {
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
     * Verifies a Client ID Metadata Document URL, which the spec holds to HTTPS and to carrying a
     * path, with no loopback exemption for the opt-in to widen.
     *
     * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration
     */
    public function verifyClientIdMetadataDocumentUrl(string $url): void
    {
        $label = 'Client ID Metadata Document URL';
        $parts = $this->parse($url) ?? throw new \InvalidArgumentException(\sprintf(
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
    private function parse(string $url): ?array
    {
        try {
            Rfc3986UriValidator::validate($url, 'URL');
        } catch (\InvalidArgumentException) {
            return null;
        }

        $parts = parse_url($url);

        if (false === $parts || ! isset($parts['scheme'], $parts['host']) || ! $this->isAddressable($parts['host'])) {
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
     * Refuses a host that names no single peer or that readers disagree on: a percent-encoded name, the
     * unspecified or IPv4-mapped IPv6 address, and any IPv4 form other than the canonical dotted quad.
     */
    private function isAddressable(string $host): bool
    {
        if (str_contains($host, '%')) {
            return false;
        }

        if (str_starts_with($host, '[')) {
            $address = (string) inet_pton(trim($host, '[]'));

            return str_repeat("\0", 16) !== $address && ! str_starts_with($address, str_repeat("\0", 10)."\xFF\xFF");
        }

        // WHATWG URL: one trailing dot is dropped before a host is parsed as IPv4.
        $name = str_ends_with($host, '.') ? substr($host, 0, -1) : $host;

        if (preg_match('/\A(?:0x[0-9a-f]*|\d+)(?:\.(?:0x[0-9a-f]*|\d+))*\z/i', $name) !== 1) {
            return true;
        }

        return '0.0.0.0' !== $host
            && preg_match('/\A(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\z/', $host) === 1;
    }

    /**
     * @param array{scheme: string, host: string, path: string, fragment: string} $parts
     */
    private function isSecureScheme(array $parts, bool $allowLoopback): bool
    {
        if ('https' === $parts['scheme']) {
            return true;
        }

        return $allowLoopback && 'http' === $parts['scheme'] && $this->isLoopback($parts['host']);
    }

    private function isLoopback(string $host): bool
    {
        $host = trim($host, '[]');

        // RFC 6761 §6.3: every name under `.localhost` is loopback.
        return 'localhost' === $host
            || str_ends_with($host, '.localhost')
            || '::1' === $host
            || preg_match('/^127(?:\.\d{1,3}){3}$/', $host) === 1;
    }
}
