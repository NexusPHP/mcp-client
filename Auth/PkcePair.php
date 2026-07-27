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
 * A PKCE `code_verifier` and the `S256` `code_challenge` derived from it.
 *
 * @internal
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4
 */
final readonly class PkcePair
{
    /**
     * The only challenge method MCP clients offer.
     */
    public const string CHALLENGE_METHOD = 'S256';

    /**
     * Verifier entropy in bytes. Base64url encoding turns this into the 43 characters RFC 7636 sets as
     * the minimum verifier length.
     */
    private const int VERIFIER_BYTES = 32;

    private function __construct(public string $verifier, public string $challenge)
    {
    }

    public static function generate(): self
    {
        return self::fromVerifier(self::encode(random_bytes(self::VERIFIER_BYTES)));
    }

    public static function fromVerifier(string $verifier): self
    {
        return new self($verifier, self::encode(hash('sha256', $verifier, true)));
    }

    private static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
