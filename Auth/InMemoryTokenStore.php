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
 * Token store that keeps tokens for the lifetime of the process only.
 */
final class InMemoryTokenStore implements TokenStoreInterface
{
    /**
     * @var array<string, AccessToken>
     */
    private array $tokens = [];

    #[\Override]
    public function read(string $resource, string $issuer): ?AccessToken
    {
        return $this->tokens[self::buildKey($resource, $issuer)] ?? null;
    }

    #[\Override]
    public function write(string $resource, string $issuer, AccessToken $token): void
    {
        $this->tokens[self::buildKey($resource, $issuer)] = $token;
    }

    #[\Override]
    public function forget(string $resource, string $issuer): void
    {
        unset($this->tokens[self::buildKey($resource, $issuer)]);
    }

    private static function buildKey(string $resource, string $issuer): string
    {
        // The length prefix keeps a resource ending in the separator from colliding with a longer issuer.
        return \sprintf('%d:%s|%s', \strlen($resource), $resource, $issuer);
    }
}
