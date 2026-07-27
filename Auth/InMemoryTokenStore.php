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
    public function read(string $resource): ?AccessToken
    {
        return $this->tokens[$resource] ?? null;
    }

    #[\Override]
    public function write(string $resource, AccessToken $token): void
    {
        $this->tokens[$resource] = $token;
    }

    #[\Override]
    public function forget(string $resource): void
    {
        unset($this->tokens[$resource]);
    }
}
