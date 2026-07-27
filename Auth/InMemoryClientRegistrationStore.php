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
 * Registration store that keeps registrations for the lifetime of the process only, so a restart registers
 * again rather than reusing an identifier it can no longer prove it owns.
 */
final class InMemoryClientRegistrationStore implements ClientRegistrationStoreInterface
{
    /**
     * @var array<string, ClientRegistration>
     */
    private array $registrations = [];

    #[\Override]
    public function read(string $issuer): ?ClientRegistration
    {
        return $this->registrations[$issuer] ?? null;
    }

    #[\Override]
    public function write(string $issuer, ClientRegistration $registration): void
    {
        $this->registrations[$issuer] = $registration;
    }
}
