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
 * Holds the client identifiers obtained through Dynamic Client Registration, keyed by the authorization
 * server that issued them so credentials are never carried across a server change.
 *
 * @see https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration#authorization-server-binding
 */
interface ClientRegistrationStoreInterface
{
    /**
     * @param string $issuer Issuer identifier of the authorization server the registration belongs to
     */
    public function read(string $issuer): ?ClientRegistration;

    public function write(string $issuer, ClientRegistration $registration): void;

    /**
     * Drops a registration the authorization server no longer recognises, so the next resolution registers
     * again rather than presenting an identifier that is spent.
     */
    public function forget(string $issuer): void;
}
