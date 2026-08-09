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
 * Store for client identifiers, keyed by the authorization server that issued them.
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#authorization-server-binding
 */
interface ClientRegistrationStoreInterface
{
    /**
     * @param string $issuer Issuer identifier of the authorization server the registration belongs to.
     */
    public function read(string $issuer): ?ClientRegistration;

    public function write(string $issuer, ClientRegistration $registration): void;

    public function forget(string $issuer): void;
}
