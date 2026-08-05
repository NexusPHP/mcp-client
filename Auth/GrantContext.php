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

use Amp\Http\Client\DelegateHttpClient;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\ScopeSet;
use Psr\Log\LoggerInterface;

/**
 * What a grant strategy may draw on to obtain a token: what discovery found, the resource the token is for,
 * the scopes to ask for, and the collaborators the coordinator holds.
 *
 * @internal
 */
final readonly class GrantContext
{
    public function __construct(
        public DiscoveredResource $discovered,
        public ResourceIdentifier $resource,
        public ScopeSet $scopes,
        public AuthorizationOptions $options,
        public ClientRegistrar $registrar,
        public TokenEndpoint $tokenEndpoint,
        public DelegateHttpClient $httpClient,
        public LoggerInterface $logger,
    ) {
    }
}
