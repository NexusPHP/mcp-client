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

use Nexus\Mcp\Core\Auth\ApplicationType;

/**
 * How this client identifies itself to the authorization servers protecting the MCP servers it talks to.
 */
final readonly class AuthorizationOptions
{
    /**
     * @param string              $clientName                  Name shown to the resource owner on a consent screen
     * @param string              $redirectUri                 Redirect URI the authorization response lands on, either loopback or HTTPS
     * @param ?string             $clientIdMetadataDocumentUrl HTTPS URL of a hosted Client ID Metadata Document, used verbatim as `client_id`
     * @param ?ClientRegistration $preRegistered               Credentials issued out of band, which take priority over every other mechanism
     * @param ApplicationType     $applicationType             Declared during Dynamic Client Registration
     * @param int                 $maxScopeUpgrades            How many times a request may be retried after an insufficient-scope challenge
     */
    public function __construct(
        public string $clientName,
        public string $redirectUri,
        public ?string $clientIdMetadataDocumentUrl = null,
        public ?ClientRegistration $preRegistered = null,
        public ApplicationType $applicationType = ApplicationType::Native,
        public int $maxScopeUpgrades = 2,
    ) {
        SecureEndpoint::verify($redirectUri, 'redirect URI');
    }
}
