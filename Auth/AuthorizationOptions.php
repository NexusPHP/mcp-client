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
use Nexus\Mcp\Core\Auth\TokenEndpointAuthMethod;

/**
 * How this client identifies itself to the authorization servers protecting the MCP servers it talks to.
 */
final readonly class AuthorizationOptions
{
    /**
     * @param string                  $clientName                  Name shown to the resource owner on a consent screen
     * @param null|string             $redirectUri                 Redirect URI the authorization response lands on, either loopback or HTTPS. `null` for grants that never visit an authorization endpoint
     * @param null|string             $clientIdMetadataDocumentUrl HTTPS URL of a hosted Client ID Metadata Document, used verbatim as `client_id`
     * @param null|ClientRegistration $preRegistered               Credentials issued out of band, which take priority over every other mechanism
     * @param ApplicationType         $applicationType             Declared during Dynamic Client Registration
     * @param int                     $maxScopeUpgrades            How many times a request may be retried after an insufficient-scope challenge
     * @param bool                    $requestOfflineAccess        Whether to ask for `offline_access`, and with it a refresh token, where the authorization server offers it
     * @param list<non-empty-string>  $defaultScopes               Scopes to ask for when no challenge names any, in place of everything the resource advertises
     * @param InsufficientScopePolicy $onInsufficientScope         Whether an insufficient-scope answer steps the scopes up or is reported to the caller
     * @param float                   $timeout                     Seconds a single authorization round trip may take
     * @param bool                    $allowInsecureLoopback       Admits an authorization server reached over cleartext HTTP on a loopback host, which the spec does not exempt. For local development and conformance runs, never production
     */
    public function __construct(
        public string $clientName,
        public ?string $redirectUri = null,
        public ?string $clientIdMetadataDocumentUrl = null,
        public ?ClientRegistration $preRegistered = null,
        public ApplicationType $applicationType = ApplicationType::Native,
        public int $maxScopeUpgrades = 2,
        public bool $requestOfflineAccess = false,
        public array $defaultScopes = [],
        public InsufficientScopePolicy $onInsufficientScope = InsufficientScopePolicy::Reauthorize,
        public float $timeout = 10.0,
        public bool $allowInsecureLoopback = false,
    ) {
        $secureEndpoint = new SecureEndpoint($allowInsecureLoopback);

        if (null !== $redirectUri) {
            $secureEndpoint->verifyRedirectUri($redirectUri);
        }

        if (null !== $clientIdMetadataDocumentUrl) {
            $secureEndpoint->verifyClientIdMetadataDocumentUrl($clientIdMetadataDocumentUrl);
        }

        if (TokenEndpointAuthMethod::PrivateKeyJwt === $preRegistered?->tokenEndpointAuthMethod) {
            throw new \InvalidArgumentException(\sprintf(
                'Pre-registered credentials cannot authenticate with "%s". Configure a ClientCredentialsGrant with a PrivateKeyJwtCredential instead.',
                TokenEndpointAuthMethod::PrivateKeyJwt->value,
            ));
        }
    }
}
