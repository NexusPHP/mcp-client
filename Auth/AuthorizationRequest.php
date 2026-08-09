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

use Nexus\Assert\Assert;
use Nexus\Mcp\Core\Auth\AuthorizationServerMetadata;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\ScopeSet;

/**
 * Builder for the OAuth 2.1 authorization request an MCP client opens in a user-agent.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-flow-steps
 */
final class AuthorizationRequest
{
    private const int STATE_BYTES = 32;

    public static function build(
        AuthorizationServerMetadata $metadata,
        string $clientId,
        string $redirectUri,
        ResourceIdentifier $resource,
        ScopeSet $scopes,
        bool $allowInsecureLoopback = false,
    ): AuthorizationRedirect {
        $endpoint = $metadata->authorizationEndpoint;
        Assert::that($endpoint)->isNonEmptyString(\sprintf(
            'The authorization server "%s" publishes no authorization endpoint.',
            $metadata->issuer,
        ));
        SecureEndpoint::verifyAuthorizationServerUrl($endpoint, 'authorization endpoint', $allowInsecureLoopback);

        $pkce = PkcePair::generate();
        $state = bin2hex(random_bytes(self::STATE_BYTES));

        $parameters = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'state' => $state,
            'code_challenge' => $pkce->challenge,
            'code_challenge_method' => PkcePair::CHALLENGE_METHOD,
            'resource' => $resource->value,
        ];

        $scope = $scopes->toParameter();

        if (null !== $scope) {
            $parameters['scope'] = $scope;
        }

        if ($scopes->contains(ScopeSet::OFFLINE_ACCESS)) {
            $parameters['prompt'] = 'consent';
        }

        return new AuthorizationRedirect(
            self::appendQuery($endpoint, $parameters),
            $state,
            $metadata->issuer,
            true === $metadata->authorizationResponseIssParameterSupported,
            $pkce,
            $scopes,
        );
    }

    /**
     * @param array<string, string> $parameters
     */
    private static function appendQuery(string $endpoint, array $parameters): string
    {
        return $endpoint.(str_contains($endpoint, '?') ? '&' : '?').http_build_query($parameters);
    }
}
