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

use Amp\Cancellation;
use Nexus\Assert\Assert;

/**
 * The OAuth 2.1 authorization-code grant.
 *
 * @internal
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
 */
final readonly class AuthorizationCodeGrantStrategy implements GrantStrategyInterface
{
    public function __construct(private UserAuthorizationInterface $userAuthorization)
    {
    }

    #[\Override]
    public function grant(GrantContext $context, Cancellation $cancellation): AccessToken
    {
        $redirectUri = $context->options->redirectUri;
        Assert::that($redirectUri)->isNonEmptyString('The authorization-code grant needs a redirect URI, and the authorization options carry none.');

        $registration = $context->resolveRegistration($cancellation);

        $redirect = AuthorizationRequest::build(
            $context->discovered->server,
            $registration->clientId,
            $redirectUri,
            $context->resource,
            $context->scopes,
            new SecureEndpoint($context->options->allowInsecureLoopback),
        );

        $code = AuthorizationResponse::readCode(
            $redirect,
            $this->userAuthorization->authorize($redirect, $cancellation),
        );

        return $context->requestToken(
            $registration,
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $redirectUri,
                'code_verifier' => $redirect->pkce->verifier,
                'resource' => $context->resource->value,
            ],
            $cancellation,
            $redirect->requestedScopes,
        );
    }

    #[\Override]
    public function renewsByFreshGrant(): bool
    {
        return false;
    }
}
