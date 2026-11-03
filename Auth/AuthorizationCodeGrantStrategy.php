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
use Nexus\Mcp\Client\Exception\InvalidAuthorizationResponseException;
use Nexus\Mcp\Client\Exception\PkceNotSupportedException;
use Nexus\Mcp\Core\Auth\AuthorizationServerMetadata;
use Nexus\Mcp\Core\Auth\MetadataReader;
use Nexus\Mcp\Core\Auth\ScopeSet;
use Nexus\Mcp\Core\Exception\RuntimeException;
use Nexus\Mcp\Core\SafeDisplay;

/**
 * The OAuth 2.1 authorization-code grant.
 *
 * @internal
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
 */
final readonly class AuthorizationCodeGrantStrategy implements GrantStrategyInterface
{
    private const int STATE_BYTES = 32;

    public function __construct(private UserAuthorizationInterface $userAuthorization)
    {
    }

    #[\Override]
    public function grant(GrantContext $context, Cancellation $cancellation): AccessToken
    {
        $redirectUri = $context->options->redirectUri;
        Assert::that($redirectUri)->isNonEmptyString(
            'The authorization-code grant needs a redirect URI, and the authorization options carry none.',
        );

        $this->verifyPkceSupport($context->discovered->server);

        $registration = $context->resolveRegistration($cancellation);

        $redirect = $this->buildRedirect($context, $registration->clientId, $redirectUri);

        $code = $this->readCode($redirect, $this->userAuthorization->authorize($redirect, $cancellation));

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

    /**
     * @throws PkceNotSupportedException
     */
    private function verifyPkceSupport(AuthorizationServerMetadata $server): void
    {
        $methods = $server->codeChallengeMethodsSupported;

        if (null === $methods || ! \in_array(PkcePair::CHALLENGE_METHOD, $methods, true)) {
            throw new PkceNotSupportedException($server->issuer);
        }
    }

    /**
     * Builds the OAuth 2.1 authorization request that the user-agent opens.
     *
     * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-flow-steps
     */
    private function buildRedirect(GrantContext $context, string $clientId, string $redirectUri): AuthorizationRedirect
    {
        $metadata = $context->discovered->server;
        $endpoint = $metadata->authorizationEndpoint;
        Assert::that($endpoint)->isNonEmptyString(\sprintf(
            'The authorization server "%s" publishes no authorization endpoint.',
            SafeDisplay::sanitiseCause($metadata->issuer),
        ));
        (new SecureEndpoint($context->options->allowInsecureLoopback))
            ->verifyAuthorizationServerUrl($endpoint, 'authorization endpoint')
        ;

        $pkce = PkcePair::generate();
        $state = bin2hex(random_bytes(self::STATE_BYTES));

        $parameters = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'state' => $state,
            'code_challenge' => $pkce->challenge,
            'code_challenge_method' => PkcePair::CHALLENGE_METHOD,
            'resource' => $context->resource->value,
        ];

        $scope = $context->scopes->toParameter();

        if (null !== $scope) {
            $parameters['scope'] = $scope;
        }

        if (! $context->options->skipOfflineAccessConsent && $context->scopes->contains(ScopeSet::OFFLINE_ACCESS)) {
            $parameters['prompt'] = 'consent';
        }

        return new AuthorizationRedirect(
            $endpoint.(str_contains($endpoint, '?') ? '&' : '?').http_build_query($parameters),
            $state,
            $metadata->issuer,
            true === $metadata->authorizationResponseIssParameterSupported,
            $pkce,
            $context->scopes,
        );
    }

    /**
     * Reads the authorization code from an authorization response once its state and issuer check out.
     *
     * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation
     */
    private function readCode(AuthorizationRedirect $redirect, AuthorizationCallback $callback): string
    {
        $reader = new MetadataReader('Authorization response');
        $parameters = $callback->parameters;

        if (! hash_equals($redirect->state, $parameters['state'] ?? '')) {
            throw new InvalidAuthorizationResponseException('its "state" does not echo the authorization request.');
        }

        $this->verifyIssuer($redirect, $parameters);

        $error = $reader->readErrorField($parameters, 'error');

        if (null !== $error) {
            $description = $reader->readErrorField($parameters, 'error_description');

            throw new RuntimeException(\sprintf(
                'The authorization server denied the request with "%s"%s',
                $error,
                null === $description ? '.' : \sprintf(': %s', $description),
            ));
        }

        $code = $parameters['code'] ?? null;

        if (null === $code) {
            throw new InvalidAuthorizationResponseException('it carries no authorization code.');
        }

        return $code;
    }

    /**
     * @param array<array-key, string> $parameters
     */
    private function verifyIssuer(AuthorizationRedirect $redirect, array $parameters): void
    {
        $issuer = $parameters['iss'] ?? null;

        if (null === $issuer) {
            if ($redirect->issuerParameterRequired) {
                throw new InvalidAuthorizationResponseException(
                    'it omits the "iss" the authorization server advertises that it emits.',
                );
            }

            return;
        }

        if ($issuer !== $redirect->expectedIssuer) {
            throw new InvalidAuthorizationResponseException(
                'its "iss" names an authorization server other than the one the request was sent to.',
            );
        }
    }
}
