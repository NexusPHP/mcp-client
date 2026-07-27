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
use Amp\Http\Client\Request;
use Nexus\Assert\Assert;
use Nexus\Mcp\Client\Exception\AuthorizationGrantRejectedException;
use Nexus\Mcp\Client\Exception\ClientRegistrationRejectedException;
use Nexus\Mcp\Client\Exception\TokenRequestFailedException;
use Nexus\Mcp\Core\Auth\AuthorizationServerMetadata;
use Nexus\Mcp\Core\Auth\MetadataReader;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\ScopeSet;
use Nexus\Mcp\Core\Auth\TokenEndpointAuthMethod;
use Nexus\Mcp\Core\Auth\WwwAuthenticateChallenge;

/**
 * Redeems an authorization code, and later a refresh token, at an authorization server's token endpoint.
 *
 * @internal
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-6
 */
final readonly class TokenEndpoint
{
    private const string LABEL = 'Token response';

    /**
     * RFC 6749 error codes that mean the grant presented cannot produce a token. Every other code is a
     * client, configuration, or server fault that granting again would not clear.
     */
    private const array GRANT_REJECTIONS = ['invalid_grant', 'invalid_scope'];

    /**
     * The RFC 6749 error code that means the client identifier presented is not one the server knows.
     */
    private const string CLIENT_REJECTION = 'invalid_client';

    private JsonHttpExchange $exchange;

    public function __construct(DelegateHttpClient $client, float $timeout = 10.0)
    {
        $this->exchange = new JsonHttpExchange($client, $timeout);
    }

    public function exchangeCode(
        AuthorizationServerMetadata $metadata,
        ClientRegistration $registration,
        AuthorizationRedirect $redirect,
        string $code,
        string $redirectUri,
        ResourceIdentifier $resource,
    ): AccessToken {
        return $this->send($metadata, $registration, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $redirect->pkce->verifier,
            'resource' => $resource->value,
        ], $resource, $redirect->requestedScopes, null);
    }

    public function refresh(
        AuthorizationServerMetadata $metadata,
        ClientRegistration $registration,
        AccessToken $token,
        ResourceIdentifier $resource,
    ): AccessToken {
        $refreshToken = $token->refreshToken;
        Assert::that($refreshToken)->not()->isNull('The access token carries no refresh token to redeem.');

        return $this->send($metadata, $registration, [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'resource' => $resource->value,
        ], $resource, new ScopeSet($token->scopes), $refreshToken);
    }

    /**
     * @param array<string, string> $parameters
     * @param ScopeSet              $requestedScopes   Scopes the token carries when the response names none
     * @param ?string               $priorRefreshToken Refresh token kept when the response rotates none
     */
    private function send(
        AuthorizationServerMetadata $metadata,
        ClientRegistration $registration,
        array $parameters,
        ResourceIdentifier $resource,
        ScopeSet $requestedScopes,
        ?string $priorRefreshToken,
    ): AccessToken {
        $endpoint = $metadata->tokenEndpoint;
        Assert::that($endpoint)->not()->isNull(\sprintf(
            'The authorization server "%s" publishes no token endpoint.',
            $metadata->issuer,
        ));
        SecureEndpoint::verifyAdvertised($endpoint, 'token endpoint', $resource);

        $headers = ['Content-Type' => 'application/x-www-form-urlencoded'];

        // RFC 6749 lets a client authenticate one way only, so the identifier travels in the header or in
        // the body but never in both.
        if (TokenEndpointAuthMethod::ClientSecretBasic === $registration->tokenEndpointAuthMethod) {
            $headers['Authorization'] = self::buildBasicCredentials($registration);
        } else {
            $parameters['client_id'] = $registration->clientId;

            if (TokenEndpointAuthMethod::ClientSecretPost === $registration->tokenEndpointAuthMethod) {
                $secret = $registration->clientSecret;
                Assert::that($secret)->not()->isNull(self::describeMissingSecret($registration));
                $parameters['client_secret'] = $secret;
            }
        }

        $request = new Request($endpoint, 'POST', http_build_query($parameters));
        $request->setHeaders($headers);

        [$status, $payload] = $this->exchange->send($request);
        $data = JsonHttpExchange::decode($payload, 'token endpoint');

        if ($status >= 400) {
            $error = MetadataReader::readString($data, 'error', self::LABEL) ?? 'invalid_request';
            $description = MetadataReader::readString($data, 'error_description', self::LABEL);

            throw match (true) {
                self::CLIENT_REJECTION === $error => new ClientRegistrationRejectedException($description),
                \in_array($error, self::GRANT_REJECTIONS, true) => new AuthorizationGrantRejectedException($error, $description),
                default => new TokenRequestFailedException($error, $description),
            };
        }

        return self::readToken($data, $metadata->issuer, $requestedScopes, $priorRefreshToken);
    }

    /**
     * @param array<string, mixed> $data
     * @param string               $issuer Stamped on the token so a store can be read back without repeating discovery
     */
    private static function readToken(array $data, string $issuer, ScopeSet $requestedScopes, ?string $priorRefreshToken): AccessToken
    {
        $type = MetadataReader::readRequiredString($data, 'token_type', self::LABEL);

        if (strcasecmp($type, WwwAuthenticateChallenge::BEARER_SCHEME) !== 0) {
            throw new TokenRequestFailedException(
                'unsupported_token_type',
                \sprintf('MCP clients can only present bearer tokens, "%s" given.', $type),
            );
        }

        $lifetime = MetadataReader::readInt($data, 'expires_in', self::LABEL);
        $scope = MetadataReader::readString($data, 'scope', self::LABEL);

        return new AccessToken(
            MetadataReader::readRequiredString($data, 'access_token', self::LABEL),
            $issuer,
            null === $lifetime ? null : time() + $lifetime,
            // A server that rotates refresh tokens issues a new one and the old is spent. One that omits it
            // leaves the prior token valid, so dropping it here would strand the client after one renewal.
            MetadataReader::readString($data, 'refresh_token', self::LABEL) ?? $priorRefreshToken,
            null === $scope ? $requestedScopes->values : ScopeSet::parse($scope)->values,
        );
    }

    private static function buildBasicCredentials(ClientRegistration $registration): string
    {
        $secret = $registration->clientSecret;
        Assert::that($secret)->not()->isNull(self::describeMissingSecret($registration));

        return 'Basic '.base64_encode(urlencode($registration->clientId).':'.urlencode($secret));
    }

    /**
     * @return non-empty-string
     */
    private static function describeMissingSecret(ClientRegistration $registration): string
    {
        return \sprintf(
            'Client "%s" must carry a secret to authenticate with "%s".',
            $registration->clientId,
            $registration->tokenEndpointAuthMethod->value,
        );
    }
}
