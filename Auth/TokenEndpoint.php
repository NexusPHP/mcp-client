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
use Amp\NullCancellation;
use Nexus\Assert\Assert;
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
    private const int MAX_RESPONSE_BYTES = 65536;

    public function __construct(private DelegateHttpClient $client, private float $timeout = 10.0)
    {
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
        ], $redirect->requestedScopes);
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
        ], new ScopeSet($token->scopes));
    }

    /**
     * @param array<string, string> $parameters
     * @param ScopeSet              $requestedScopes Scopes the token carries when the response names none
     */
    private function send(
        AuthorizationServerMetadata $metadata,
        ClientRegistration $registration,
        array $parameters,
        ScopeSet $requestedScopes,
    ): AccessToken {
        $endpoint = $metadata->tokenEndpoint;
        Assert::that($endpoint)->not()->isNull(\sprintf(
            'The authorization server "%s" publishes no token endpoint.',
            $metadata->issuer,
        ));
        SecureEndpoint::verify($endpoint, 'token endpoint');

        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Accept' => 'application/json',
        ];

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
        $request->setTransferTimeout($this->timeout);
        $request->setInactivityTimeout($this->timeout);

        $response = $this->client->request($request, new NullCancellation());
        $payload = $response->getBody()->buffer(limit: self::MAX_RESPONSE_BYTES);
        $data = json_decode($payload, associative: true, flags: \JSON_THROW_ON_ERROR);
        Assert::that($data)->isMap('The token endpoint answered with a payload that is not a JSON object.');

        if ($response->getStatus() >= 400) {
            throw new TokenRequestFailedException(
                MetadataReader::readString($data, 'error', self::LABEL) ?? 'invalid_request',
                MetadataReader::readString($data, 'error_description', self::LABEL),
            );
        }

        return self::readToken($data, $requestedScopes);
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function readToken(array $data, ScopeSet $requestedScopes): AccessToken
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
            null === $lifetime ? null : time() + $lifetime,
            MetadataReader::readString($data, 'refresh_token', self::LABEL),
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
