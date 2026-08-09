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
use Amp\Http\Client\DelegateHttpClient;
use Amp\Http\Client\Request;
use Nexus\Assert\Assert;
use Nexus\Mcp\Client\Exception\AuthorizationGrantRejectedException;
use Nexus\Mcp\Client\Exception\ClientRegistrationRejectedException;
use Nexus\Mcp\Client\Exception\MalformedAuthorizationResponseException;
use Nexus\Mcp\Client\Exception\TokenRequestFailedException;
use Nexus\Mcp\Core\Auth\AuthorizationServerMetadata;
use Nexus\Mcp\Core\Auth\MetadataReader;
use Nexus\Mcp\Core\Auth\ResourceIdentifier;
use Nexus\Mcp\Core\Auth\ScopeSet;
use Nexus\Mcp\Core\Auth\TokenEndpointAuthMethod;
use Nexus\Mcp\Core\Auth\WwwAuthenticateChallenge;
use Nexus\Mcp\Core\Http\HttpStatus;

/**
 * Client for an authorization server's token endpoint.
 *
 * @internal
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-6
 */
final readonly class TokenEndpoint
{
    private const string LABEL = 'Token response';
    private const array GRANT_REJECTIONS = ['invalid_grant', 'invalid_scope'];
    private const string CLIENT_REJECTION = 'invalid_client';
    private const int MAX_LIFETIME_SECONDS = 315_360_000;

    private JsonHttpExchange $exchange;

    public function __construct(
        DelegateHttpClient $client,
        float $timeout = 10.0,
        private bool $allowInsecureLoopback = false,
    ) {
        $this->exchange = new JsonHttpExchange($client, $timeout);
    }

    public function refresh(
        AuthorizationServerMetadata $metadata,
        ClientRegistration $registration,
        AccessToken $token,
        ResourceIdentifier $resource,
        Cancellation $cancellation,
    ): AccessToken {
        $refreshToken = $token->refreshToken;
        Assert::that($refreshToken)->isString('The access token carries no refresh token to redeem.');

        return $this->send($metadata, $registration, [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'resource' => $resource->value,
        ], new ScopeSet($token->scopes), $refreshToken, $cancellation);
    }

    /**
     * @param array<string, string> $parameters      Full form body of the grant, `grant_type` included
     * @param ScopeSet              $requestedScopes Scopes the token carries when the response names none
     */
    public function requestToken(
        AuthorizationServerMetadata $metadata,
        ClientRegistration $registration,
        array $parameters,
        ScopeSet $requestedScopes,
        Cancellation $cancellation,
    ): AccessToken {
        return $this->send($metadata, $registration, $parameters, $requestedScopes, null, $cancellation);
    }

    /**
     * @param array<string, string> $parameters
     * @param ScopeSet              $requestedScopes   Scopes the token carries when the response names none
     * @param null|string           $priorRefreshToken Refresh token kept when the response rotates none
     */
    private function send(
        AuthorizationServerMetadata $metadata,
        ClientRegistration $registration,
        array $parameters,
        ScopeSet $requestedScopes,
        ?string $priorRefreshToken,
        Cancellation $cancellation,
    ): AccessToken {
        $endpoint = $metadata->tokenEndpoint;
        Assert::that($endpoint)->isNonEmptyString(\sprintf(
            'The authorization server "%s" publishes no token endpoint.',
            $metadata->issuer,
        ));
        SecureEndpoint::verifyAuthorizationServerUrl($endpoint, 'token endpoint', $this->allowInsecureLoopback);

        $headers = ['Content-Type' => 'application/x-www-form-urlencoded'];

        if (TokenEndpointAuthMethod::ClientSecretBasic === $registration->tokenEndpointAuthMethod) {
            $headers['Authorization'] = self::buildBasicCredentials($registration);
        } elseif (TokenEndpointAuthMethod::PrivateKeyJwt === $registration->tokenEndpointAuthMethod) {
            Assert::that($parameters)->hasOffset('client_assertion', \sprintf(
                'Client "%s" must carry a "client_assertion" parameter to authenticate with "private_key_jwt".',
                $registration->clientId,
            ));
        } else {
            $parameters['client_id'] = $registration->clientId;

            if (TokenEndpointAuthMethod::ClientSecretPost === $registration->tokenEndpointAuthMethod) {
                $secret = $registration->clientSecret;
                Assert::that($secret)->isString(self::describeMissingSecret($registration));
                $parameters['client_secret'] = $secret;
            }
        }

        $request = new Request($endpoint, 'POST', http_build_query($parameters));
        $request->setHeaders($headers);

        [$status, $payload] = $this->exchange->send($request, $cancellation);

        try {
            $data = JsonHttpExchange::decode($payload, 'token endpoint');
        } catch (MalformedAuthorizationResponseException $e) {
            if (HttpStatus::Ok->value === $status) {
                throw $e;
            }

            throw new TokenRequestFailedException(
                'invalid_request',
                \sprintf('The token endpoint answered %d with a body that is not a JSON object.', $status),
            );
        }

        if ($status >= HttpStatus::BadRequest->value) {
            $error = MetadataReader::readErrorField($data, 'error', self::LABEL) ?? 'invalid_request';
            $description = MetadataReader::readErrorField($data, 'error_description', self::LABEL);

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
            null === $lifetime ? null : time() + min($lifetime, self::MAX_LIFETIME_SECONDS),
            MetadataReader::readString($data, 'refresh_token', self::LABEL) ?? $priorRefreshToken,
            null === $scope ? $requestedScopes->values : ScopeSet::parse($scope)->values,
        );
    }

    private static function buildBasicCredentials(ClientRegistration $registration): string
    {
        $secret = $registration->clientSecret;
        Assert::that($secret)->isString(self::describeMissingSecret($registration));

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
