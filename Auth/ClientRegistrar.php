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
use Nexus\Mcp\Client\Exception\AuthorizationServerMismatchException;
use Nexus\Mcp\Client\Exception\ClientRegistrationRequiredException;
use Nexus\Mcp\Core\Auth\AuthorizationServerMetadata;
use Nexus\Mcp\Core\Auth\MetadataReader;
use Nexus\Mcp\Core\Auth\TokenEndpointAuthMethod;
use Nexus\Mcp\Core\Exception\RuntimeException;
use Nexus\Mcp\Core\SafeDisplay;

/**
 * Resolver for the `client_id` an MCP client presents to an authorization server.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration
 */
final readonly class ClientRegistrar
{
    private JsonHttpExchange $exchange;
    private MetadataReader $reader;

    public function __construct(
        DelegateHttpClient $client,
        private ClientRegistrationStoreInterface $store,
        float $timeout = 10.0,
        private SecureEndpoint $secureEndpoint = new SecureEndpoint(),
    ) {
        $this->exchange = new JsonHttpExchange($client, 'registration endpoint', $timeout);
        $this->reader = new MetadataReader('Client registration response');
    }

    public function resolve(
        AuthorizationServerMetadata $metadata,
        AuthorizationOptions $options,
        Cancellation $cancellation,
    ): ClientRegistration {
        $preRegistered = $options->preRegistered;

        if (null !== $preRegistered) {
            if (null === $preRegistered->issuer) {
                return new ClientRegistration(
                    $preRegistered->clientId,
                    $metadata->issuer,
                    $preRegistered->clientSecret,
                    $this->bindAuthMethod($preRegistered),
                );
            }

            if ($preRegistered->issuer !== $metadata->issuer) {
                throw new AuthorizationServerMismatchException($preRegistered->issuer, $metadata->issuer);
            }

            return $preRegistered;
        }

        $documentUrl = $options->clientIdMetadataDocumentUrl;

        if (null !== $documentUrl && true === $metadata->clientIdMetadataDocumentSupported) {
            return new ClientRegistration($documentUrl, $metadata->issuer);
        }

        $stored = $this->store->read($metadata->issuer);

        if (null !== $stored) {
            return $stored;
        }

        $registration = $this->register($metadata, $options, $cancellation);
        $this->store->write($metadata->issuer, $registration);

        return $registration;
    }

    public function forget(string $issuer): void
    {
        $this->store->forget($issuer);
    }

    private function register(
        AuthorizationServerMetadata $metadata,
        AuthorizationOptions $options,
        Cancellation $cancellation,
    ): ClientRegistration {
        $endpoint = $metadata->registrationEndpoint;

        if (null === $endpoint) {
            throw new ClientRegistrationRequiredException($metadata->issuer);
        }

        $redirectUri = $options->redirectUri;
        Assert::that($redirectUri)->isNonEmptyString('Dynamic Client Registration needs a redirect URI, and the authorization options carry none.');

        $this->secureEndpoint->verifyAuthorizationServerUrl($endpoint, 'registration endpoint');

        $request = new Request($endpoint, 'POST', json_encode([
            'client_name' => $options->clientName,
            'redirect_uris' => [$redirectUri],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => TokenEndpointAuthMethod::None->value,
            'application_type' => $options->applicationType->value,
        ], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES));
        $request->setHeader('Content-Type', 'application/json');

        [$status, $payload] = $this->exchange->send($request, $cancellation);
        $data = $this->exchange->decode($payload);

        if ($status >= 400) {
            throw $this->buildRegistrationFailure(
                $this->reader->readErrorField($data, 'error') ?? 'invalid_client_metadata',
                $this->reader->readErrorField($data, 'error_description'),
            );
        }

        $secret = $this->reader->readString($data, 'client_secret');

        return new ClientRegistration(
            $this->reader->readRequiredString($data, 'client_id'),
            $metadata->issuer,
            $secret,
            $this->resolveAuthMethod($data, $secret),
        );
    }

    private function bindAuthMethod(ClientRegistration $registration): TokenEndpointAuthMethod
    {
        if (TokenEndpointAuthMethod::None !== $registration->tokenEndpointAuthMethod || null === $registration->clientSecret) {
            return $registration->tokenEndpointAuthMethod;
        }

        return TokenEndpointAuthMethod::ClientSecretBasic;
    }

    /**
     * @param array<string, mixed> $data
     */
    private function resolveAuthMethod(array $data, ?string $secret): TokenEndpointAuthMethod
    {
        $declared = $this->reader->readString($data, 'token_endpoint_auth_method');

        if (null === $declared) {
            return null === $secret ? TokenEndpointAuthMethod::None : TokenEndpointAuthMethod::ClientSecretBasic;
        }

        $method = TokenEndpointAuthMethod::tryFrom($declared);

        if (null === $method || TokenEndpointAuthMethod::PrivateKeyJwt === $method) {
            throw $this->buildRegistrationFailure(
                'invalid_client_metadata',
                \sprintf('The client was registered with the unsupported "%s" token endpoint authentication method.', SafeDisplay::sanitise($declared)),
            );
        }

        return $method;
    }

    private function buildRegistrationFailure(string $error, ?string $description): RuntimeException
    {
        return new RuntimeException(\sprintf(
            'Dynamic Client Registration failed with "%s"%s',
            $error,
            null === $description ? '.' : \sprintf(': %s', $description),
        ));
    }
}
