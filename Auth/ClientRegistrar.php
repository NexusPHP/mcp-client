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
use Nexus\Mcp\Client\Exception\AuthorizationServerMismatchException;
use Nexus\Mcp\Client\Exception\ClientRegistrationFailedException;
use Nexus\Mcp\Client\Exception\ClientRegistrationRequiredException;
use Nexus\Mcp\Core\Auth\AuthorizationServerMetadata;
use Nexus\Mcp\Core\Auth\MetadataReader;
use Nexus\Mcp\Core\Auth\TokenEndpointAuthMethod;

/**
 * Resolves the `client_id` to present to an authorization server, walking the mechanisms in the priority
 * order the spec fixes: pre-registered credentials, then a Client ID Metadata Document, then Dynamic Client
 * Registration.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration
 */
final readonly class ClientRegistrar
{
    private const string LABEL = 'Client registration response';

    private JsonHttpExchange $exchange;

    public function __construct(
        DelegateHttpClient $client,
        private ClientRegistrationStoreInterface $store,
        float $timeout = 10.0,
        private bool $allowInsecureLoopback = false,
    ) {
        $this->exchange = new JsonHttpExchange($client, $timeout);
    }

    public function resolve(
        AuthorizationServerMetadata $metadata,
        AuthorizationOptions $options,
        Cancellation $cancellation,
    ): ClientRegistration {
        $preRegistered = $options->preRegistered;

        if (null !== $preRegistered) {
            if ($preRegistered->issuer !== $metadata->issuer) {
                throw new AuthorizationServerMismatchException($preRegistered->issuer, $metadata->issuer);
            }

            return $preRegistered;
        }

        $documentUrl = $options->clientIdMetadataDocumentUrl;

        if (null !== $documentUrl && true === $metadata->clientIdMetadataDocumentSupported) {
            // A document URL is resolved by the authorization server on demand, so it is portable across
            // servers and never stored against one.
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

    /**
     * Drops the registration held for an authorization server, so the next resolution registers again.
     */
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

        SecureEndpoint::verifyAuthorizationServerUrl($endpoint, 'registration endpoint', $this->allowInsecureLoopback);

        $request = new Request($endpoint, 'POST', json_encode([
            'client_name' => $options->clientName,
            'redirect_uris' => [$options->redirectUri],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => TokenEndpointAuthMethod::None->value,
            'application_type' => $options->applicationType->value,
        ], \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES));
        $request->setHeader('Content-Type', 'application/json');

        [$status, $payload] = $this->exchange->send($request, $cancellation);
        $data = JsonHttpExchange::decode($payload, 'registration endpoint');

        if ($status >= 400) {
            throw new ClientRegistrationFailedException(
                MetadataReader::readErrorField($data, 'error', self::LABEL) ?? 'invalid_client_metadata',
                MetadataReader::readErrorField($data, 'error_description', self::LABEL),
            );
        }

        $secret = MetadataReader::readString($data, 'client_secret', self::LABEL);

        return new ClientRegistration(
            MetadataReader::readRequiredString($data, 'client_id', self::LABEL),
            $metadata->issuer,
            $secret,
            self::resolveAuthMethod($data, $secret),
        );
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function resolveAuthMethod(array $data, ?string $secret): TokenEndpointAuthMethod
    {
        $declared = MetadataReader::readString($data, 'token_endpoint_auth_method', self::LABEL);

        if (null === $declared) {
            // RFC 7591 registers `client_secret_basic` by default, which only applies once a secret exists.
            return null === $secret ? TokenEndpointAuthMethod::None : TokenEndpointAuthMethod::ClientSecretBasic;
        }

        return TokenEndpointAuthMethod::tryFrom($declared) ?? throw new ClientRegistrationFailedException(
            'invalid_client_metadata',
            \sprintf('The client was registered with the unsupported "%s" token endpoint authentication method.', $declared),
        );
    }
}
