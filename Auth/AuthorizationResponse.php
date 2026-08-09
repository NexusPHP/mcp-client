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

use Nexus\Mcp\Client\Exception\AuthorizationDeniedException;
use Nexus\Mcp\Client\Exception\InvalidAuthorizationResponseException;
use Nexus\Mcp\Core\Auth\MetadataReader;

/**
 * Validated read of the authorization code an authorization response carries.
 *
 * @internal
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#authorization-response-validation
 */
final class AuthorizationResponse
{
    private const string LABEL = 'Authorization response';

    public static function readCode(AuthorizationRedirect $redirect, AuthorizationCallback $callback): string
    {
        $parameters = $callback->parameters;

        if (! hash_equals($redirect->state, $parameters['state'] ?? '')) {
            throw new InvalidAuthorizationResponseException('its "state" does not echo the authorization request.');
        }

        self::validateIssuer($redirect, $parameters);

        $error = MetadataReader::readErrorField($parameters, 'error', self::LABEL);

        if (null !== $error) {
            throw new AuthorizationDeniedException($error, MetadataReader::readErrorField($parameters, 'error_description', self::LABEL));
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
    private static function validateIssuer(AuthorizationRedirect $redirect, array $parameters): void
    {
        $issuer = $parameters['iss'] ?? null;

        if (null === $issuer) {
            if ($redirect->issuerParameterRequired) {
                throw new InvalidAuthorizationResponseException('it omits the "iss" the authorization server advertises that it emits.');
            }

            return;
        }

        if ($issuer !== $redirect->expectedIssuer) {
            throw new InvalidAuthorizationResponseException('its "iss" names an authorization server other than the one the request was sent to.');
        }
    }
}
