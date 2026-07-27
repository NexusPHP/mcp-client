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

/**
 * The authorization response an MCP client receives, read from the redirect URI the user-agent landed on.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9207#section-2.4
 */
final readonly class AuthorizationCallback
{
    /**
     * @var array<array-key, string>
     */
    public array $parameters;

    /**
     * @param string $callbackUrl The redirect URI the user-agent arrived at, query string included
     */
    public function __construct(string $callbackUrl)
    {
        $query = parse_url($callbackUrl, \PHP_URL_QUERY);
        $parameters = [];

        if (\is_string($query)) {
            parse_str($query, $parsed);

            foreach ($parsed as $name => $value) {
                if (\is_string($value)) {
                    $parameters[$name] = $value;
                }
            }
        }

        $this->parameters = $parameters;
    }
}
