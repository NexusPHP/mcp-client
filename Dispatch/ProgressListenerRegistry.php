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

namespace Nexus\Mcp\Client\Dispatch;

use Nexus\Mcp\Core\Schema\ProgressToken;

/**
 * Per-call progress listeners keyed by progress token. `Client::callTool()`
 * registers a listener for the duration of a call. The routing progress
 * handler reads it when a matching `notifications/progress` arrives.
 *
 * @internal
 */
final class ProgressListenerRegistry
{
    /**
     * @var array<non-empty-string, \Closure(float, ?float, ?string): void>
     */
    private array $listeners = [];

    /**
     * @param \Closure(float $progress, ?float $total, ?string $message): void $onProgress
     */
    public function register(ProgressToken $token, \Closure $onProgress): void
    {
        $this->listeners[self::key($token)] = $onProgress;
    }

    public function unregister(ProgressToken $token): void
    {
        unset($this->listeners[self::key($token)]);
    }

    /**
     * @return null|\Closure(float $progress, ?float $total, ?string $message): void
     */
    public function get(ProgressToken $token): ?\Closure
    {
        return $this->listeners[self::key($token)] ?? null;
    }

    /**
     * @return non-empty-string
     */
    private static function key(ProgressToken $token): string
    {
        return \sprintf('"progressToken":%s', var_export($token->token, true));
    }
}
