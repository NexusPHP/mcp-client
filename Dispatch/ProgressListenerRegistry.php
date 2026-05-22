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
     * @var array<int|non-empty-string, \Closure(float, ?float, ?string): void>
     */
    private array $listeners = [];

    /**
     * @param \Closure(float $progress, ?float $total, ?string $message): void $onProgress
     */
    public function register(ProgressToken $token, \Closure $onProgress): void
    {
        $this->listeners[$token->token] = $onProgress;
    }

    public function unregister(ProgressToken $token): void
    {
        unset($this->listeners[$token->token]);
    }

    /**
     * @return null|\Closure(float $progress, ?float $total, ?string $message): void
     */
    public function get(ProgressToken $token): ?\Closure
    {
        return $this->listeners[$token->token] ?? null;
    }
}
