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

namespace Nexus\Mcp\Client\Subscription;

use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcNotification;
use Nexus\Mcp\Core\Schema\RequestId;

/**
 * Per-stream notification listeners keyed by subscription id. `Client::listen()` registers one for the
 * life of a stream, and the dispatcher reads it when a notification arrives tagged with that id.
 *
 * @internal
 */
final class SubscriptionListenerRegistry
{
    /**
     * @var array<non-empty-string, \Closure(JsonRpcNotification<non-empty-string>): void>
     */
    private array $listeners = [];

    /**
     * @param \Closure(JsonRpcNotification<non-empty-string>): void $onNotification
     */
    public function register(RequestId $id, \Closure $onNotification): void
    {
        $this->listeners[self::buildKey($id)] = $onNotification;
    }

    public function unregister(RequestId $id): void
    {
        unset($this->listeners[self::buildKey($id)]);
    }

    /**
     * @return null|\Closure(JsonRpcNotification<non-empty-string>): void
     */
    public function get(RequestId $id): ?\Closure
    {
        return $this->listeners[self::buildKey($id)] ?? null;
    }

    /**
     * @return non-empty-string
     */
    private static function buildKey(RequestId $id): string
    {
        return \sprintf('"subscriptionId":%s', var_export($id->id, true));
    }
}
