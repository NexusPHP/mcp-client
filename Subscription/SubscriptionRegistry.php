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

use Nexus\Mcp\Core\Schema\RequestId;

/**
 * The `subscriptions/listen` streams the client currently holds open, keyed by subscription id.
 * `Client::listen()` registers one for the life of a stream, the dispatcher reads it when a
 * notification arrives tagged with that id, and a reconnect replays it against the fresh peer.
 *
 * @internal
 */
final class SubscriptionRegistry
{
    /**
     * @var array<non-empty-string, OpenSubscription>
     */
    private array $subscriptions = [];

    public function register(OpenSubscription $subscription): void
    {
        $this->subscriptions[self::buildKey($subscription->subscriptionId)] = $subscription;
    }

    /**
     * Removes the stream for `$id` and returns it, or `null` if it was already gone. Membership is what
     * marks a stream as still owing its caller an outcome, so every settlement claims it through here.
     */
    public function forget(RequestId $id): ?OpenSubscription
    {
        $key = self::buildKey($id);
        $subscription = $this->subscriptions[$key] ?? null;
        unset($this->subscriptions[$key]);

        return $subscription;
    }

    public function get(RequestId $id): ?OpenSubscription
    {
        return $this->subscriptions[self::buildKey($id)] ?? null;
    }

    /**
     * Every open stream, in the order it was opened.
     *
     * @return list<OpenSubscription>
     */
    public function all(): array
    {
        return array_values($this->subscriptions);
    }

    /**
     * Empties the registry and returns what it held, so a caller settling every stream cannot race a
     * re-entrant `unregister()` from the settlement itself.
     *
     * @return list<OpenSubscription>
     */
    public function drain(): array
    {
        $subscriptions = $this->subscriptions;
        $this->subscriptions = [];

        return array_values($subscriptions);
    }

    /**
     * @return non-empty-string
     */
    private static function buildKey(RequestId $id): string
    {
        return \sprintf('"subscriptionId":%s', var_export($id->id, true));
    }
}
