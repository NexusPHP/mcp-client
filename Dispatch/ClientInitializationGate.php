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

use Nexus\Mcp\Core\Dispatch\InitializationState;
use Nexus\Mcp\Core\Schema\Request\InitializeRequest;
use Nexus\Mcp\Core\Schema\Request\PingRequest;

/**
 * Tracks the client-initiated handshake lifecycle and decides which outbound
 * request methods may be sent before it completes.
 */
final class ClientInitializationGate
{
    private InitializationState $state = InitializationState::AwaitingInitialize;

    public function isInitialized(): bool
    {
        return InitializationState::Initialized === $this->state;
    }

    /**
     * @param non-empty-string $requestMethod
     */
    public function allowsRequest(string $requestMethod): bool
    {
        if (InitializeRequest::getMethod() === $requestMethod) {
            return InitializationState::AwaitingInitialize === $this->state;
        }

        return $this->isInitialized() || PingRequest::getMethod() === $requestMethod;
    }

    /**
     * Transitions `AwaitingInitialize` -> `InitializeInFlight`. Returns `true` if the transition fired.
     */
    public function markInitializeInFlight(): bool
    {
        if (InitializationState::AwaitingInitialize !== $this->state) {
            return false;
        }

        $this->state = InitializationState::InitializeInFlight;

        return true;
    }

    /**
     * Transitions `InitializeInFlight` -> `Initialized`. Returns `true` if the transition fired.
     */
    public function markInitialized(): bool
    {
        if (InitializationState::InitializeInFlight !== $this->state) {
            return false;
        }

        $this->state = InitializationState::Initialized;

        return true;
    }

    /**
     * Reverts `InitializeInFlight` -> `AwaitingInitialize`. Returns `true` if the transition fired.
     */
    public function revertInitializeInFlight(): bool
    {
        if (InitializationState::InitializeInFlight !== $this->state) {
            return false;
        }

        $this->state = InitializationState::AwaitingInitialize;

        return true;
    }
}
