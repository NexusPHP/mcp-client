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

namespace Nexus\Mcp\Client\Handler\Request;

use Nexus\Mcp\Client\ClientContext;
use Nexus\Mcp\Client\Dispatch\DiscoveredServerCapabilities;
use Nexus\Mcp\Core\Exception\MethodNotFoundException;
use Nexus\Mcp\Core\Handler\AbstractContext;
use Nexus\Mcp\Core\Handler\RequestHandlerInterface;
use Nexus\Mcp\Core\Schema\JsonRpc\JsonRpcRequest;
use Nexus\Mcp\Core\Schema\Result;

/**
 * Gate refusing an extension-owned inbound request from a server that did not advertise the extension.
 *
 * @internal
 *
 * @implements RequestHandlerInterface<non-empty-string, Result, ClientContext>
 */
final readonly class ExtensionGateRequestHandler implements RequestHandlerInterface
{
    /**
     * @param non-empty-string                                                 $identifier
     * @param RequestHandlerInterface<non-empty-string, Result, ClientContext> $handler
     */
    public function __construct(
        private string $identifier,
        private RequestHandlerInterface $handler,
        private DiscoveredServerCapabilities $serverCapabilities,
    ) {
    }

    #[\Override]
    public function handle(JsonRpcRequest $request, AbstractContext $context): Result
    {
        \assert($context instanceof ClientContext);
        $capabilities = $this->serverCapabilities->current();

        if (null !== $capabilities && ! \array_key_exists($this->identifier, $capabilities->extensions ?? [])) {
            throw new MethodNotFoundException($request::getMethod(), $request->id);
        }

        return $this->handler->handle($request, $context);
    }
}
