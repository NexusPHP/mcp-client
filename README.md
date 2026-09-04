# Nexus MCP SDK: Client

[![PHP](http://poser.pugx.org/nexusphp/mcp-client/require/php)](https://packagist.org/packages/nexusphp/mcp-client)
[![Latest Stable Version](http://poser.pugx.org/nexusphp/mcp-client/v)](https://packagist.org/packages/nexusphp/mcp-client)
[![License](https://img.shields.io/github/license/NexusPHP/mcp)](LICENSE)

The client half of the [Nexus MCP SDK](https://github.com/NexusPHP/mcp): a `ClientBuilder`, a
`Client` with one typed method per MCP capability, transports for spawned stdio servers and
Streamable HTTP endpoints, and the OAuth authorization flow with pluggable token stores.

> [!IMPORTANT]
> This repository is a read-only subtree split of [NexusPHP/mcp](https://github.com/NexusPHP/mcp).
> Open issues and pull requests there. Anything opened here is closed automatically with the same pointer.

## Installation

```bash
composer require nexusphp/mcp-client
```

This pulls in `nexusphp/mcp-core`. The umbrella `nexusphp/mcp` ships the server and the official
extensions alongside it.

## What is inside

| Namespace | Contents |
| --- | --- |
| `Nexus\Mcp\Client` | `ClientBuilder`, `Client`, and `ClientContext` |
| `Nexus\Mcp\Client\Transport` | `StdioClientTransport`, `StreamableHttpClientTransport`, and `SupervisedTransport` |
| `Nexus\Mcp\Client\Auth` | The authorization coordinator, grant strategies, PKCE, and the token and registration stores |
| `Nexus\Mcp\Client\Dispatch` and `Nexus\Mcp\Client\Handler` | Request deadlines, progress, and the notification handler registry |
| `Nexus\Mcp\Client\Subscription` | The `subscriptions/listen` consumer |
| `Nexus\Mcp\Client\Extension` and `Nexus\Mcp\Client\Time` | The outbound extension gate and the cancellable delay |

## Documentation

- [Getting started](https://nexusphp.github.io/mcp/getting-started/) and the
  [Client API overview](https://nexusphp.github.io/mcp/client/).
- [Transports](https://nexusphp.github.io/mcp/transports/) and the
  [client authorization](https://nexusphp.github.io/mcp/auth/client/) guide.
- [API reference](https://nexusphp.github.io/mcp/api/).
- [Changelog](https://github.com/NexusPHP/mcp/blob/1.x/CHANGELOG.md) and
  [versioning policy](https://github.com/NexusPHP/mcp/blob/1.x/VERSIONING.md), shared by every component.

## License

Released under the [MIT License](LICENSE).
