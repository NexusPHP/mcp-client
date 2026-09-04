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

use Nexus\Assert\Assert;
use Nexus\Mcp\Core\Exception\RuntimeException;
use Nexus\Mcp\Core\Validation\SuggestedDependencyGuard;

/**
 * Token store that persists its tokens to one file, encrypted with XChaCha20-Poly1305.
 */
final readonly class EncryptedFileTokenStore implements TokenStoreInterface
{
    /**
     * @param non-empty-string $path File the encrypted token map is kept in
     * @param non-empty-string $key  32-byte secret, e.g. from `random_bytes(32)`
     */
    public function __construct(
        private string $path,

        #[\SensitiveParameter]
        private string $key,
    ) {
        SuggestedDependencyGuard::verifyExtension(self::class, 'sodium');

        Assert::that($path)->isNonEmptyString('Encrypted token store path must be a non-empty string.');
        Assert::that($key)->hasLength(
            \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            'Encrypted token store key must be exactly 32 bytes long, {actual} given.',
        );
    }

    #[\Override]
    public function read(string $resource): ?AccessToken
    {
        $entry = $this->readMap()[$resource] ?? null;

        return null === $entry ? null : $this->parseToken($entry);
    }

    #[\Override]
    public function write(string $resource, AccessToken $token): void
    {
        $map = $this->readMap();
        $map[$resource] = [
            'value' => $token->value,
            'issuer' => $token->issuer,
            'expiresAt' => $token->expiresAt,
            'refreshToken' => $token->refreshToken,
            'scopes' => $token->scopes,
        ];

        $this->saveMap($map);
    }

    #[\Override]
    public function forget(string $resource): void
    {
        if (! is_file($this->path)) {
            return;
        }

        $map = $this->readMap();
        unset($map[$resource]);

        if ([] === $map) {
            if (! @unlink($this->path)) {
                throw $this->refuseWrite();
            }

            return;
        }

        $this->saveMap($map);
    }

    /**
     * @return array<array-key, mixed>
     */
    private function readMap(): array
    {
        if (! is_file($this->path)) {
            return [];
        }

        $raw = @file_get_contents($this->path);

        if (false === $raw) {
            throw new RuntimeException(\sprintf('Encrypted token store could not read "%s".', $this->path));
        }

        try {
            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                substr($raw, \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES),
                '',
                substr($raw, 0, \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES),
                $this->key,
            );
        } catch (\SodiumException) {
            throw $this->refuseUnreadable();
        }

        if (false === $plain) {
            throw $this->refuseUnreadable();
        }

        $map = json_decode($plain, associative: true);

        if (! \is_array($map)) {
            throw $this->refuseUnreadable();
        }

        return $map;
    }

    private function parseToken(mixed $entry): AccessToken
    {
        if (! \is_array($entry)) {
            throw $this->refuseUnreadable();
        }

        $value = $entry['value'] ?? null;
        $issuer = $entry['issuer'] ?? null;
        $expiresAt = $entry['expiresAt'] ?? null;
        $refreshToken = $entry['refreshToken'] ?? null;
        $scopes = $entry['scopes'] ?? [];

        if (
            ! \is_string($value)
            || ! \is_string($issuer)
            || (null !== $expiresAt && ! \is_int($expiresAt))
            || (null !== $refreshToken && ! \is_string($refreshToken))
            || ! \is_array($scopes)
        ) {
            throw $this->refuseUnreadable();
        }

        $scopeList = [];

        foreach ($scopes as $scope) {
            if (
                ! \is_string($scope)
                || '' === $scope
            ) {
                throw $this->refuseUnreadable();
            }

            $scopeList[] = $scope;
        }

        return new AccessToken($value, $issuer, $expiresAt, $refreshToken, $scopeList);
    }

    /**
     * @param array<array-key, mixed> $map
     */
    private function saveMap(array $map): void
    {
        try {
            $payload = json_encode($map, \JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw $this->refuseWrite($e);
        }

        $nonce = random_bytes(\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($payload, '', $nonce, $this->key);

        $temp = \sprintf('%s.%s.tmp', $this->path, bin2hex(random_bytes(8)));

        if (
            false === @file_put_contents($temp, '')
            || ! @chmod($temp, 0o600)
            || false === @file_put_contents($temp, $nonce.$cipher)
            || ! @rename($temp, $this->path)
        ) {
            @unlink($temp);

            throw $this->refuseWrite();
        }
    }

    private function refuseUnreadable(): RuntimeException
    {
        return new RuntimeException(\sprintf(
            'Encrypted token store file "%s" is not a token map written with the configured key.',
            $this->path,
        ));
    }

    private function refuseWrite(?\JsonException $cause = null): RuntimeException
    {
        return new RuntimeException(\sprintf('Encrypted token store could not write "%s".', $this->path), previous: $cause);
    }
}
