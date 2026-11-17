<?php

// PATENT-GATE: A19C — Filing 3 extension — FILED, PENDING GRANT. Do not expose.

declare(strict_types=1);

namespace DevFortress\Sdk\Tier2Gated;

use DevFortress\Sdk\CredentialVault;
use DevFortress\Sdk\VaultEncryptedRecord;
use Throwable;

/**
 * Shared in-process alias cache + encrypted vault backing IdentityProjection
 * — mirrors the Node SDK's module-level aliasCache/VAULT_KEY/vault
 * (identity-projection.ts) and the Go/Ruby SDKs' own shared-vault ports. A
 * single process-wide key (rather than per-instance) is required because
 * the static resolveAlias()/revokeByAlias() entry points on
 * IdentityProjection have no instance to read a per-instance key from.
 *
 * @internal Gated surface — excluded from the distributed package.
 */
final class VaultShared
{
    private static ?string $key = null;
    /** @var array<string, VaultEncryptedRecord> */
    private static array $entries = [];

    private function __construct()
    {
    }

    public static function register(string $alias, string $realValue): void
    {
        self::$entries[$alias] = CredentialVault::encrypt($realValue, self::key());
    }

    public static function resolve(string $alias): ?string
    {
        $record = self::$entries[$alias] ?? null;
        if ($record === null) {
            return null;
        }
        try {
            return CredentialVault::decrypt($record, self::key());
        } catch (Throwable) {
            return null;
        }
    }

    public static function delete(string $alias): void
    {
        unset(self::$entries[$alias]);
    }

    private static function key(): string
    {
        return self::$key ??= random_bytes(32);
    }
}
