<?php

// PATENT-GATE: A19C — Filing 3 extension — FILED, PENDING GRANT. Do not expose.

declare(strict_types=1);

namespace DevFortress\Sdk\Tier2Gated;

use DevFortress\Sdk\CredentialVault;
use DevFortress\Sdk\VaultEncryptedRecord;
use Throwable;

/**
 * DevFortress SDK — A19C: Per-Agent Consent Matrix.
 *
 * Stores, reads, and enforces per-agent, per-category consent decisions.
 * Each entry is AES-256-GCM encrypted before it is placed in the
 * in-process bounded cache — the key lives in the same process as the
 * ciphertext, so this is defense-in-depth against memory dumps or
 * accidental serialization, not a separate trust boundary. Default
 * decision: deny. Mirrors
 * packages/devfortress-sdk/src/agent-identity/consent-matrix.ts.
 *
 * @internal Gated surface — excluded from the distributed package.
 */
final class ConsentMatrix
{
    private const MAX_ENTRIES = 10_000;
    private const ALL_CATEGORIES = [
        'identity.name', 'identity.email', 'identity.phone', 'identity.location',
        'identity.payment', 'identity.calendar', 'identity.contacts',
    ];

    private readonly string $key;
    /** @var array<string, VaultEncryptedRecord> */
    private array $store = [];

    public function __construct(?string $secret = null)
    {
        $this->key = $secret !== null ? CredentialVault::deriveVaultKey($secret, 'consent-matrix') : random_bytes(32);
    }

    /** Never throws — a decrypt/auth-tag failure fails closed as 'deny'. */
    public function check(string $agentId, string $category): string
    {
        $key = self::makeKey($agentId, $category);
        $record = $this->store[$key] ?? null;
        if ($record === null) {
            return 'deny';
        }

        $entry = $this->tryDecrypt($record);
        if ($entry === null) {
            unset($this->store[$key]);

            return 'deny';
        }
        if ($entry['expiresAt'] !== null && (microtime(true) * 1000) > $entry['expiresAt'] * 1000) {
            unset($this->store[$key]);

            return 'deny';
        }

        return $entry['decision'];
    }

    public function grant(string $agentId, string $category, string $decision, ?int $ttlSeconds = null): void
    {
        $key = self::makeKey($agentId, $category);
        $entry = [
            'agentId' => $agentId,
            'category' => $category,
            'decision' => $decision,
            'grantedAt' => (int) floor(microtime(true)),
            'expiresAt' => $ttlSeconds !== null ? (int) floor(microtime(true)) + $ttlSeconds : null,
        ];

        if (array_key_exists($key, $this->store)) {
            unset($this->store[$key]);
        } elseif (count($this->store) >= self::MAX_ENTRIES) {
            unset($this->store[array_key_first($this->store)]);
        }
        $this->store[$key] = CredentialVault::encrypt(json_encode($entry, JSON_THROW_ON_ERROR), $this->key);
    }

    public function revoke(string $agentId, ?string $category = null): void
    {
        if ($category !== null) {
            unset($this->store[self::makeKey($agentId, $category)]);

            return;
        }
        foreach (self::ALL_CATEGORIES as $cat) {
            unset($this->store[self::makeKey($agentId, $cat)]);
        }
    }

    /**
     * Skips any entry that fails to decrypt rather than throwing.
     *
     * @return list<array{agentId: string, category: string, decision: string, grantedAt: int, expiresAt: ?int}>
     */
    public function export(): array
    {
        $entries = [];
        foreach ($this->store as $record) {
            $entry = $this->tryDecrypt($record);
            if ($entry === null) {
                continue;
            }
            if ($entry['expiresAt'] === null || (microtime(true) * 1000) <= $entry['expiresAt'] * 1000) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    private static function makeKey(string $agentId, string $category): string
    {
        return "{$agentId}::{$category}";
    }

    /** @return array{agentId: string, category: string, decision: string, grantedAt: int, expiresAt: ?int}|null */
    private function tryDecrypt(VaultEncryptedRecord $record): ?array
    {
        try {
            /** @var array{agentId: string, category: string, decision: string, grantedAt: int, expiresAt: int|null} $entry */
            $entry = json_decode(CredentialVault::decrypt($record, $this->key), true, flags: JSON_THROW_ON_ERROR);

            return $entry;
        } catch (Throwable) {
            return null;
        }
    }
}
