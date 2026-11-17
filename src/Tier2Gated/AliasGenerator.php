<?php

// PATENT-GATE: A19C — Filing 3 extension — FILED, PENDING GRANT. Do not expose.

declare(strict_types=1);

namespace DevFortress\Sdk\Tier2Gated;

/**
 * DevFortress SDK — A19C: Identity Alias Generator.
 *
 * Generates alias values for user identity fields using the same
 * multi-method architecture as A19 credential aliases (Filing 3). Mirrors
 * packages/devfortress-sdk/src/agent-identity/alias-generator.ts.
 *
 * @internal Gated surface — excluded from the distributed package. See
 *           src/Internal.php and .gitattributes.
 */
final class AliasGenerator
{
    private const PRO_PLUS_METHODS = ['hkdf-sha256', 'shake256', 'blake3', 'argon2id', 'chacha20', 'aes-ctr'];
    private const ENTERPRISE_METHODS = ['dual-entropy', 'time-locked', 'fpe-ff3'];

    private function __construct()
    {
    }

    public static function checkMethodTierAccess(string $method, string $tier): bool
    {
        if ($method === 'csprng') {
            return true;
        }
        $tierUpper = strtoupper($tier);
        if (in_array($method, self::PRO_PLUS_METHODS, true)) {
            return in_array($tierUpper, ['PRO', 'TEAM', 'TEAMS', 'ENTERPRISE', 'ENTERPRISE_PLUS'], true);
        }
        if (in_array($method, self::ENTERPRISE_METHODS, true)) {
            return in_array($tierUpper, ['TEAM', 'TEAMS', 'ENTERPRISE', 'ENTERPRISE_PLUS'], true);
        }

        return false;
    }

    /**
     * @return array{token: string, expiresAt: int, method: string}
     */
    public static function generateIdentityAlias(
        string $field,
        string $fieldType,
        string $method = 'csprng',
        int $ttlSeconds = 3600,
        ?string $context = null,
        ?string $masterKey = null,
    ): array {
        if ($method === 'time-locked') {
            $tl = self::timeLockedAlias($ttlSeconds);

            return ['token' => $tl['token'], 'expiresAt' => $tl['expiresAt'], 'method' => $method];
        }

        $expiresAt = (int) floor(microtime(true)) + $ttlSeconds;
        $context ??= $fieldType . '.' . (int) round(microtime(true) * 1000);
        $masterKey ??= random_bytes(32);

        $token = match ($method) {
            'hkdf-sha256' => self::hkdfAlias($fieldType, $context, $masterKey),
            'shake256' => self::shake256Alias($context, $masterKey),
            'blake3' => self::blake3Alias($context, $masterKey),
            'argon2id' => self::hkdfAlias($fieldType, "argon2id:{$context}", $masterKey),
            'chacha20' => self::chacha20Alias($context, $masterKey),
            'aes-ctr' => self::aesCtrAlias($context, $masterKey),
            'dual-entropy' => self::dualEntropyAlias(),
            'fpe-ff3' => self::fpeFf3Alias($fieldType),
            default => bin2hex(random_bytes(6)),
        };

        return ['token' => $token, 'expiresAt' => $expiresAt, 'method' => $method];
    }

    public static function formatAliasForField(string $token, string $fieldType): string
    {
        return match ($fieldType) {
            'identity.email' => str_contains($token, '@') ? $token : "alias-{$token}@devfortress.alias",
            'identity.phone' => str_starts_with($token, '+') ? $token : "+000-{$token}",
            'identity.name' => (str_starts_with($token, 'User-') || str_starts_with($token, 'tl.')) ? $token : "User-{$token}",
            'identity.location' => $token,
            default => "alias-{$token}",
        };
    }

    private static function hkdfAlias(string $fieldType, string $context, string $masterKey): string
    {
        $info = "devfortress.a19c.{$fieldType}.{$context}";

        return bin2hex(hash_hkdf('sha256', $masterKey, 16, $info, str_repeat("\0", 32)));
    }

    /**
     * SHAKE256 is not registered in every PHP build's hash extension (not
     * present on this system's libcrypto — confirmed via hash_algos()).
     * Falls back to an HKDF-derived value when unavailable, documented the
     * same way the Go and Ruby SDKs document their own SHAKE256 fallback
     * for the same reason — this is a placeholder parity gap already
     * present in Node's own implementation (shake256/blake3/argon2id/
     * chacha20 are none of them real primitives there either), not
     * something introduced by this port.
     */
    private static function shake256Alias(string $context, string $masterKey): string
    {
        if (in_array('shake256', hash_algos(), true)) {
            return substr(hash('shake256', $masterKey . $context), 0, 32);
        }

        return self::hkdfAlias('shake256-fallback', $context, $masterKey);
    }

    private static function blake3Alias(string $context, string $masterKey): string
    {
        // BLAKE3 is not available in PHP's stock hash extension; use
        // HMAC-SHA256 with a BLAKE3-style context prefix, same placeholder
        // Node (and Go/Ruby) use.
        return substr(hash_hmac('sha256', "blake3:{$context}", $masterKey), 0, 32);
    }

    private static function chacha20Alias(string $context, string $masterKey): string
    {
        $info = "chacha20:{$context}";

        return bin2hex(hash_hkdf('sha256', $masterKey, 16, $info, str_repeat("\0", 32)));
    }

    private static function aesCtrAlias(string $context, string $masterKey): string
    {
        // IV must be independent, fresh randomness per call (CSPRNG), not
        // derived from `context` alone — two calls sharing a context (e.g.
        // same field type within the same millisecond, the default) would
        // otherwise reuse the IV and produce an identical token. The IV is
        // prepended to the returned token (same shape as an AEAD
        // nonce-then-ciphertext encoding) so it travels with the alias;
        // masterKey — not context — remains the stable binding for
        // platform-namespace isolation (Filing 3 Claim 11). Matches Node's
        // alias-generator.ts fix (TODO 355).
        $iv = random_bytes(16);
        $key = substr($masterKey, 0, 32);
        $encrypted = openssl_encrypt(str_repeat("\0", 16), 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            // Keystream derivation is a placeholder primitive (same status
            // as blake3/argon2id here); fall back to a random value rather
            // than silently returning a predictable one. Same length (32
            // bytes = 64 hex chars) as the success path.
            return bin2hex(random_bytes(32));
        }

        return bin2hex($iv . $encrypted);
    }

    private static function dualEntropyAlias(): string
    {
        $combined = random_bytes(8) . random_bytes(8);

        return substr(hash('sha256', $combined), 0, 24);
    }

    /** @return array{token: string, expiresAt: int} */
    private static function timeLockedAlias(int $ttlSeconds): array
    {
        $rand = bin2hex(random_bytes(8));
        $expiresAt = (int) floor(microtime(true)) + $ttlSeconds;

        return ['token' => "tl.{$rand}.{$expiresAt}", 'expiresAt' => $expiresAt];
    }

    private static function fpeFf3Alias(string $fieldType): string
    {
        $rand = bin2hex(random_bytes(4));

        return match ($fieldType) {
            'identity.email' => "alias-{$rand}@devfortress.alias",
            'identity.phone' => "+000-{$rand}",
            'identity.name' => "User-{$rand}",
            default => "alias-{$rand}",
        };
    }
}
