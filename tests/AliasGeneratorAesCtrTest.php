<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\Tier2Gated\AliasGenerator;
use PHPUnit\Framework\TestCase;

/**
 * A19C Identity Alias Generator — TODO 355 regression coverage.
 *
 * The aes-ctr AliasMethod used to derive its IV solely from
 * SHA-256(context), so two calls sharing a context (e.g. the default
 * fieldType.microtime context within the same millisecond) produced
 * identical tokens. The fix uses a fresh CSPRNG IV per call, prepended
 * to the returned token — ported from Node's alias-generator.ts fix.
 */
final class AliasGeneratorAesCtrTest extends TestCase
{
    public function testAesCtrDifferentTokensForIdenticalContext(): void
    {
        $key = random_bytes(32);
        $context = 'identity.email.1234567890'; // fixed — simulates same-millisecond collision

        $first = AliasGenerator::generateIdentityAlias('real-a@example.com', 'identity.email', method: 'aes-ctr', context: $context, masterKey: $key);
        $second = AliasGenerator::generateIdentityAlias('real-b@example.com', 'identity.email', method: 'aes-ctr', context: $context, masterKey: $key);

        self::assertNotSame($first['token'], $second['token']);
    }

    public function testAesCtrUniqueAcrossRepeatedCallsWithFixedContext(): void
    {
        $key = random_bytes(32);
        $tokens = [];

        for ($i = 0; $i < 50; $i++) {
            $generated = AliasGenerator::generateIdentityAlias('real@example.com', 'identity.email', method: 'aes-ctr', context: 'fixed-context', masterKey: $key);
            self::assertArrayNotHasKey($generated['token'], $tokens, "token collision on iteration {$i}");
            $tokens[$generated['token']] = true;
        }
    }

    public function testAesCtrTokenShape(): void
    {
        $key = random_bytes(32);
        $generated = AliasGenerator::generateIdentityAlias('real@example.com', 'identity.email', method: 'aes-ctr', context: 'fixed-context', masterKey: $key);

        self::assertSame('aes-ctr', $generated['method']);
        self::assertMatchesRegularExpression('/^[0-9a-f]+$/', $generated['token']);
        // iv (16 bytes) + ciphertext (16 bytes) == 32 bytes == 64 hex chars
        self::assertSame(64, strlen($generated['token']));
    }

    public function testAesCtrRemainsProPlusGated(): void
    {
        self::assertFalse(AliasGenerator::checkMethodTierAccess('aes-ctr', 'FREE'));
        self::assertTrue(AliasGenerator::checkMethodTierAccess('aes-ctr', 'PRO'));
        self::assertTrue(AliasGenerator::checkMethodTierAccess('aes-ctr', 'ENTERPRISE'));
    }
}
