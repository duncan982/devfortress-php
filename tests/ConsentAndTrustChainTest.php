<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\Tier2Gated\ConsentAliasLifecycle;
use DevFortress\Sdk\Tier2Gated\MultiHopTrustChain;
use PHPUnit\Framework\TestCase;

/**
 * ConsentAliasLifecycle (B3) and MultiHopTrustChain (B4), gated again as
 * of TODO 420 (2026-11-03) — see src/Tier2Gated/ConsentAliasLifecycle.php
 * and src/Tier2Gated/MultiHopTrustChain.php. This test file itself lives
 * under tests/, export-ignored the same as Tier2Gated/ and Internal.php,
 * so it never ships either.
 */
final class ConsentAndTrustChainTest extends TestCase
{
    // ── ConsentAliasLifecycle (B3) ────────────────────────────────

    public function testConsentAliasLifecycleWithdrawalRevokesImmediately(): void
    {
        $revokedIds = [];
        $lifecycle = new ConsentAliasLifecycle(aliasRevoker: function (string $aliasId) use (&$revokedIds): bool {
            $revokedIds[] = $aliasId;

            return true;
        });

        $lifecycle->grantConsent('subject-1', 'marketing', ['alias-a', 'alias-b']);
        self::assertTrue($lifecycle->checkConsent('subject-1')['allowed']);

        $result = $lifecycle->withdrawConsent('subject-1');
        self::assertFalse($result['allowed']);
        self::assertSame('withdrawn', $result['consentState']);
        self::assertSame(['alias-a', 'alias-b'], $result['revokedAliasIds'] ?? null);
        self::assertSame(['alias-a', 'alias-b'], $revokedIds);

        // No grace period — immediately denied again.
        self::assertFalse($lifecycle->checkConsent('subject-1')['allowed']);
    }

    public function testConsentAliasLifecycleUnknownSubjectRequiresExplicitConsent(): void
    {
        $lifecycle = new ConsentAliasLifecycle();
        $result = $lifecycle->checkConsent('never-granted');
        self::assertFalse($result['allowed']);
        self::assertSame('unknown', $result['consentState']);
    }

    // ── MultiHopTrustChain (B4) ───────────────────────────────────

    public function testMultiHopTrustChainDecaysTrustPerDelegation(): void
    {
        $chain = new MultiHopTrustChain(trustDecayFactor: 0.8, minTrustForDelegation: 0.1);
        $created = $chain->createChain('service-a', [
            'serviceId' => 'service-a', 'aliasId' => 'alias-0', 'timestamp' => 1000,
            'signature' => 'sig-0', 'parentAliasId' => null, 'scope' => ['read', 'write'],
        ]);

        $result = $chain->addHop($created['chainId'], [
            'serviceId' => 'service-b', 'aliasId' => 'alias-1', 'timestamp' => 1001,
            'signature' => 'sig-1', 'parentAliasId' => 'alias-0', 'scope' => ['read'],
        ]);

        self::assertTrue($result['valid']);
        self::assertEqualsWithDelta(0.8, $result['currentTrust'] ?? null, 0.0001);
    }

    public function testMultiHopTrustChainRejectsScopeExpansion(): void
    {
        $chain = new MultiHopTrustChain();
        $created = $chain->createChain('service-a', [
            'serviceId' => 'service-a', 'aliasId' => 'alias-0', 'timestamp' => 1000,
            'signature' => 'sig-0', 'parentAliasId' => null, 'scope' => ['read'],
        ]);

        $result = $chain->addHop($created['chainId'], [
            'serviceId' => 'service-b', 'aliasId' => 'alias-1', 'timestamp' => 1001,
            'signature' => 'sig-1', 'parentAliasId' => 'alias-0', 'scope' => ['read', 'write'],
        ]);

        self::assertFalse($result['valid']);
        self::assertStringContainsString('not a subset', $result['reason'] ?? '');
    }

    public function testMultiHopTrustChainCascadeRevokeOnParentMismatch(): void
    {
        $chain = new MultiHopTrustChain(strictOrdering: true);
        $created = $chain->createChain('service-a', [
            'serviceId' => 'service-a', 'aliasId' => 'alias-0', 'timestamp' => 1000,
            'signature' => 'sig-0', 'parentAliasId' => null, 'scope' => ['read'],
        ]);

        $result = $chain->addHop($created['chainId'], [
            'serviceId' => 'service-b', 'aliasId' => 'alias-1', 'timestamp' => 1001,
            'signature' => 'sig-1', 'parentAliasId' => 'wrong-parent', 'scope' => ['read'],
        ]);

        self::assertFalse($result['valid']);
        self::assertTrue($result['cascadeRevocationNeeded']);
    }

    public function testMultiHopTrustChainCascadeRevoke(): void
    {
        $chain = new MultiHopTrustChain();
        $created = $chain->createChain('service-a', [
            'serviceId' => 'service-a', 'aliasId' => 'alias-0', 'timestamp' => 1000,
            'signature' => 'sig-0', 'parentAliasId' => null, 'scope' => ['read'],
        ]);
        $chain->addHop($created['chainId'], [
            'serviceId' => 'service-b', 'aliasId' => 'alias-1', 'timestamp' => 1001,
            'signature' => 'sig-1', 'parentAliasId' => 'alias-0', 'scope' => ['read'],
        ]);

        $revocation = $chain->cascadeRevoke($created['chainId'], 1);
        self::assertTrue($revocation['success']);
        self::assertSame(['alias-1'], $revocation['revokedAliases']);
    }

    public function testMultiHopTrustChainFingerprintInheritanceAndDivergence(): void
    {
        $chain = new MultiHopTrustChain();
        $created = $chain->createChain('service-a', [
            'serviceId' => 'service-a', 'aliasId' => 'alias-0', 'timestamp' => 1000,
            'signature' => 'sig-0', 'parentAliasId' => null, 'scope' => ['read'],
            'fingerprint' => ['workloadId' => 'wl-1', 'geoCountry' => 'US'],
        ]);

        $chain->addHop($created['chainId'], [
            'serviceId' => 'service-b', 'aliasId' => 'alias-1', 'timestamp' => 1001,
            'signature' => 'sig-1', 'parentAliasId' => 'alias-0', 'scope' => ['read'],
            'fingerprint' => ['workloadId' => 'wl-1', 'geoCountry' => 'RU'],
        ]);

        $divergence = $chain->detectFingerprintDivergence($created['chainId']);
        self::assertCount(1, $divergence);
        self::assertSame('geo_drift', $divergence[0]['divergences'][0]['type']);
    }
}
