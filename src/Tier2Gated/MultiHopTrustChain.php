<?php

// PATENT-GATE: B4 — Filing 4 — Wave 4 only

declare(strict_types=1);

namespace DevFortress\Sdk\Tier2Gated;

/**
 * DevFortress SDK — B4: Multi-Hop Trust Chain.
 *
 * Validates trust propagation across multi-hop service chains. When a
 * request passes through multiple services, B4 ensures each hop maintains
 * a valid trust chain and detects cascade revocation scenarios. Mirrors
 * packages/devfortress-sdk/src/multi-hop-trust-chain.ts.
 *
 * @phpstan-type HopFingerprint array{requestIp?: string, geoCountry?: string, workloadId?: string, deviceFingerprint?: string, containerId?: string}
 * @phpstan-type TrustHop array{serviceId: string, aliasId: string, timestamp: int, signature: string, parentAliasId: ?string, trust: float, scope: list<string>, fingerprint?: HopFingerprint}
 * @phpstan-type TrustChain array{chainId: string, hops: list<TrustHop>, originServiceId: string, valid: bool, createdAt: int}
 */
final class MultiHopTrustChain
{
    /** @var array<string, TrustChain> */
    private array $chains = [];

    public function __construct(
        private readonly int $maxChainDepth = 10,
        private readonly int $cascadeTimeoutMs = 5000,
        private readonly bool $strictOrdering = true,
        private readonly float $trustDecayFactor = 0.85,
        private readonly float $minTrustForDelegation = 0.5,
    ) {
    }

    /**
     * Compares a hop's own captured fingerprint against the baseline it
     * inherited from its parent, surfacing drift across the chain.
     *
     * @param array{requestIp?: string, geoCountry?: string, workloadId?: string, deviceFingerprint?: string, containerId?: string} $baseline
     * @param array{requestIp?: string, geoCountry?: string, workloadId?: string, deviceFingerprint?: string, containerId?: string} $live
     * @return list<array{type: string, expected: string, received: string}>
     */
    public static function compareHopFingerprints(array $baseline, array $live): array
    {
        $divergences = [];

        if (!empty($baseline['workloadId']) && ($live['workloadId'] ?? null) !== $baseline['workloadId']) {
            $divergences[] = ['type' => 'workload_mismatch', 'expected' => $baseline['workloadId'], 'received' => $live['workloadId'] ?? 'none'];
        }
        if (!empty($baseline['geoCountry']) && ($live['geoCountry'] ?? null) !== $baseline['geoCountry']) {
            $divergences[] = ['type' => 'geo_drift', 'expected' => $baseline['geoCountry'], 'received' => $live['geoCountry'] ?? 'none'];
        }
        if (!empty($baseline['deviceFingerprint']) && ($live['deviceFingerprint'] ?? null) !== $baseline['deviceFingerprint']) {
            $divergences[] = ['type' => 'device_mismatch', 'expected' => $baseline['deviceFingerprint'], 'received' => $live['deviceFingerprint'] ?? 'none'];
        }
        if (!empty($baseline['containerId']) && ($live['containerId'] ?? null) !== $baseline['containerId']) {
            $divergences[] = ['type' => 'container_mismatch', 'expected' => $baseline['containerId'], 'received' => $live['containerId'] ?? 'none'];
        }

        return $divergences;
    }

    /**
     * Create a new trust chain starting from an origin service.
     *
     * @param array{serviceId: string, aliasId: string, timestamp: int, signature: string, parentAliasId: ?string, trust?: float, scope: list<string>, fingerprint?: array{requestIp?: string, geoCountry?: string, workloadId?: string, deviceFingerprint?: string, containerId?: string}} $initialHop Trust defaults to 1.0 if not specified.
     * @return TrustChain
     */
    public function createChain(string $originServiceId, array $initialHop): array
    {
        if (getenv('FEATURE_PLATFORM_INTEL') === 'false') {
            return ['chainId' => '', 'hops' => [], 'originServiceId' => $originServiceId, 'valid' => false, 'createdAt' => self::nowMs()];
        }

        $chainId = 'chain_' . self::nowMs() . '_' . substr(bin2hex(random_bytes(6)), 0, 8);
        $firstHop = [...$initialHop, 'trust' => $initialHop['trust'] ?? 1.0];
        $chain = [
            'chainId' => $chainId,
            'hops' => [$firstHop],
            'originServiceId' => $originServiceId,
            'valid' => true,
            'createdAt' => self::nowMs(),
        ];
        $this->chains[$chainId] = $chain;

        return $chain;
    }

    /**
     * Add a hop to an existing chain.
     *
     * @param array{serviceId: string, aliasId: string, timestamp: int, signature: string, parentAliasId: ?string, scope: list<string>, fingerprint?: array{requestIp?: string, geoCountry?: string, workloadId?: string, deviceFingerprint?: string, containerId?: string}} $hop Delegated hop — no 'trust' key: the system computes it.
     * @return array{valid: bool, chainDepth: int, brokenAtHop?: int, reason?: string, cascadeRevocationNeeded: bool, affectedAliases: list<string>, currentTrust?: float}
     */
    public function addHop(string $chainId, array $hop): array
    {
        if (getenv('FEATURE_PLATFORM_INTEL') === 'false') {
            return ['valid' => false, 'chainDepth' => 0, 'reason' => 'Feature not enabled', 'cascadeRevocationNeeded' => false, 'affectedAliases' => []];
        }

        $chain = $this->chains[$chainId] ?? null;
        if ($chain === null) {
            return ['valid' => false, 'chainDepth' => 0, 'reason' => 'Chain not found', 'cascadeRevocationNeeded' => false, 'affectedAliases' => []];
        }

        if (count($chain['hops']) >= $this->maxChainDepth) {
            return [
                'valid' => false, 'chainDepth' => count($chain['hops']),
                'reason' => "Max chain depth {$this->maxChainDepth} exceeded",
                'cascadeRevocationNeeded' => false, 'affectedAliases' => [],
            ];
        }

        $lastHop = $chain['hops'][count($chain['hops']) - 1];
        if ($this->strictOrdering && ($hop['parentAliasId'] ?? null) !== $lastHop['aliasId']) {
            return [
                'valid' => false, 'chainDepth' => count($chain['hops']), 'brokenAtHop' => count($chain['hops']),
                'reason' => 'Parent alias mismatch — chain integrity violated',
                'cascadeRevocationNeeded' => true,
                'affectedAliases' => array_map(static fn (array $h): string => $h['aliasId'], $chain['hops']),
            ];
        }

        // Per spec: trust attenuates per delegation (trust_(n+1) = trust_n *
        // gamma) — system-computed, not caller-supplied.
        $computedTrust = $lastHop['trust'] * $this->trustDecayFactor;
        if ($computedTrust < $this->minTrustForDelegation) {
            return [
                'valid' => false, 'chainDepth' => count($chain['hops']), 'brokenAtHop' => count($chain['hops']),
                'reason' => sprintf('Trust attenuated below minimum for delegation (%.3f < %s)', $computedTrust, $this->minTrustForDelegation),
                'cascadeRevocationNeeded' => false, 'affectedAliases' => [], 'currentTrust' => $computedTrust,
            ];
        }

        // Scope must not expand across a delegation — every scope entry at
        // this hop must already be present in the parent hop's scope.
        $outOfScope = array_values(array_diff($hop['scope'], $lastHop['scope']));
        if ($outOfScope !== []) {
            return [
                'valid' => false, 'chainDepth' => count($chain['hops']), 'brokenAtHop' => count($chain['hops']),
                'reason' => 'Requested scope is not a subset of the parent hop\'s scope: ' . implode(', ', $outOfScope),
                'cascadeRevocationNeeded' => false, 'affectedAliases' => [], 'currentTrust' => $lastHop['trust'],
            ];
        }

        // Cascading fingerprint inheritance: a delegated hop that doesn't
        // explicitly supply its own fingerprint inherits the parent hop's
        // verbatim.
        $fingerprint = $hop['fingerprint'] ?? ($lastHop['fingerprint'] ?? null);
        unset($hop['fingerprint']);
        $newHop = $fingerprint !== null
            ? [...$hop, 'trust' => $computedTrust, 'fingerprint' => $fingerprint]
            : [...$hop, 'trust' => $computedTrust];
        $chain['hops'][] = $newHop;
        $this->chains[$chainId] = $chain;

        return [
            'valid' => true, 'chainDepth' => count($chain['hops']), 'cascadeRevocationNeeded' => false,
            'currentTrust' => $computedTrust, 'affectedAliases' => [],
        ];
    }

    /**
     * Walks a chain comparing each hop's own fingerprint against the one
     * it inherited from its immediate parent. Read-only.
     *
     * @return list<array{hopIndex: int, divergences: list<array{type: string, expected: string, received: string}>}>
     */
    public function detectFingerprintDivergence(string $chainId): array
    {
        $chain = $this->chains[$chainId] ?? null;
        if ($chain === null) {
            return [];
        }

        $results = [];
        $hops = $chain['hops'];
        for ($i = 1; $i < count($hops); $i++) {
            $parentFingerprint = $hops[$i - 1]['fingerprint'] ?? null;
            $hopFingerprint = $hops[$i]['fingerprint'] ?? null;
            if ($parentFingerprint === null || $hopFingerprint === null) {
                continue;
            }
            $divergences = self::compareHopFingerprints($parentFingerprint, $hopFingerprint);
            if ($divergences !== []) {
                $results[] = ['hopIndex' => $i, 'divergences' => $divergences];
            }
        }

        return $results;
    }

    /**
     * Validate the entire trust chain.
     *
     * @return array{valid: bool, chainDepth: int, brokenAtHop?: int, reason?: string, cascadeRevocationNeeded: bool, affectedAliases: list<string>}
     */
    public function validate(string $chainId): array
    {
        if (getenv('FEATURE_PLATFORM_INTEL') === 'false') {
            return ['valid' => false, 'chainDepth' => 0, 'reason' => 'Feature not enabled', 'cascadeRevocationNeeded' => false, 'affectedAliases' => []];
        }

        $chain = $this->chains[$chainId] ?? null;
        if ($chain === null) {
            return ['valid' => false, 'chainDepth' => 0, 'reason' => 'Chain not found', 'cascadeRevocationNeeded' => false, 'affectedAliases' => []];
        }

        $hops = $chain['hops'];
        for ($i = 1; $i < count($hops); $i++) {
            $prev = $hops[$i - 1];
            $curr = $hops[$i];

            if ($this->strictOrdering && $curr['parentAliasId'] !== $prev['aliasId']) {
                $chain['valid'] = false;
                $this->chains[$chainId] = $chain;

                return [
                    'valid' => false, 'chainDepth' => count($hops), 'brokenAtHop' => $i,
                    'reason' => "Chain broken at hop {$i}: parent alias mismatch",
                    'cascadeRevocationNeeded' => true,
                    'affectedAliases' => array_map(static fn (array $h): string => $h['aliasId'], array_slice($hops, $i)),
                ];
            }

            if ($curr['timestamp'] < $prev['timestamp']) {
                $chain['valid'] = false;
                $this->chains[$chainId] = $chain;

                return [
                    'valid' => false, 'chainDepth' => count($hops), 'brokenAtHop' => $i,
                    'reason' => "Chain broken at hop {$i}: timestamp ordering violation",
                    'cascadeRevocationNeeded' => true,
                    'affectedAliases' => array_map(static fn (array $h): string => $h['aliasId'], array_slice($hops, $i)),
                ];
            }
        }

        return ['valid' => true, 'chainDepth' => count($hops), 'cascadeRevocationNeeded' => false, 'affectedAliases' => []];
    }

    /**
     * Cascade revoke all aliases from a given hop onwards.
     *
     * @return array{revokedCount: int, revokedAliases: list<string>, propagationTimeMs: int, success: bool}
     */
    public function cascadeRevoke(string $chainId, int $fromHop): array
    {
        $start = self::nowMs();
        if (getenv('FEATURE_PLATFORM_INTEL') === 'false') {
            return ['revokedCount' => 0, 'revokedAliases' => [], 'propagationTimeMs' => 0, 'success' => false];
        }

        $chain = $this->chains[$chainId] ?? null;
        if ($chain === null) {
            return ['revokedCount' => 0, 'revokedAliases' => [], 'propagationTimeMs' => 0, 'success' => false];
        }

        $affected = array_map(static fn (array $h): string => $h['aliasId'], array_slice($chain['hops'], $fromHop));
        $chain['valid'] = false;
        $this->chains[$chainId] = $chain;

        return ['revokedCount' => count($affected), 'revokedAliases' => $affected, 'propagationTimeMs' => self::nowMs() - $start, 'success' => true];
    }

    /** @return TrustChain|null */
    public function getChain(string $chainId): ?array
    {
        return $this->chains[$chainId] ?? null;
    }

    /**
     * Configured cascade-propagation timeout. Stored for API-shape parity
     * with Node's MultiHopConfig.cascadeTimeoutMs — Node itself never
     * enforces this as an actual timeout anywhere in
     * multi-hop-trust-chain.ts either (cascadeRevoke() only measures
     * elapsed time, it doesn't bound it); this getter exists so the field
     * has a real read site rather than being silently dead.
     */
    public function getCascadeTimeoutMs(): int
    {
        return $this->cascadeTimeoutMs;
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}
