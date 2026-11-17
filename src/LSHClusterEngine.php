<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * DevFortress SDK — LSH Fingerprint Similarity & Campaign Detection
 * (GAP-A2-1, A2-2, A2-3, A2-4).
 *
 * Mirrors packages/devfortress-sdk/src/lsh-cluster-engine.ts. Implements
 * locality-sensitive hashing for O(n*log(n)) fingerprint clustering and
 * campaign signature detection:
 *
 *   GAP-A2-1: LSH for O(n*log(n)) fingerprint similarity — MinHash-based
 *             approximate nearest-neighbor for request fingerprints.
 *   GAP-A2-2: Campaign signature detection — identifies coordinated
 *             attacks sharing target endpoints, timing patterns, and
 *             payloads.
 *   GAP-A2-3: Cluster TTL/dissolution — clusters expire after a
 *             30-minute inactivity timeout, preventing stale groupings.
 *   GAP-A2-4: Cluster size explosion guard — allowlist mechanism plus
 *             confirmation prompt when a cluster exceeds 20 members.
 *
 * @phpstan-type RequestFingerprint array{
 *     sourceId: string,
 *     endpoint: string,
 *     method: string,
 *     headerSignature: list<string>,
 *     bodyHash?: string,
 *     userAgent?: string,
 *     timestamp?: float,
 * }
 * @phpstan-type CampaignSignature array{
 *     clusterId: string,
 *     targetEndpoints: list<string>,
 *     participantCount: int,
 *     startTime: float,
 *     lastSeen: float,
 *     confidence: float,
 *     mitigated: bool,
 * }
 * @phpstan-type LSHMatchResult array{
 *     sourceId: string,
 *     clusterId: ?string,
 *     similarity: float,
 *     newCluster: bool,
 *     explosionGuard: bool,
 *     campaign: ?CampaignSignature,
 * }
 * @phpstan-type ClusterInfo array{
 *     id: string,
 *     memberCount: int,
 *     topEndpoints: list<array{0: string, 1: int}>,
 *     createdAt: float,
 *     lastActivity: float,
 *     isCampaign: bool,
 *     explosionGuardTriggered: bool,
 * }
 * @phpstan-type Cluster array{
 *     id: string,
 *     members: array<string, true>,
 *     sharedEndpoints: array<string, int>,
 *     createdAt: float,
 *     lastActivity: float,
 *     isCampaign: bool,
 *     explosionGuardTriggered: bool,
 * }
 */
final class LSHClusterEngine
{
    private const SHINGLE_SPLIT_PATTERN = '/[|\/.\-_]/';

    /** @var BoundedMap<Cluster> */
    private BoundedMap $clusters;

    /** @var array<string, array<string, true>> band bucket key -> set of cluster IDs */
    private array $bandBuckets = [];

    /** @var BoundedMap<string> */
    private BoundedMap $fingerprintToCluster;

    /** @var BoundedMap<CampaignSignature> */
    private BoundedMap $campaigns;

    /** @var list<int> */
    private array $seeds;

    private int $nextClusterId = 0;

    /** @var array<string, true> */
    private array $allowlistedClusters;

    /**
     * @param list<string> $allowlistedClusters
     */
    public function __construct(
        private readonly int $hashesPerBand = 5,
        private readonly int $numBands = 10,
        private readonly float $similarityThreshold = 0.7,
        private readonly float $clusterTtlSeconds = 1_800.0,
        private readonly int $maxClusterSize = 20,
        private readonly int $hardCapClusterSize = 100,
        private readonly int $maxClusters = 10_000,
        private readonly int $maxFingerprints = 100_000,
        array $allowlistedClusters = [],
        private readonly int $minSharedEndpointsForCampaign = 3,
        private readonly int $minCampaignMembers = 3,
    ) {
        $this->clusters = new BoundedMap($this->maxClusters);
        $this->fingerprintToCluster = new BoundedMap($this->maxFingerprints);
        $this->campaigns = new BoundedMap($this->maxClusters);
        $this->allowlistedClusters = array_fill_keys($allowlistedClusters, true);

        $totalHashes = $this->hashesPerBand * $this->numBands;
        $this->seeds = [];
        for ($i = 0; $i < $totalHashes; $i++) {
            $this->seeds[] = ($i + 1) * 31_337;
        }
    }

    /**
     * Ingests a request fingerprint, finding or creating a cluster.
     *
     * @param RequestFingerprint $fp
     * @return LSHMatchResult
     */
    public function ingest(array $fp): array
    {
        $fp['bodyHash'] ??= '';
        $fp['userAgent'] ??= '';
        $fp['timestamp'] ??= microtime(true);

        $now = microtime(true);
        $this->expireStaleClusters($now);

        $sig = $this->computeSignature($fp);

        // ── Find candidate clusters via LSH bucket matching ──
        $candidateClusterIds = [];
        for ($b = 0; $b < $this->numBands; $b++) {
            $bucket = $this->bandBuckets[$this->bandBucketKey($b, $sig[$b])] ?? [];
            foreach (array_keys($bucket) as $cid) {
                $candidateClusterIds[$cid] = true;
            }
        }

        // ── Find best matching cluster ──
        $bestClusterId = null;
        $bestSimilarity = 0.0;

        foreach (array_keys($candidateClusterIds) as $cid) {
            /** @var Cluster|null $cluster */
            $cluster = $this->clusters->get($cid);
            if ($cluster === null) {
                continue;
            }
            $similarity = $this->estimateJaccard($sig, $cluster);
            if ($similarity > $bestSimilarity) {
                $bestSimilarity = $similarity;
                $bestClusterId = $cid;
            }
        }

        // Spec default tau=0.7 (Section 5.4.3) — requires ~70% band
        // overlap to join a cluster, not just a single matching band
        // bucket.
        $explosionGuard = false;

        if ($bestClusterId !== null && $bestSimilarity >= $this->similarityThreshold) {
            /** @var Cluster $cluster */
            $cluster = $this->clusters->get($bestClusterId);

            // ── Explosion guard (GAP-A2-4) ──
            if (count($cluster['members']) >= $this->maxClusterSize && !isset($this->allowlistedClusters[$bestClusterId])) {
                $cluster['explosionGuardTriggered'] = true;
                $explosionGuard = true;

                // Hard cap: reject if already at absolute limit.
                if (count($cluster['members']) >= $this->hardCapClusterSize) {
                    $this->clusters->set($bestClusterId, $cluster);

                    return [
                        'sourceId' => $fp['sourceId'],
                        'clusterId' => $bestClusterId,
                        'similarity' => $bestSimilarity,
                        'newCluster' => false,
                        'explosionGuard' => true,
                        'campaign' => $this->campaigns->get($bestClusterId),
                    ];
                }
            }

            // Add to existing cluster.
            $cluster['members'][$fp['sourceId']] = true;
            $cluster['lastActivity'] = $now;
            $cluster['sharedEndpoints'][$fp['endpoint']] = ($cluster['sharedEndpoints'][$fp['endpoint']] ?? 0) + 1;
            $this->fingerprintToCluster->set($fp['sourceId'], $bestClusterId);

            // Check campaign signature (GAP-A2-2).
            $this->checkCampaign($cluster);

            $this->clusters->set($bestClusterId, $cluster);

            return [
                'sourceId' => $fp['sourceId'],
                'clusterId' => $bestClusterId,
                'similarity' => $bestSimilarity,
                'newCluster' => false,
                'explosionGuard' => $explosionGuard,
                'campaign' => $this->campaigns->get($bestClusterId),
            ];
        }

        // ── Create new cluster ──
        $newClusterId = 'cluster_' . (++$this->nextClusterId);
        /** @var Cluster $newCluster */
        $newCluster = [
            'id' => $newClusterId,
            'members' => [$fp['sourceId'] => true],
            'sharedEndpoints' => [$fp['endpoint'] => 1],
            'createdAt' => $now,
            'lastActivity' => $now,
            'isCampaign' => false,
            'explosionGuardTriggered' => false,
        ];

        $this->clusters->set($newClusterId, $newCluster);
        $this->fingerprintToCluster->set($fp['sourceId'], $newClusterId);

        for ($b = 0; $b < $this->numBands; $b++) {
            $key = $this->bandBucketKey($b, $sig[$b]);
            $this->bandBuckets[$key] ??= [];
            $this->bandBuckets[$key][$newClusterId] = true;
        }

        return [
            'sourceId' => $fp['sourceId'],
            'clusterId' => $newClusterId,
            'similarity' => 0.0,
            'newCluster' => true,
            'explosionGuard' => false,
            'campaign' => null,
        ];
    }

    /**
     * Returns all active campaigns.
     *
     * @return list<CampaignSignature>
     */
    public function getActiveCampaigns(): array
    {
        $campaigns = [];
        $this->campaigns->forEach(static function (array $c) use (&$campaigns): void {
            $campaigns[] = $c;
        });

        return $campaigns;
    }

    /**
     * Returns cluster info by ID, or null if not found.
     *
     * @return ClusterInfo|null
     */
    public function getCluster(string $clusterId): ?array
    {
        /** @var Cluster|null $c */
        $c = $this->clusters->get($clusterId);
        if ($c === null) {
            return null;
        }

        $endpoints = [];
        foreach ($c['sharedEndpoints'] as $endpoint => $count) {
            $endpoints[] = [$endpoint, $count];
        }
        usort($endpoints, static fn (array $a, array $b): int => $b[1] <=> $a[1]);
        $endpoints = array_slice($endpoints, 0, 10);

        return [
            'id' => $c['id'],
            'memberCount' => count($c['members']),
            'topEndpoints' => $endpoints,
            'createdAt' => $c['createdAt'],
            'lastActivity' => $c['lastActivity'],
            'isCampaign' => $c['isCampaign'],
            'explosionGuardTriggered' => $c['explosionGuardTriggered'],
        ];
    }

    /** Allowlists a cluster, bypassing the explosion guard. */
    public function allowlistCluster(string $clusterId): void
    {
        $this->allowlistedClusters[$clusterId] = true;
    }

    /**
     * Returns a metrics snapshot.
     *
     * @return array{
     *     totalClusters: int,
     *     totalFingerprints: int,
     *     activeCampaigns: int,
     *     clustersWithExplosionGuard: int,
     *     allowlistedClusters: int,
     * }
     */
    public function getMetrics(): array
    {
        $explosionCount = 0;
        $this->clusters->forEach(static function (array $c) use (&$explosionCount): void {
            if ($c['explosionGuardTriggered']) {
                $explosionCount++;
            }
        });

        return [
            'totalClusters' => $this->clusters->size(),
            'totalFingerprints' => $this->fingerprintToCluster->size(),
            'activeCampaigns' => $this->campaigns->size(),
            'clustersWithExplosionGuard' => $explosionCount,
            'allowlistedClusters' => count($this->allowlistedClusters),
        ];
    }

    /**
     * Computes a MinHash band signature for a fingerprint.
     *
     * @param RequestFingerprint $fp
     * @return list<int>
     */
    private function computeSignature(array $fp): array
    {
        $shingles = $this->generateShingles($fp);
        if ($shingles === []) {
            return array_fill(0, $this->numBands, 0);
        }

        $bands = [];
        for ($b = 0; $b < $this->numBands; $b++) {
            $bandHash = 0;
            for ($h = 0; $h < $this->hashesPerBand; $h++) {
                $seedIdx = $b * $this->hashesPerBand + $h;
                $seed = $this->seeds[$seedIdx];
                $minHash = \PHP_INT_MAX;
                foreach ($shingles as $shingle) {
                    $hash = self::simpleHash($shingle, $seed);
                    if ($hash < $minHash) {
                        $minHash = $hash;
                    }
                }
                $bandHash ^= self::toUint32($minHash * ($h + 1));
            }
            $bands[] = $bandHash;
        }

        return $bands;
    }

    /**
     * @param RequestFingerprint $fp
     * @return list<string>
     */
    private function generateShingles(array $fp, int $k = 2): array
    {
        $parts = [
            $fp['method'],
            $fp['endpoint'],
            $fp['userAgent'] ?? '',
            $fp['bodyHash'] ?? '',
            ...$fp['headerSignature'],
        ];
        $tokens = preg_split(self::SHINGLE_SPLIT_PATTERN, implode('|', $parts));
        \assert($tokens !== false);

        $shingles = [];
        $count = count($tokens);
        for ($i = 0; $i <= $count - $k; $i++) {
            $shingles[] = implode('_', \array_slice($tokens, $i, $k));
        }

        return $shingles;
    }

    private function bandBucketKey(int $band, int $hash): string
    {
        return "b{$band}:{$hash}";
    }

    /**
     * Estimates Jaccard similarity between a signature and a cluster.
     * Uses band-based estimation for O(1) per comparison.
     *
     * @param list<int> $sig
     * @param Cluster $cluster
     */
    private function estimateJaccard(array $sig, array $cluster): float
    {
        $matches = 0;
        for ($b = 0; $b < $this->numBands; $b++) {
            $bucket = $this->bandBuckets[$this->bandBucketKey($b, $sig[$b])] ?? [];
            if (isset($bucket[$cluster['id']])) {
                $matches++;
            }
        }

        return $matches / $this->numBands;
    }

    /**
     * Campaign signature detection (GAP-A2-2): identifies coordinated
     * attacks sharing target endpoints.
     *
     * @param Cluster $cluster
     */
    private function checkCampaign(array &$cluster): void
    {
        if (count($cluster['members']) < $this->minCampaignMembers) {
            return;
        }

        $significantEndpoints = [];
        foreach ($cluster['sharedEndpoints'] as $endpoint => $count) {
            if ($count >= $this->minCampaignMembers) {
                $significantEndpoints[] = $endpoint;
            }
        }

        if (count($significantEndpoints) >= $this->minSharedEndpointsForCampaign) {
            $cluster['isCampaign'] = true;
            $confidence = min(
                1.0,
                (count($significantEndpoints) / 10) * (count($cluster['members']) / $this->maxClusterSize),
            );

            $this->campaigns->set($cluster['id'], [
                'clusterId' => $cluster['id'],
                'targetEndpoints' => $significantEndpoints,
                'participantCount' => count($cluster['members']),
                'startTime' => $cluster['createdAt'],
                'lastSeen' => $cluster['lastActivity'],
                'confidence' => round($confidence * 1000) / 1000,
                'mitigated' => false,
            ]);
        }
    }

    /**
     * Expires clusters that haven't seen activity within the TTL
     * (GAP-A2-3).
     */
    private function expireStaleClusters(float $now): void
    {
        $expired = [];
        $this->clusters->forEach(function (array $cluster, string $id) use ($now, &$expired): void {
            if ($now - $cluster['lastActivity'] > $this->clusterTtlSeconds) {
                $expired[] = $id;
            }
        });

        foreach ($expired as $id) {
            /** @var Cluster|null $cluster */
            $cluster = $this->clusters->get($id);
            if ($cluster !== null) {
                foreach (array_keys($cluster['members']) as $member) {
                    if ($this->fingerprintToCluster->get($member) === $id) {
                        $this->fingerprintToCluster->delete($member);
                    }
                }
            }
            $this->clusters->delete($id);
            $this->campaigns->delete($id);

            foreach (array_keys($this->bandBuckets) as $key) {
                unset($this->bandBuckets[$key][$id]);
            }
        }
    }

    /**
     * 32-bit Knuth multiplicative hash, with the same wraparound
     * semantics as JavaScript's `|0` truncation.
     */
    private static function simpleHash(string $str, int $seed): int
    {
        $hash = $seed;
        $len = \strlen($str);
        for ($i = 0; $i < $len; $i++) {
            $hash = self::toInt32(($hash << 5) - $hash + \ord($str[$i]));
            $hash = self::toInt32($hash * 2_654_435_761);
        }

        return self::toUint32($hash);
    }

    private static function toInt32(int $n): int
    {
        $n &= 0xFFFFFFFF;

        return $n >= 0x80000000 ? $n - 0x100000000 : $n;
    }

    private static function toUint32(int $n): int
    {
        return $n & 0xFFFFFFFF;
    }
}
