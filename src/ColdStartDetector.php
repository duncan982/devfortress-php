<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * DevFortress SDK — Cold-Start Suspicious Baseline Detector (GAP-A1-1,
 * A1-2, A1-3, A1-5).
 *
 * Mirrors packages/devfortress-sdk/src/cold-start-detector.ts. Addresses
 * the cold-start problem for agent behavioral baselines:
 *
 *   GAP-A1-1: Population comparator — uses global population stats to
 *             detect suspicious behavior even when no individual
 *             baseline exists yet.
 *   GAP-A1-2: Baseline quality metric — coefficient of variation (CV)
 *             threshold to determine when a baseline has stabilized and
 *             is trustworthy.
 *   GAP-A1-3: Response body size as 9th feature dimension — extends the
 *             8-feature behavioral vector with avgResponseBodyBytes for
 *             better anomaly detection.
 *   GAP-A1-5: Adaptive EWMA decay — alpha=0.3 during learning phase
 *             (high responsiveness), alpha=0.05 once baseline is stable
 *             (low drift tolerance).
 *
 * @phpstan-type BehavioralFeatureVector array{
 *     avgCallsPerSession: float,
 *     endpointEntropy: float,
 *     avgRequestBytes: float,
 *     avgLatencyMs: float,
 *     avgSessionDurationMs: float,
 *     uniqueEndpoints: float,
 *     errorRate: float,
 *     timeOfDayBias: float,
 *     avgResponseBodyBytes: float,
 * }
 * @phpstan-type BaselinePhase 'cold_start'|'learning'|'stable'
 * @phpstan-type BaselineQuality array{
 *     cvPerFeature: array<int, float>,
 *     maxCV: float,
 *     isStable: bool,
 *     sessionCount: int,
 *     currentAlpha: float,
 *     phase: BaselinePhase,
 * }
 * @phpstan-type ColdStartMethod 'population_comparator'|'individual_baseline'|'hybrid'
 * @phpstan-type ColdStartDetectionResult array{
 *     entityId: string,
 *     suspicious: bool,
 *     method: ColdStartMethod,
 *     zScore: float,
 *     anomalousFeatures: list<string>,
 *     quality: BaselineQuality,
 *     confidence: float,
 *     detectedAt: float,
 * }
 * @phpstan-type BaselineEntry array{
 *     ewmaMean: array<int, float>,
 *     ewmaVariance: array<int, float>,
 *     sessionCount: int,
 *     stable: bool,
 *     firstSeen: float,
 *     lastUpdated: float,
 * }
 */
final class ColdStartDetector
{
    /** @var list<string> */
    private const FEATURE_NAMES = [
        'avgCallsPerSession',
        'endpointEntropy',
        'avgRequestBytes',
        'avgLatencyMs',
        'avgSessionDurationMs',
        'uniqueEndpoints',
        'errorRate',
        'timeOfDayBias',
        'avgResponseBodyBytes',
    ];

    /** @var BoundedMap<BaselineEntry> */
    private BoundedMap $baselines;

    /** @var array<int, float> */
    private array $populationMean;

    /** @var array<int, float> */
    private array $populationVariance;

    private int $populationTotalSessions = 0;

    public function __construct(
        private readonly int $minSessionsForBaseline = 10,
        private readonly float $cvStabilityThreshold = 0.35,
        private readonly float $learningAlpha = 0.3,
        private readonly float $stableAlpha = 0.05,
        private readonly float $populationZScoreThreshold = 2.5,
        private readonly int $maxEntities = 50_000,
        private readonly int $featureDimensions = 9,
    ) {
        $this->baselines = new BoundedMap($this->maxEntities);

        $mean = [];
        $variance = [];
        for ($i = 0; $i < $this->featureDimensions; $i++) {
            $mean[] = 0.0;
            $variance[] = 1.0; // avoid /0
        }
        $this->populationMean = $mean;
        $this->populationVariance = $variance;
    }

    /**
     * Records a session observation and updates baselines. Updates both
     * the individual entity baseline (EWMA) and population stats.
     *
     * @param BehavioralFeatureVector $features
     */
    public function recordObservation(string $entityId, array $features): void
    {
        $vals = $this->vectorToArray($features);
        $dims = $this->featureDimensions;

        // ── Update population stats (Welford's online algorithm) ──
        $this->populationTotalSessions++;
        $n = (float) $this->populationTotalSessions;
        for ($i = 0; $i < $dims; $i++) {
            $delta = $vals[$i] - $this->populationMean[$i];
            $this->populationMean[$i] += $delta / $n;
            $delta2 = $vals[$i] - $this->populationMean[$i];
            $this->populationVariance[$i] =
                (($n - 1) * $this->populationVariance[$i] + $delta * $delta2) / max($n, 1.0);
        }

        // ── Update individual baseline (EWMA — GAP-A1-5) ──
        /** @var BaselineEntry|null $entry */
        $entry = $this->baselines->get($entityId);
        if ($entry === null) {
            $ewmaVariance = [];
            for ($i = 0; $i < $dims; $i++) {
                $ewmaVariance[] = 0.0;
            }
            $entry = [
                'ewmaMean' => $vals,
                'ewmaVariance' => $ewmaVariance,
                'sessionCount' => 0,
                'stable' => false,
                'firstSeen' => microtime(true),
                'lastUpdated' => microtime(true),
            ];
        }

        $entry['sessionCount']++;
        $entry['lastUpdated'] = microtime(true);

        $alpha = $entry['stable'] ? $this->stableAlpha : $this->learningAlpha;

        for ($i = 0; $i < $dims; $i++) {
            $oldMean = $entry['ewmaMean'][$i];
            $entry['ewmaMean'][$i] = $alpha * $vals[$i] + (1 - $alpha) * $oldMean;
            $diff = $vals[$i] - $entry['ewmaMean'][$i];
            $entry['ewmaVariance'][$i] = $alpha * $diff * $diff + (1 - $alpha) * $entry['ewmaVariance'][$i];
        }

        // Check stability (GAP-A1-2).
        if ($entry['sessionCount'] >= $this->minSessionsForBaseline && !$entry['stable']) {
            if ($this->computeMaxCV($entry) < $this->cvStabilityThreshold) {
                $entry['stable'] = true;
            }
        }

        $this->baselines->set($entityId, $entry);
    }

    /**
     * Assesses whether an entity's behavior is suspicious. Uses the
     * population comparator for cold-start, individual baseline
     * otherwise.
     *
     * @param BehavioralFeatureVector $features
     * @return ColdStartDetectionResult
     */
    public function assess(string $entityId, array $features): array
    {
        $vals = $this->vectorToArray($features);
        $dims = $this->featureDimensions;
        /** @var BaselineEntry|null $entry */
        $entry = $this->baselines->get($entityId);
        $quality = $this->getQuality($entityId);

        if ($entry === null || $entry['sessionCount'] < $this->minSessionsForBaseline) {
            // ── Cold-start: use population comparator (GAP-A1-1) ──
            $method = $entry !== null ? 'hybrid' : 'population_comparator';
            $zScores = [];
            for ($i = 0; $i < $dims; $i++) {
                $std = sqrt(max($this->populationVariance[$i], 1e-10));
                $zScores[] = abs(($vals[$i] - $this->populationMean[$i]) / $std);
            }
            $threshold = $this->populationZScoreThreshold;
        } else {
            // ── Individual baseline comparison ──
            $method = 'individual_baseline';
            $zScores = [];
            for ($i = 0; $i < $dims; $i++) {
                $std = sqrt(max($entry['ewmaVariance'][$i], 1e-10));
                $zScores[] = abs(($vals[$i] - $entry['ewmaMean'][$i]) / $std);
            }
            // Tighter threshold for stable baselines.
            $threshold = $entry['stable']
                ? $this->populationZScoreThreshold * 0.8
                : $this->populationZScoreThreshold;
        }

        $maxZ = $zScores === [] ? 0.0 : max($zScores);
        $anomalousFeatures = [];
        foreach ($zScores as $i => $z) {
            if ($z > $threshold) {
                $anomalousFeatures[] = self::FEATURE_NAMES[$i];
            }
        }

        // Confidence scales with data quality.
        $confidence = match ($quality['phase']) {
            'cold_start' => min(0.4, $this->populationTotalSessions / 100),
            'learning' => 0.4 + 0.4 * ($quality['sessionCount'] / $this->minSessionsForBaseline),
            default => 0.8 + 0.2 * min(1.0, $quality['sessionCount'] / 100),
        };

        return [
            'entityId' => $entityId,
            'suspicious' => $anomalousFeatures !== [],
            'method' => $method,
            'zScore' => $maxZ,
            'anomalousFeatures' => $anomalousFeatures,
            'quality' => $quality,
            'confidence' => round($confidence * 1000) / 1000,
            'detectedAt' => microtime(true),
        ];
    }

    /**
     * Returns baseline quality metrics for an entity (GAP-A1-2).
     *
     * @return BaselineQuality
     */
    public function getQuality(string $entityId): array
    {
        /** @var BaselineEntry|null $entry */
        $entry = $this->baselines->get($entityId);
        if ($entry === null) {
            return [
                'cvPerFeature' => [],
                'maxCV' => \INF,
                'isStable' => false,
                'sessionCount' => 0,
                'currentAlpha' => $this->learningAlpha,
                'phase' => 'cold_start',
            ];
        }

        $cvPerFeature = [];
        $maxCV = 0.0;
        $anyFinite = false;
        foreach ($entry['ewmaMean'] as $i => $mean) {
            $std = sqrt(max($entry['ewmaVariance'][$i], 1e-10));
            if (abs($mean) > 1e-10) {
                $cv = $std / abs($mean);
                $cvPerFeature[] = $cv;
                $maxCV = max($maxCV, $cv);
                $anyFinite = true;
            } else {
                $cvPerFeature[] = \INF;
            }
        }
        if (!$anyFinite) {
            $maxCV = \INF;
        }

        return [
            'cvPerFeature' => $cvPerFeature,
            'maxCV' => $maxCV,
            'isStable' => $entry['stable'],
            'sessionCount' => $entry['sessionCount'],
            'currentAlpha' => $entry['stable'] ? $this->stableAlpha : $this->learningAlpha,
            'phase' => $entry['stable'] ? 'stable' : ($entry['sessionCount'] > 0 ? 'learning' : 'cold_start'),
        ];
    }

    /**
     * Returns a snapshot of population statistics.
     *
     * @return array{totalSessions: int, mean: array<int, float>, stdDev: array<int, float>}
     */
    public function getPopulationStats(): array
    {
        return [
            'totalSessions' => $this->populationTotalSessions,
            'mean' => $this->populationMean,
            'stdDev' => array_map(static fn (float $v): float => sqrt(max($v, 0.0)), $this->populationVariance),
        ];
    }

    /**
     * Returns a metrics snapshot.
     *
     * @return array{trackedEntities: int, stableEntities: int, populationSessions: int, configuredDimensions: int}
     */
    public function getMetrics(): array
    {
        $stableCount = 0;
        $this->baselines->forEach(static function (array $entry) use (&$stableCount): void {
            /** @var BaselineEntry $entry */
            if ($entry['stable']) {
                $stableCount++;
            }
        });

        return [
            'trackedEntities' => $this->baselines->size(),
            'stableEntities' => $stableCount,
            'populationSessions' => $this->populationTotalSessions,
            'configuredDimensions' => $this->featureDimensions,
        ];
    }

    /**
     * @param BehavioralFeatureVector $v
     * @return list<float>
     */
    private function vectorToArray(array $v): array
    {
        return [
            $v['avgCallsPerSession'],
            $v['endpointEntropy'],
            $v['avgRequestBytes'],
            $v['avgLatencyMs'],
            $v['avgSessionDurationMs'],
            $v['uniqueEndpoints'],
            $v['errorRate'],
            $v['timeOfDayBias'],
            $v['avgResponseBodyBytes'],
        ];
    }

    /** @param BaselineEntry $entry */
    private function computeMaxCV(array $entry): float
    {
        $maxCV = 0.0;
        for ($i = 0; $i < $this->featureDimensions; $i++) {
            $mean = $entry['ewmaMean'][$i];
            $std = sqrt(max($entry['ewmaVariance'][$i], 1e-10));
            if (abs($mean) > 1e-10) {
                $maxCV = max($maxCV, $std / abs($mean));
            }
        }

        return $maxCV;
    }
}
