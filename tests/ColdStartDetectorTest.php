<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\ColdStartDetector;
use PHPUnit\Framework\TestCase;

final class ColdStartDetectorTest extends TestCase
{
    /** @return array{avgCallsPerSession: float, endpointEntropy: float, avgRequestBytes: float, avgLatencyMs: float, avgSessionDurationMs: float, uniqueEndpoints: float, errorRate: float, timeOfDayBias: float, avgResponseBodyBytes: float} */
    private function sampleFeatures(float $seed = 0.0): array
    {
        return [
            'avgCallsPerSession' => 10.0 + $seed,
            'endpointEntropy' => 1.5,
            'avgRequestBytes' => 512.0,
            'avgLatencyMs' => 50.0,
            'avgSessionDurationMs' => 60_000.0,
            'uniqueEndpoints' => 4.0,
            'errorRate' => 0.01,
            'timeOfDayBias' => 14.0,
            'avgResponseBodyBytes' => 1024.0,
        ];
    }

    public function testColdStartUsesPopulationComparator(): void
    {
        $detector = new ColdStartDetector();

        for ($i = 0; $i < 20; $i++) {
            $detector->recordObservation('seed-entity', $this->sampleFeatures((float) ($i % 3)));
        }

        $result = $detector->assess('brand-new-entity', $this->sampleFeatures());
        self::assertSame('population_comparator', $result['method']);
        self::assertSame('cold_start', $result['quality']['phase']);
    }

    public function testLearningPhaseBeforeMinSessions(): void
    {
        $detector = new ColdStartDetector(minSessionsForBaseline: 10);

        for ($i = 0; $i < 5; $i++) {
            $detector->recordObservation('entity-1', $this->sampleFeatures());
        }

        $quality = $detector->getQuality('entity-1');
        self::assertSame('learning', $quality['phase']);
        self::assertFalse($quality['isStable']);
    }

    public function testStabilizesBelowCvThreshold(): void
    {
        $detector = new ColdStartDetector(minSessionsForBaseline: 5, cvStabilityThreshold: 0.5);

        for ($i = 0; $i < 10; $i++) {
            $detector->recordObservation('entity-1', $this->sampleFeatures());
        }

        $quality = $detector->getQuality('entity-1');
        self::assertTrue($quality['isStable']);
        self::assertSame('stable', $quality['phase']);
        self::assertEqualsWithDelta(0.05, $quality['currentAlpha'], 1e-9);
    }

    public function testIndividualBaselineFlagsAnomaly(): void
    {
        $detector = new ColdStartDetector(minSessionsForBaseline: 5, populationZScoreThreshold: 2.5);

        for ($i = 0; $i < 10; $i++) {
            $detector->recordObservation('entity-1', $this->sampleFeatures());
        }

        $anomalous = $this->sampleFeatures();
        $anomalous['avgCallsPerSession'] = 10_000.0;

        $result = $detector->assess('entity-1', $anomalous);
        self::assertSame('individual_baseline', $result['method']);
        self::assertTrue($result['suspicious']);
        self::assertContains('avgCallsPerSession', $result['anomalousFeatures']);
    }

    public function testConfidenceIncreasesWithSessionCount(): void
    {
        $detector = new ColdStartDetector(minSessionsForBaseline: 10);

        $detector->recordObservation('entity-1', $this->sampleFeatures());
        $early = $detector->assess('entity-1', $this->sampleFeatures());

        for ($i = 0; $i < 20; $i++) {
            $detector->recordObservation('entity-1', $this->sampleFeatures());
        }
        $later = $detector->assess('entity-1', $this->sampleFeatures());

        self::assertGreaterThan($early['confidence'], $later['confidence']);
    }

    public function testPopulationStatsAccumulate(): void
    {
        $detector = new ColdStartDetector();

        for ($i = 0; $i < 5; $i++) {
            $detector->recordObservation('entity-1', $this->sampleFeatures((float) $i));
        }

        $stats = $detector->getPopulationStats();
        self::assertSame(5, $stats['totalSessions']);
        self::assertCount(9, $stats['mean']);
        self::assertCount(9, $stats['stdDev']);
    }

    public function testMetrics(): void
    {
        $detector = new ColdStartDetector(minSessionsForBaseline: 3, cvStabilityThreshold: 0.9);

        for ($i = 0; $i < 5; $i++) {
            $detector->recordObservation('entity-1', $this->sampleFeatures());
        }
        $detector->recordObservation('entity-2', $this->sampleFeatures());

        $metrics = $detector->getMetrics();
        self::assertSame(2, $metrics['trackedEntities']);
        self::assertSame(6, $metrics['populationSessions']);
        self::assertSame(9, $metrics['configuredDimensions']);
    }

    public function testQualityForUnknownEntityIsColdStart(): void
    {
        $detector = new ColdStartDetector();
        $quality = $detector->getQuality('never-seen');
        self::assertSame('cold_start', $quality['phase']);
        self::assertInfinite($quality['maxCV']);
    }

    public function testMaxEntitiesEvictsOldest(): void
    {
        $detector = new ColdStartDetector(maxEntities: 2);

        $detector->recordObservation('entity-1', $this->sampleFeatures());
        $detector->recordObservation('entity-2', $this->sampleFeatures());
        $detector->recordObservation('entity-3', $this->sampleFeatures());

        self::assertSame(2, $detector->getMetrics()['trackedEntities']);
        self::assertSame('cold_start', $detector->getQuality('entity-1')['phase']);
    }
}
