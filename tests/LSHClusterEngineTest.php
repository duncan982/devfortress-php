<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\LSHClusterEngine;
use PHPUnit\Framework\TestCase;

final class LSHClusterEngineTest extends TestCase
{
    /** @return array{sourceId: string, endpoint: string, method: string, headerSignature: list<string>, bodyHash?: string, userAgent?: string} */
    private function fpFor(string $sourceId, string $endpoint): array
    {
        return [
            'sourceId' => $sourceId,
            'endpoint' => $endpoint,
            'method' => 'POST',
            'headerSignature' => ['accept-encoding:gzip', 'accept-language:en'],
            'bodyHash' => 'abc123',
            'userAgent' => 'attack-bot/1.0',
        ];
    }

    public function testFirstIngestCreatesNewCluster(): void
    {
        $engine = new LSHClusterEngine();

        $result = $engine->ingest($this->fpFor('src-1', '/api/login'));
        self::assertTrue($result['newCluster']);
        self::assertNotNull($result['clusterId']);
        self::assertSame(0.0, $result['similarity']);
    }

    public function testSimilarFingerprintsJoinSameCluster(): void
    {
        $engine = new LSHClusterEngine();

        $first = $engine->ingest($this->fpFor('src-1', '/api/login'));
        $second = $engine->ingest($this->fpFor('src-2', '/api/login'));

        self::assertFalse($second['newCluster']);
        self::assertSame($first['clusterId'], $second['clusterId']);
        self::assertGreaterThanOrEqual(0.7, $second['similarity']);
    }

    public function testDissimilarFingerprintsCreateSeparateClusters(): void
    {
        $engine = new LSHClusterEngine();

        $a = $engine->ingest([
            'sourceId' => 'src-a', 'endpoint' => '/api/login', 'method' => 'POST',
            'headerSignature' => ['accept:text/html'], 'userAgent' => 'curl/8.0',
        ]);
        $b = $engine->ingest([
            'sourceId' => 'src-b', 'endpoint' => '/api/billing/export', 'method' => 'GET',
            'headerSignature' => ['accept:application/json'], 'userAgent' => 'Mozilla/5.0 Chrome/120',
        ]);

        self::assertNotSame($a['clusterId'], $b['clusterId']);
    }

    public function testCampaignDetectedWithSharedEndpoints(): void
    {
        $engine = new LSHClusterEngine(minSharedEndpointsForCampaign: 1, minCampaignMembers: 3);

        $last = null;
        for ($i = 0; $i < 4; $i++) {
            $last = $engine->ingest($this->fpFor("bot-{$i}", '/api/admin/export'));
        }

        self::assertNotNull($last['campaign']);
        self::assertGreaterThanOrEqual(3, $last['campaign']['participantCount']);
    }

    public function testExplosionGuardTriggersAboveMaxClusterSize(): void
    {
        $engine = new LSHClusterEngine(maxClusterSize: 3, hardCapClusterSize: 10);

        $last = null;
        for ($i = 0; $i < 5; $i++) {
            $last = $engine->ingest($this->fpFor("src-{$i}", '/api/login'));
        }

        self::assertTrue($last['explosionGuard']);
    }

    public function testHardCapRejectsBeyondAbsoluteLimit(): void
    {
        $engine = new LSHClusterEngine(maxClusterSize: 2, hardCapClusterSize: 3);

        for ($i = 0; $i < 3; $i++) {
            $engine->ingest($this->fpFor("src-{$i}", '/api/login'));
        }
        $before = $engine->getMetrics()['totalFingerprints'];

        $engine->ingest($this->fpFor('src-overflow', '/api/login'));
        $after = $engine->getMetrics()['totalFingerprints'];

        self::assertSame($before, $after);
    }

    public function testAllowlistBypassesExplosionGuard(): void
    {
        $engine = new LSHClusterEngine(maxClusterSize: 2, hardCapClusterSize: 10);

        $first = $engine->ingest($this->fpFor('src-0', '/api/login'));
        self::assertNotNull($first['clusterId']);
        $engine->allowlistCluster($first['clusterId']);

        $last = null;
        for ($i = 1; $i < 5; $i++) {
            $last = $engine->ingest($this->fpFor("src-{$i}", '/api/login'));
        }

        self::assertFalse($last['explosionGuard']);
    }

    public function testClusterExpiresAfterTtl(): void
    {
        $engine = new LSHClusterEngine(clusterTtlSeconds: 0.01);

        $result = $engine->ingest($this->fpFor('src-1', '/api/login'));
        usleep(50_000);

        $engine->ingest($this->fpFor('src-2', '/api/other'));

        self::assertNotNull($result['clusterId']);
        self::assertNull($engine->getCluster($result['clusterId']));
    }

    public function testGetClusterReturnsTopEndpoints(): void
    {
        $engine = new LSHClusterEngine();

        $result = $engine->ingest($this->fpFor('src-1', '/api/login'));
        $engine->ingest($this->fpFor('src-2', '/api/login'));

        self::assertNotNull($result['clusterId']);
        $info = $engine->getCluster($result['clusterId']);
        self::assertNotNull($info);
        self::assertSame(2, $info['memberCount']);
        self::assertSame('/api/login', $info['topEndpoints'][0][0]);
    }

    public function testMetrics(): void
    {
        $engine = new LSHClusterEngine();

        $engine->ingest($this->fpFor('src-1', '/api/login'));
        $engine->ingest($this->fpFor('src-2', '/api/login'));

        $metrics = $engine->getMetrics();
        self::assertGreaterThanOrEqual(1, $metrics['totalClusters']);
        self::assertSame(2, $metrics['totalFingerprints']);
    }
}
