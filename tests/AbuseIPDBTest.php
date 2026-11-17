<?php

declare(strict_types=1);

namespace DevFortress\Sdk\Tests;

use DevFortress\Sdk\AbuseIPDB;
use DevFortress\Sdk\AbuseIPDBException;
use DevFortress\Sdk\Tests\Support\StubServer;
use PHPUnit\Framework\TestCase;

/**
 * Node's SDK has no test file for abuseipdb.ts, so there is no existing
 * coverage pattern to mirror. These tests exercise the real curl-based
 * HTTP calls against PHP's own built-in server (StubServer, shared with
 * CurlWireTest) — no real network calls — plus cache/scoring/rate-limit
 * logic.
 */
final class AbuseIPDBTest extends TestCase
{
    private ?StubServer $server = null;

    protected function setUp(): void
    {
        AbuseIPDB::_reset();
    }

    protected function tearDown(): void
    {
        $this->server?->close();
        $this->server = null;
        AbuseIPDB::_reset();
    }

    /** @param list<array{0: int, 1: array<string, mixed>}> $responses */
    private function stub(array $responses): StubServer
    {
        $server = $this->server = new StubServer($responses);
        AbuseIPDB::$apiBase = $server->url;
        return $server;
    }

    public function testCheckIpParsesSuccessfulResponse(): void
    {
        $this->stub([[200, ['data' => [
            'abuseConfidenceScore' => 42, 'totalReports' => 3, 'numDistinctUsers' => 2, 'isTor' => false,
            'usageType' => 'Data Center/Web Hosting/Transit', 'countryCode' => 'US',
            'lastReportedAt' => '2026-10-01T00:00:00Z', 'isp' => 'Example ISP',
        ]]]]);

        $result = AbuseIPDB::checkIp('1.2.3.4', 'test-key');
        self::assertSame(42, $result['abuseConfidenceScore']);
        self::assertFalse($result['isTor']);
    }

    public function testCheckIpThrowsOnNonOkResponse(): void
    {
        $this->stub([[500, []]]);
        $this->expectException(AbuseIPDBException::class);
        AbuseIPDB::checkIp('1.2.3.4', 'test-key');
    }

    public function testCheckIpThrowsWhenRateLimited(): void
    {
        AbuseIPDB::_setRateLimitCount('checkCount', AbuseIPDB::CHECKS_PER_DAY);
        $this->expectException(AbuseIPDBException::class);
        AbuseIPDB::checkIp('1.2.3.4', 'test-key');
    }

    public function testReportIpSucceeds(): void
    {
        $this->stub([[200, ['data' => ['abuseConfidenceScore' => 50]]]]);
        $result = AbuseIPDB::reportIp('1.2.3.4', [18, 21], 'brute force', 'test-key');
        self::assertSame(50, $result['data']['abuseConfidenceScore']);
    }

    public function testReportIpThrowsWhenRateLimited(): void
    {
        AbuseIPDB::_setRateLimitCount('reportCount', AbuseIPDB::REPORTS_PER_DAY);
        $this->expectException(AbuseIPDBException::class);
        AbuseIPDB::reportIp('1.2.3.4', [18], 'x', 'test-key');
    }

    public function testSyncBlacklistCachesSyncedEntries(): void
    {
        $this->stub([[200, ['data' => [
            ['ipAddress' => '9.9.9.9', 'abuseConfidenceScore' => 99],
            ['ipAddress' => '8.8.8.8', 'abuseConfidenceScore' => 80],
        ]]]]);

        $count = AbuseIPDB::syncBlacklist('test-key');
        self::assertSame(2, $count);
        self::assertSame(99, AbuseIPDB::getCachedScore('9.9.9.9'));
        self::assertSame(80, AbuseIPDB::getCachedScore('8.8.8.8'));
    }

    public function testSyncBlacklistThrowsWhenRateLimited(): void
    {
        AbuseIPDB::_setRateLimitCount('blacklistCount', AbuseIPDB::BLACKLIST_SYNCS_PER_DAY);
        $this->expectException(AbuseIPDBException::class);
        AbuseIPDB::syncBlacklist('test-key');
    }

    public function testScoreThreatUsesCacheWhenAvailable(): void
    {
        AbuseIPDB::_setCacheEntry('1.2.3.4', 80, microtime(true) + 60);
        $result = AbuseIPDB::scoreThreat('1.2.3.4', 0.1, 'unused');
        self::assertTrue($result['fromCache']);
        self::assertSame(80, $result['abuseScore']);
    }

    public function testScoreThreatFallsBackWithoutApiKey(): void
    {
        $result = AbuseIPDB::scoreThreat('5.6.7.8', 0.9);
        self::assertSame(0, $result['abuseScore']);
        self::assertSame(54, $result['score']); // 0*0.4 + 0.9*100*0.6 = 54
        self::assertFalse($result['fromCache']);
    }

    public function testScoreThreatAmplifiersIncreaseScoreAndCapAt100(): void
    {
        $this->stub([[200, ['data' => [
            'abuseConfidenceScore' => 95, 'totalReports' => 50, 'numDistinctUsers' => 15, 'isTor' => true,
            'usageType' => 'Data Center/Web Hosting/Transit', 'countryCode' => 'US', 'isp' => 'x',
        ]]]]);

        $result = AbuseIPDB::scoreThreat('9.9.9.9', 0.95, 'test-key');
        self::assertSame(100, $result['score']);
        self::assertSame('critical', $result['severity']);
    }

    public function testScoreThreatSeverityBands(): void
    {
        $low = AbuseIPDB::scoreThreat('low-ip', 0.1);
        self::assertSame('low', $low['severity']);

        AbuseIPDB::_setCacheEntry('med-ip', 50, microtime(true) + 60);
        $medium = AbuseIPDB::scoreThreat('med-ip', 0.3);
        self::assertSame('medium', $medium['severity']);
    }

    public function testScoreThreatSwallowsCheckIpFailures(): void
    {
        $this->stub([[500, []]]);
        $result = AbuseIPDB::scoreThreat('1.1.1.1', 0.5, 'test-key');
        self::assertSame(0, $result['abuseScore']);
        self::assertSame(30, $result['score']);
    }

    public function testGetCachedScoreReturnsNullWhenAbsent(): void
    {
        self::assertNull(AbuseIPDB::getCachedScore('not-cached'));
    }

    public function testGetCachedScoreReturnsNullWhenExpired(): void
    {
        AbuseIPDB::_setCacheEntry('expired', 10, microtime(true) - 1);
        self::assertNull(AbuseIPDB::getCachedScore('expired'));
    }

    public function testRateLimitStatusReportsUsage(): void
    {
        AbuseIPDB::_setRateLimitCount('checkCount', 5);
        $status = AbuseIPDB::rateLimitStatus();
        self::assertSame(5, $status['checks']['used']);
        self::assertSame(AbuseIPDB::CHECKS_PER_DAY, $status['checks']['limit']);
    }
}
