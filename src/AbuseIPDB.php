<?php

declare(strict_types=1);

namespace DevFortress\Sdk;

/**
 * DevFortress SDK — AbuseIPDB Integration Module.
 *
 * Mirrors packages/devfortress-sdk/src/abuseipdb.ts.
 *
 * Provides:
 * - checkIp()        — Query single IP reputation
 * - reportIp()       — Report confirmed malicious IP back to the community
 * - syncBlacklist()  — Pull full blacklist into local cache
 * - scoreThreat()    — Composite scoring combining AbuseIPDB + DevFortress signals
 *
 * The API key is always passed in by the caller (environment variable or
 * config, per the embedding app) — never hardcoded or logged here,
 * matching Node's module, which also takes it as a plain parameter.
 *
 * @phpstan-type AbuseIPDBCheckResult array{
 *     abuseConfidenceScore: int,
 *     totalReports: int,
 *     numDistinctUsers: int,
 *     isTor: bool,
 *     usageType: string,
 *     countryCode: string,
 *     lastReportedAt: string|null,
 *     isp: string,
 * }
 * @phpstan-type CompositeScoreResult array{
 *     score: int,
 *     severity: string,
 *     abuseScore: int,
 *     isTor: bool,
 *     isDatacenter: bool,
 *     distinctUsers: int,
 *     fromCache: bool,
 * }
 */
final class AbuseIPDB
{
    /** Overridable only for tests in this package (mutable static, not exposed to consumers). */
    public static string $apiBase = 'https://api.abuseipdb.com/api/v2';

    // ── S26: Client-Side Rate Limiting ──────────────────────────
    // AbuseIPDB free tier: 1,000 check requests/day, 500 reports/day. We
    // enforce conservative limits client-side to avoid 429 responses.
    public const CHECKS_PER_DAY = 900; // Leave 10% headroom from 1,000
    public const REPORTS_PER_DAY = 450; // Leave 10% headroom from 500
    public const BLACKLIST_SYNCS_PER_DAY = 4; // max 4 syncs/day (every 6h)
    private const WINDOW_SECONDS = 86_400; // 24 hours

    /** @var array<string, array{score: int, expiresAt: float}> */
    private static array $ipCache = [];

    /**
     * windowStart starts at 0.0 because a static property default must be
     * a compile-time constant (microtime(true) is not). ensureWindowInitialized()
     * sets it to the real current time on first use from any entry point —
     * checkRateLimit() or rateLimitStatus() — matching Node's windowStart:
     * Date.now() set once at module load.
     *
     * @var array{checkCount: int, reportCount: int, blacklistCount: int, windowStart: float}
     */
    private static array $rateLimitState = ['checkCount' => 0, 'reportCount' => 0, 'blacklistCount' => 0, 'windowStart' => 0.0];

    private static function ensureWindowInitialized(): void
    {
        if (self::$rateLimitState['windowStart'] === 0.0) {
            self::$rateLimitState['windowStart'] = microtime(true);
        }
    }

    private static function checkRateLimit(string $operation): bool
    {
        self::ensureWindowInitialized();

        $now = microtime(true);
        if (($now - self::$rateLimitState['windowStart']) >= self::WINDOW_SECONDS) {
            self::$rateLimitState = ['checkCount' => 0, 'reportCount' => 0, 'blacklistCount' => 0, 'windowStart' => $now];
        }

        return match ($operation) {
            'check' => self::bumpCheckCount(),
            'report' => self::bumpReportCount(),
            'blacklist' => self::bumpBlacklistCount(),
            default => throw new \InvalidArgumentException("unknown operation: {$operation}"),
        };
    }

    private static function bumpCheckCount(): bool
    {
        if (self::$rateLimitState['checkCount'] >= self::CHECKS_PER_DAY) {
            return false;
        }
        self::$rateLimitState['checkCount']++;
        return true;
    }

    private static function bumpReportCount(): bool
    {
        if (self::$rateLimitState['reportCount'] >= self::REPORTS_PER_DAY) {
            return false;
        }
        self::$rateLimitState['reportCount']++;
        return true;
    }

    private static function bumpBlacklistCount(): bool
    {
        if (self::$rateLimitState['blacklistCount'] >= self::BLACKLIST_SYNCS_PER_DAY) {
            return false;
        }
        self::$rateLimitState['blacklistCount']++;
        return true;
    }

    /**
     * Gets current AbuseIPDB rate limit usage for diagnostics.
     *
     * @return array{
     *     checks: array{used: int, limit: int},
     *     reports: array{used: int, limit: int},
     *     blacklistSyncs: array{used: int, limit: int},
     *     windowResetSeconds: float,
     * }
     */
    public static function rateLimitStatus(): array
    {
        self::ensureWindowInitialized();
        $elapsed = microtime(true) - self::$rateLimitState['windowStart'];
        return [
            'checks' => ['used' => self::$rateLimitState['checkCount'], 'limit' => self::CHECKS_PER_DAY],
            'reports' => ['used' => self::$rateLimitState['reportCount'], 'limit' => self::REPORTS_PER_DAY],
            'blacklistSyncs' => ['used' => self::$rateLimitState['blacklistCount'], 'limit' => self::BLACKLIST_SYNCS_PER_DAY],
            'windowResetSeconds' => max(0.0, self::WINDOW_SECONDS - $elapsed),
        ];
    }

    /**
     * Checks a single IP against AbuseIPDB. Returns reputation data
     * including confidence score, Tor status, etc.
     *
     * @return AbuseIPDBCheckResult
     */
    public static function checkIp(string $ip, string $apiKey): array
    {
        if (!self::checkRateLimit('check')) {
            throw new AbuseIPDBException('AbuseIPDB check rate limited: daily quota exhausted');
        }

        $url = self::$apiBase . '/check?' . http_build_query(['ipAddress' => $ip, 'maxAgeInDays' => 90, 'verbose' => '']);
        [$status, $body] = self::httpRequest('GET', $url, ['Key' => $apiKey, 'Accept' => 'application/json']);

        if ($status < 200 || $status >= 300) {
            throw new AbuseIPDBException("AbuseIPDB check failed: {$status}");
        }

        $decoded = json_decode($body, true);
        $data = is_array($decoded) && is_array($decoded['data'] ?? null) ? $decoded['data'] : [];

        $lastReportedAt = $data['lastReportedAt'] ?? null;

        return [
            'abuseConfidenceScore' => is_int($data['abuseConfidenceScore'] ?? null) ? $data['abuseConfidenceScore'] : 0,
            'totalReports' => is_int($data['totalReports'] ?? null) ? $data['totalReports'] : 0,
            'numDistinctUsers' => is_int($data['numDistinctUsers'] ?? null) ? $data['numDistinctUsers'] : 0,
            'isTor' => is_bool($data['isTor'] ?? null) ? $data['isTor'] : false,
            'usageType' => is_string($data['usageType'] ?? null) ? $data['usageType'] : '',
            'countryCode' => is_string($data['countryCode'] ?? null) ? $data['countryCode'] : '',
            'lastReportedAt' => is_string($lastReportedAt) ? $lastReportedAt : null,
            'isp' => is_string($data['isp'] ?? null) ? $data['isp'] : '',
        ];
    }

    /**
     * Reports a confirmed malicious IP back to AbuseIPDB.
     *
     * Category codes:
     *   15 = Hacking
     *   18 = Brute Force
     *   19 = Port Scan / Recon
     *   21 = Web App Attack (SQLi, XSS, injection)
     *
     * @param list<int> $categories
     * @return array<string, mixed>
     */
    public static function reportIp(string $ip, array $categories, string $comment, string $apiKey): array
    {
        if (!self::checkRateLimit('report')) {
            throw new AbuseIPDBException('AbuseIPDB report rate limited: daily quota exhausted');
        }

        $body = http_build_query(['ip' => $ip, 'categories' => implode(',', $categories), 'comment' => $comment]);
        [$status, $resBody] = self::httpRequest('POST', self::$apiBase . '/report', [
            'Key' => $apiKey,
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Accept' => 'application/json',
        ], $body);

        if ($status < 200 || $status >= 300) {
            throw new AbuseIPDBException("AbuseIPDB report failed: {$status}");
        }

        $decoded = json_decode($resBody, true);
        if (!is_array($decoded)) {
            return [];
        }

        $result = [];
        foreach ($decoded as $key => $value) {
            if (is_string($key)) {
                $result[$key] = $value;
            }
        }
        return $result;
    }

    /**
     * Pulls the AbuseIPDB blacklist and stores it in the in-memory
     * cache. Returns the number of IPs synced.
     */
    public static function syncBlacklist(string $apiKey, int $confidenceMinimum = 90): int
    {
        if (!self::checkRateLimit('blacklist')) {
            throw new AbuseIPDBException('AbuseIPDB blacklist sync rate limited: daily quota exhausted');
        }

        $url = self::$apiBase . '/blacklist?' . http_build_query(['confidenceMinimum' => $confidenceMinimum, 'limit' => 10_000]);
        [$status, $body] = self::httpRequest('GET', $url, ['Key' => $apiKey, 'Accept' => 'application/json']);

        if ($status < 200 || $status >= 300) {
            throw new AbuseIPDBException("AbuseIPDB blacklist sync failed: {$status}");
        }

        /** @var array{data: list<array{ipAddress: string, abuseConfidenceScore: int}>} $json */
        $json = json_decode($body, true);
        $entries = $json['data'];

        $expiresAt = microtime(true) + (6 * 60 * 60); // 6 hours
        foreach ($entries as $entry) {
            self::$ipCache['abuseipdb:' . $entry['ipAddress']] = ['score' => (int) $entry['abuseConfidenceScore'], 'expiresAt' => $expiresAt];
        }

        return count($entries);
    }

    /**
     * Composite threat scoring. Combines AbuseIPDB external reputation
     * (40%) with DevFortress live signal (60%).
     *
     * Amplifiers (additive, capped at 100):
     *   Tor exit node          -> +20
     *   Datacenter IP          -> +10
     *   Reported by >=10 users -> +10
     *
     * @return CompositeScoreResult
     */
    public static function scoreThreat(string $ip, float $devFortressConfidence, ?string $apiKey = null): array
    {
        $cached = self::$ipCache['abuseipdb:' . $ip] ?? null;

        $abuseScore = 0;
        $isTor = false;
        $isDatacenter = false;
        $distinctUsers = 0;
        $fromCache = false;

        if ($cached !== null && microtime(true) < $cached['expiresAt']) {
            $abuseScore = $cached['score'];
            $fromCache = true;
        } elseif ($apiKey !== null) {
            try {
                $data = self::checkIp($ip, $apiKey);
                $abuseScore = $data['abuseConfidenceScore'];
                $isTor = $data['isTor'];
                $isDatacenter = str_contains($data['usageType'], 'Data Center');
                $distinctUsers = $data['numDistinctUsers'];

                self::$ipCache['abuseipdb:' . $ip] = ['score' => $abuseScore, 'expiresAt' => microtime(true) + 3600];
            } catch (\Throwable) {
                $abuseScore = 0;
            }
        }

        $score = ($abuseScore * 0.4) + ($devFortressConfidence * 100 * 0.6);
        if ($isTor) {
            $score += 20;
        }
        if ($isDatacenter) {
            $score += 10;
        }
        if ($distinctUsers >= 10) {
            $score += 10;
        }
        $scoreInt = min((int) round($score), 100);

        $severity = match (true) {
            $scoreInt >= 85 => 'critical',
            $scoreInt >= 60 => 'high',
            $scoreInt >= 35 => 'medium',
            default => 'low',
        };

        return [
            'score' => $scoreInt,
            'severity' => $severity,
            'abuseScore' => $abuseScore,
            'isTor' => $isTor,
            'isDatacenter' => $isDatacenter,
            'distinctUsers' => $distinctUsers,
            'fromCache' => $fromCache,
        ];
    }

    /** Gets the cached score for an IP without making an API call. */
    public static function getCachedScore(string $ip): ?int
    {
        $cached = self::$ipCache['abuseipdb:' . $ip] ?? null;
        if ($cached === null || microtime(true) > $cached['expiresAt']) {
            return null;
        }
        return $cached['score'];
    }

    /** @internal for tests only. */
    public static function _reset(): void
    {
        self::$ipCache = [];
        self::$rateLimitState = ['checkCount' => 0, 'reportCount' => 0, 'blacklistCount' => 0, 'windowStart' => microtime(true)];
        self::$apiBase = 'https://api.abuseipdb.com/api/v2';
    }

    /** @internal for tests only. */
    public static function _setCacheEntry(string $ip, int $score, float $expiresAt): void
    {
        self::$ipCache['abuseipdb:' . $ip] = ['score' => $score, 'expiresAt' => $expiresAt];
    }

    /** @internal for tests only. */
    public static function _setRateLimitCount(string $key, int $value): void
    {
        match ($key) {
            'checkCount' => self::$rateLimitState['checkCount'] = $value,
            'reportCount' => self::$rateLimitState['reportCount'] = $value,
            'blacklistCount' => self::$rateLimitState['blacklistCount'] = $value,
            default => throw new \InvalidArgumentException("unknown rate limit key: {$key}"),
        };
    }

    /**
     * @param 'GET'|'POST' $method
     * @param array<string, string> $headers
     * @return array{0: int, 1: string}
     */
    private static function httpRequest(string $method, string $url, array $headers, string $body = ''): array
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new AbuseIPDBException('could not initialise curl');
        }

        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = "{$name}: {$value}";
        }

        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $lines);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        if ($body !== '') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $response = curl_exec($ch);
        if ($response === false) {
            $message = curl_error($ch);
            curl_close($ch);
            throw new AbuseIPDBException($message !== '' ? $message : 'curl request failed');
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return [$status, (string) $response];
    }
}
