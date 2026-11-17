<?php

// PATENT-GATE: A19C — Filing 3 extension — FILED, PENDING GRANT. Do not expose.

declare(strict_types=1);

namespace DevFortress\Sdk\Tier2Gated;

/**
 * DevFortress SDK — A19C: Identity Field Projection.
 *
 * Projects real user identity fields into alias values using the
 * configured alias generation method. Real values are never stored in the
 * projection — only in the AES-256-GCM encrypted local vault (VaultShared).
 *
 * Namespace context strings include a platform dimension
 * (`{agentId}.{platformId}.{sessionId}.{category}`) so the same real
 * value, agent, and session produce statistically independent aliases on
 * different platforms. Mirrors
 * packages/devfortress-sdk/src/agent-identity/identity-projection.ts.
 *
 * @internal Gated surface — excluded from the distributed package.
 */
final class IdentityProjection
{
    private const DEFAULT_PLATFORM_ID = 'default';

    /** @var array<string, array{category: string, expiresAt: int, platformId: string}> */
    private static array $aliasCache = [];

    public function __construct(
        private readonly string $method = 'csprng',
        private readonly int $ttlSeconds = 3600,
        private readonly ?string $masterKey = null,
    ) {
    }

    /**
     * Generate (and register in the resolvable cache) a single field alias.
     * Shared by project() below and by IdentityRelay's runtime interception
     * path, so every alias handed to an agent resolves later.
     */
    public function projectField(
        string $agentId,
        string $sessionId,
        string $category,
        string $real,
        ?int $expiresAt = null,
        string $platformId = self::DEFAULT_PLATFORM_ID,
    ): string {
        $effectiveExpiresAt = $expiresAt ?? (int) floor(microtime(true)) + $this->ttlSeconds;

        $generated = AliasGenerator::generateIdentityAlias(
            field: $real,
            fieldType: $category,
            method: $this->method,
            ttlSeconds: $this->ttlSeconds,
            context: "{$agentId}.{$platformId}.{$sessionId}.{$category}",
            masterKey: $this->masterKey,
        );
        $formatted = AliasGenerator::formatAliasForField($generated['token'], $category);
        VaultShared::register($formatted, $real);
        self::$aliasCache[$formatted] = ['category' => $category, 'expiresAt' => $effectiveExpiresAt, 'platformId' => $platformId];

        return $formatted;
    }

    /**
     * @param array{name?: string, email?: string, phone?: string, location?: array{lat: float, lng: float, city?: string}, paymentToken?: string, calendarAccessToken?: string, contactsAccessToken?: string} $profile
     * @param list<string> $consentedCategories
     * @return array<string, mixed>
     */
    public function project(string $agentId, string $sessionId, array $profile, array $consentedCategories, string $platformId = self::DEFAULT_PLATFORM_ID): array
    {
        $now = (int) floor(microtime(true));
        $expiresAt = $now + $this->ttlSeconds;

        $bound = fn (string $real, string $category) => $this->projectField($agentId, $sessionId, $category, $real, $expiresAt, $platformId);

        $nameAlias = isset($profile['name']) && in_array('identity.name', $consentedCategories, true)
            ? $bound($profile['name'], 'identity.name')
            : 'User-' . bin2hex(random_bytes(3));

        $emailAlias = isset($profile['email']) && in_array('identity.email', $consentedCategories, true)
            ? $bound($profile['email'], 'identity.email')
            : 'alias-' . bin2hex(random_bytes(3)) . '@devfortress.alias';

        if (!array_key_exists($nameAlias, self::$aliasCache)) {
            VaultShared::register($nameAlias, '');
            self::$aliasCache[$nameAlias] = ['category' => 'identity.name', 'expiresAt' => $expiresAt, 'platformId' => $platformId];
        }
        if (!array_key_exists($emailAlias, self::$aliasCache)) {
            VaultShared::register($emailAlias, '');
            self::$aliasCache[$emailAlias] = ['category' => 'identity.email', 'expiresAt' => $expiresAt, 'platformId' => $platformId];
        }

        $result = [
            'aliasName' => $nameAlias,
            'aliasEmail' => $emailAlias,
            'sessionId' => $sessionId,
            'agentId' => $agentId,
            'aliasMethod' => $this->method,
            'issuedAt' => $now,
            'expiresAt' => $expiresAt,
        ];

        if (isset($profile['phone']) && in_array('identity.phone', $consentedCategories, true)) {
            $result['aliasPhone'] = $bound($profile['phone'], 'identity.phone');
        }

        if (isset($profile['location']) && in_array('identity.location', $consentedCategories, true)) {
            $cityAlias = $profile['location']['city'] ?? self::downgradeLocationToCityLevel($profile['location']);
            $result['aliasLocation'] = ['city' => $cityAlias];
        }

        if (isset($profile['paymentToken']) && in_array('identity.payment', $consentedCategories, true)) {
            $result['aliasPaymentRef'] = $bound($profile['paymentToken'], 'identity.payment');
        }

        if (isset($profile['calendarAccessToken']) && in_array('identity.calendar', $consentedCategories, true)) {
            $result['aliasCalendarRef'] = $bound($profile['calendarAccessToken'], 'identity.calendar');
        }

        if (isset($profile['contactsAccessToken']) && in_array('identity.contacts', $consentedCategories, true)) {
            $result['aliasContactsRef'] = $bound($profile['contactsAccessToken'], 'identity.contacts');
        }

        return $result;
    }

    /**
     * Resolve an alias back to the real value from the encrypted local
     * vault. Local-only — no network call.
     *
     * $platformId, when passed, must match the platform the alias was
     * minted under — a mismatch returns null.
     */
    public function resolve(string $alias, ?string $platformId = null): ?string
    {
        return self::resolveAlias($alias, $platformId);
    }

    /** Remove all cached aliases for a session. */
    public function revokeSession(string $sessionId, string $agentId, string $platformId = self::DEFAULT_PLATFORM_ID): void
    {
        $prefix = "{$agentId}.{$platformId}.{$sessionId}";
        foreach (array_keys(self::$aliasCache) as $key) {
            if (str_contains($key, $prefix)) {
                unset(self::$aliasCache[$key]);
                VaultShared::delete($key);
            }
        }
    }

    /**
     * Static cross-module resolution entry point (e.g. relay, and the live
     * product path via AgentIdentitySession::resolve()).
     */
    public static function resolveAlias(string $alias, ?string $platformId = null): ?string
    {
        $entry = self::$aliasCache[$alias] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($platformId !== null && $entry['platformId'] !== $platformId) {
            return null;
        }
        if ((microtime(true) * 1000) > $entry['expiresAt'] * 1000) {
            unset(self::$aliasCache[$alias]);
            VaultShared::delete($alias);

            return null;
        }

        return VaultShared::resolve($alias);
    }

    public static function revokeByAlias(string $alias): void
    {
        unset(self::$aliasCache[$alias]);
        VaultShared::delete($alias);
    }

    /**
     * Reduce a lat/lng pair to a coarse, non-reversible city-level bucket.
     *
     * PLACEHOLDER: no reverse-geocoding service is wired up yet, so this
     * cannot resolve an actual city name from coordinates. It rounds to
     * one decimal degree (~11km) so raw coordinates are never passed
     * through unmodified — same placeholder as Node's own
     * downgradeLocationToCityLevel().
     *
     * @param array{lat: float, lng: float} $location
     */
    private static function downgradeLocationToCityLevel(array $location): string
    {
        $roundedLat = number_format(round($location['lat'], 1), 1);
        $roundedLng = number_format(round($location['lng'], 1), 1);

        return "Region {$roundedLat},{$roundedLng}";
    }
}
