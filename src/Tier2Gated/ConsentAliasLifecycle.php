<?php

// PATENT-GATE: B3 — Filing 4 — Wave 4 only

declare(strict_types=1);

namespace DevFortress\Sdk\Tier2Gated;

/**
 * DevFortress SDK — B3: Consent Alias Lifecycle.
 *
 * Manages consent-aware alias creation and revocation. Aliases are only
 * created when user consent is obtained, and automatically revoked
 * immediately when consent is withdrawn (spec §5.3.2's 5-step description
 * has no grace-period language — this is a GDPR/CCPA correctness
 * property, not a tunable preference). Mirrors
 * packages/devfortress-sdk/src/consent-alias-lifecycle.ts.
 */
final class ConsentAliasLifecycle
{
    private readonly bool $requireExplicitConsent;
    /** @var (\Closure(string, ?string): bool)|null */
    private readonly ?\Closure $aliasRevoker;
    /** @var array<string, array{subjectId: string, consentGiven: bool, consentTimestamp: int, withdrawalTimestamp: ?int, aliasIds: list<string>, purpose: string}> */
    private array $store = [];

    /** @param (callable(string, ?string): bool)|null $aliasRevoker Called for every alias bound to a subject when consent is withdrawn. */
    public function __construct(bool $requireExplicitConsent = true, ?callable $aliasRevoker = null)
    {
        $this->requireExplicitConsent = $requireExplicitConsent;
        $this->aliasRevoker = $aliasRevoker !== null ? \Closure::fromCallable($aliasRevoker) : null;
    }

    /** @return array{allowed: bool, reason: string, consentState: string} */
    public function checkConsent(string $subjectId): array
    {
        if (getenv('FEATURE_PLATFORM_INTEL') === 'false') {
            return ['allowed' => false, 'reason' => 'Feature not enabled', 'consentState' => 'unknown'];
        }

        $record = $this->store[$subjectId] ?? null;

        if ($record === null) {
            return [
                'allowed' => !$this->requireExplicitConsent,
                'reason' => $this->requireExplicitConsent ? 'No consent record found' : 'Implicit consent allowed',
                'consentState' => 'unknown',
            ];
        }

        if ($record['consentGiven'] && $record['withdrawalTimestamp'] === null) {
            return ['allowed' => true, 'reason' => 'Active consent', 'consentState' => 'active'];
        }

        // Withdrawal is immediate (spec §5.3.2) — there is no grace period
        // during which a withdrawn subject remains treated as consented.
        return ['allowed' => false, 'reason' => 'Consent withdrawn', 'consentState' => 'withdrawn'];
    }

    /**
     * @param list<string> $aliasIds
     * @return array{subjectId: string, consentGiven: bool, consentTimestamp: int, withdrawalTimestamp: ?int, aliasIds: list<string>, purpose: string}
     */
    public function grantConsent(string $subjectId, string $purpose, array $aliasIds = []): array
    {
        $record = [
            'subjectId' => $subjectId,
            'consentGiven' => true,
            'consentTimestamp' => (int) round(microtime(true) * 1000),
            'withdrawalTimestamp' => null,
            'aliasIds' => $aliasIds,
            'purpose' => $purpose,
        ];
        $this->store[$subjectId] = $record;

        return $record;
    }

    /**
     * Withdraw consent for a subject — revokes every alias bound to them
     * immediately (spec §5.3.2). No grace period: a withdrawn subject's
     * aliases must not continue to be treated as consented-to.
     *
     * @return array{allowed: bool, reason: string, consentState: string, revokedAliasIds?: list<string>}
     */
    public function withdrawConsent(string $subjectId): array
    {
        $record = $this->store[$subjectId] ?? null;
        if ($record === null) {
            return ['allowed' => false, 'reason' => 'No consent record found', 'consentState' => 'unknown'];
        }

        $record['consentGiven'] = false;
        $record['withdrawalTimestamp'] = (int) round(microtime(true) * 1000);

        $revokedAliasIds = [];
        if ($this->aliasRevoker !== null) {
            foreach ($record['aliasIds'] as $aliasId) {
                if (($this->aliasRevoker)($aliasId, 'consent_withdrawn')) {
                    $revokedAliasIds[] = $aliasId;
                }
            }
        }

        $this->store[$subjectId] = $record;

        return [
            'allowed' => false,
            'reason' => $this->aliasRevoker !== null
                ? 'Consent withdrawn — ' . count($revokedAliasIds) . '/' . count($record['aliasIds']) . ' alias(es) immediately revoked'
                : 'Consent withdrawn — immediate revocation required, but no aliasRevoker is configured on this instance',
            'consentState' => 'withdrawn',
            'revokedAliasIds' => $revokedAliasIds,
        ];
    }

    /** @return array{subjectId: string, consentGiven: bool, consentTimestamp: int, withdrawalTimestamp: ?int, aliasIds: list<string>, purpose: string}|null */
    public function getRecord(string $subjectId): ?array
    {
        return $this->store[$subjectId] ?? null;
    }
}
