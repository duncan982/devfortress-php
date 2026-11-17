<?php

// PATENT-GATE: A19C — Filing 3 extension — FILED, PENDING GRANT. Do not expose.

declare(strict_types=1);

namespace DevFortress\Sdk\Tier2Gated;

/**
 * Agent Identity Session (A19C) — returned by Internal::agentIdentitySession().
 * Wraps ConsentMatrix + IdentityProjection + IdentityRelay with a clean
 * API. Mirrors
 * packages/devfortress-sdk/src/agent-identity/devfortress-full.ts's
 * AgentIdentitySession.
 *
 * Usage:
 *   $session = Internal::agentIdentitySession('support-agent-1', 'proj_123', 'whsec_test');
 *   $session->consent(['identity.email' => 'alias', 'identity.phone' => 'deny']);
 *   $projected = $session->project(['name' => 'Jane Doe', 'email' => 'jane@example.com']);
 *   $cert = $session->revoke();
 *
 * @internal Gated surface — excluded from the distributed package.
 */
final class AgentIdentitySession
{
    private readonly string $sessionId;
    private readonly int $sessionStart;
    private readonly ConsentMatrix $consentMatrix;
    private readonly IdentityProjection $identityProjection;
    private readonly IdentityRelay $relay;
    /** @var list<array{category: string, decision: string}> */
    private array $accessLog = [];
    /** @var (\Closure(string, array<string, mixed>): void)|null */
    private ?\Closure $emitHandler = null;

    /**
     * $identityMasterKey may be null (an ephemeral per-call key is then
     * used by context-reading alias methods, which defeats persistent
     * platform-namespace isolation for those methods specifically — csprng,
     * the default, is unaffected).
     */
    public function __construct(
        public readonly string $agentId,
        private readonly string $projectId,
        private readonly string $webhookSecret,
        ?string $identityMasterKey = null,
        string $aliasMethod = 'csprng',
        public readonly string $platformId = 'default',
    ) {
        $this->sessionId = bin2hex(random_bytes(12));
        $this->sessionStart = (int) floor(microtime(true));

        $this->consentMatrix = new ConsentMatrix($identityMasterKey);
        $this->identityProjection = new IdentityProjection($aliasMethod, masterKey: $identityMasterKey);
        $emit = function (string $eventType, array $payload): void {
            if ($this->emitHandler !== null) {
                /** @var array<string, mixed> $payload */
                ($this->emitHandler)($eventType, $payload);
            }
        };
        $this->relay = new IdentityRelay($this->consentMatrix, $this->identityProjection, $emit);
    }

    /**
     * Sets the callback invoked for every event this session's relay
     * emits (AGENT_DATA_ACCESS, AGENT_DATA_DENIAL,
     * PROMPT_INJECTION_IDENTITY_EXFILTRATION, AGENT_SESSION_ATTESTATION).
     *
     * @param callable(string, array<string, mixed>): void $handler
     */
    public function onEmit(callable $handler): void
    {
        $this->emitHandler = \Closure::fromCallable($handler);
    }

    /**
     * Set consent decisions for this agent.
     *
     * @param array<string, string> $decisions category => decision ('allow'|'deny'|'alias')
     */
    public function consent(array $decisions): self
    {
        foreach ($decisions as $category => $decision) {
            $this->consentMatrix->grant($this->agentId, $category, $decision);
        }

        return $this;
    }

    /**
     * Project user identity to alias values based on current consent. Each
     * present profile field is routed through IdentityRelay::intercept()
     * so consent is checked/gated in one place — the same path that emits
     * AGENT_DATA_ACCESS/AGENT_DATA_DENIAL/prompt-injection events — instead
     * of re-deriving decisions locally and bypassing the relay.
     *
     * @param array{name?: string, email?: string, phone?: string, location?: array{lat: float, lng: float, city?: string}, paymentToken?: string, calendarAccessToken?: string, contactsAccessToken?: string} $profile
     * @return array<string, mixed>
     */
    public function project(array $profile): array
    {
        $categoryFields = [
            ['identity.name', $profile['name'] ?? null],
            ['identity.email', $profile['email'] ?? null],
            ['identity.phone', $profile['phone'] ?? null],
            ['identity.location', $profile['location'] ?? null],
            ['identity.payment', $profile['paymentToken'] ?? null],
            ['identity.calendar', $profile['calendarAccessToken'] ?? null],
            ['identity.contacts', $profile['contactsAccessToken'] ?? null],
        ];

        $consentedCategories = [];
        foreach ($categoryFields as [$category, $value]) {
            if ($value === null) {
                continue;
            }
            $response = $this->relay->intercept(
                $this->agentId,
                $category,
                is_array($value) ? json_encode($value, JSON_THROW_ON_ERROR) : $value,
                $this->sessionId,
                platformId: $this->platformId,
            );
            $decision = $response['denied'] ? 'deny' : ($response['wasAliased'] ? 'alias' : 'allow');
            $this->accessLog[] = ['category' => $category, 'decision' => $decision];
            if ($response['wasAliased']) {
                $consentedCategories[] = $category;
            }
        }

        return $this->identityProjection->project($this->agentId, $this->sessionId, $profile, $consentedCategories, $this->platformId);
    }

    /**
     * Resolve an alias back to the real value. Local-only — no network
     * call. Deliberately does NOT go through relay::intercept()/resolve()
     * (both emit events via the injected $emit callback, a fire-and-forget
     * network call) — routing resolution through the relay would turn this
     * into a networked call and break the "local-only" guarantee this
     * method exists to provide.
     */
    public function resolve(string $alias): ?string
    {
        return IdentityProjection::resolveAlias($alias, $this->platformId);
    }

    /**
     * Revoke all aliases and consent for this agent session. Returns a
     * signed attestation certificate for compliance audit.
     *
     * @return array<string, mixed>
     */
    public function revoke(): array
    {
        $cert = Attestation::generate([
            'sessionId' => $this->sessionId,
            'agentId' => $this->agentId,
            'projectId' => $this->projectId,
            'startedAt' => $this->sessionStart,
            'dataAccessed' => $this->accessLog,
        ], $this->webhookSecret);

        $this->consentMatrix->revoke($this->agentId);
        $this->identityProjection->revokeSession($this->sessionId, $this->agentId, $this->platformId);

        if ($this->emitHandler !== null) {
            ($this->emitHandler)(EventTypes::AGENT_SESSION_ATTESTATION, [
                'agentId' => $this->agentId,
                'sessionId' => $this->sessionId,
                'projectId' => $this->projectId,
                'issuedAt' => $cert['issuedAt'],
                'signature' => $cert['signature'],
                'realIdentityTransmitted' => $cert['realIdentityTransmitted'],
                'dataAccessedCount' => count($cert['dataAccessed']),
                'severity' => 'INFO',
                'timestamp' => (int) round(microtime(true) * 1000),
            ]);
        }

        return $cert;
    }
}
