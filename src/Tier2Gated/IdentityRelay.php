<?php

// PATENT-GATE: A19C — Filing 3 extension — FILED, PENDING GRANT. Do not expose.

declare(strict_types=1);

namespace DevFortress\Sdk\Tier2Gated;

use DevFortress\Sdk\PromptInjectionFilter;

/**
 * DevFortress SDK — A19C: On-Device Identity Relay.
 *
 * Intercepts data access requests from AI agents, checks the consent
 * matrix, and either fulfils with alias-projected values, denies with a
 * structured response, or passes through real values when allowed.
 * Mirrors packages/devfortress-sdk/src/agent-identity/identity-relay.ts.
 *
 * @internal Gated surface — excluded from the distributed package.
 */
final class IdentityRelay
{
    /**
     * Identity-exfiltration-specific phrasing that A16's generic injection
     * patterns don't cover (A16 targets instruction-override/role-hijack/
     * code exec; these target "give the agent's output my PII" phrasing).
     * Fed into PromptInjectionFilter as customPatterns so detection runs
     * through A16's single weighted-scoring engine instead of a second
     * parallel check.
     */
    private const IDENTITY_EXFILTRATION_CUSTOM_PATTERNS = [
        'send.*(?:email|name|phone|address|identity).*to',
        'forward.*(?:user|customer).*(?:data|info|details)',
        '(?:extract|leak|export).*(?:personal|pii|identity)',
        'reveal.*(?:real|actual|true).*(?:email|name|identity)',
        'output.*(?:all|the).*user.*(?:data|info|profile)',
        'print.*(?:real|actual).*(?:email|name|phone)',
        'disclose.*(?:personal|private|real).*information',
    ];

    private readonly PromptInjectionFilter $identityInjectionFilter;
    /** @var \Closure(string, array<string, mixed>): void */
    private readonly \Closure $emit;

    /** @param callable(string, array<string, mixed>): void $emit */
    public function __construct(
        private readonly ConsentMatrix $consentMatrix,
        private readonly IdentityProjection $identityProjection,
        callable $emit,
    ) {
        $this->emit = \Closure::fromCallable($emit);
        // A16 already covers generic instruction-override/role-hijack/
        // code-exec patterns; 'high' sensitivity plus the identity-specific
        // custom patterns above means a single match scores well past the
        // filter's "unsafe" threshold.
        $this->identityInjectionFilter = new PromptInjectionFilter('high', self::IDENTITY_EXFILTRATION_CUSTOM_PATTERNS);
    }

    /**
     * Convenience wrapper around intercept() for a single-field access
     * check outside of a tracked session.
     *
     * @param array<string, mixed>|string $realValue
     * @return array{value: array<string, mixed>|string|null, wasAliased: bool, denied: bool, threatType?: string}
     */
    public function resolve(string $agentId, string $requestedCategory, array|string $realValue): array
    {
        return $this->intercept($agentId, $requestedCategory, $realValue, '');
    }

    /**
     * @param array<string, mixed>|string $realValue
     * @return array{value: array<string, mixed>|string|null, wasAliased: bool, denied: bool, threatType?: string}
     */
    public function intercept(
        string $agentId,
        string $category,
        array|string $realValue,
        string $sessionId,
        ?string $reasoning = null,
        ?string $platformId = null,
    ): array {
        // Prompt injection detection — check before consent, emit regardless
        $injectionResult = $this->detectPromptInjection($reasoning);
        if ($injectionResult !== null) {
            ($this->emit)(EventTypes::PROMPT_INJECTION_IDENTITY_EXFILTRATION, [
                'agentId' => $agentId,
                'category' => $category,
                'sessionId' => $sessionId,
                'threatType' => 'prompt_injection_identity_exfiltration',
                'severity' => 'CRITICAL',
                'detectedPatterns' => $injectionResult['detectedPatterns'],
                'confidence' => $injectionResult['confidence'],
                'reasoning' => substr((string) $reasoning, 0, 200),
                'timestamp' => self::nowMs(),
            ]);
        }

        $decision = $this->consentMatrix->check($agentId, $category);

        if ($decision === 'deny') {
            ($this->emit)(EventTypes::AGENT_DATA_DENIAL, [
                'agentId' => $agentId, 'category' => $category, 'sessionId' => $sessionId,
                'threatType' => 'out_of_scope_data_access', 'severity' => 'MEDIUM', 'timestamp' => self::nowMs(),
            ]);

            return ['value' => null, 'wasAliased' => false, 'denied' => true, 'threatType' => 'out_of_scope_data_access'];
        }

        if ($decision === 'alias') {
            $realValueForAlias = is_string($realValue) ? $realValue : json_encode($realValue, JSON_THROW_ON_ERROR);
            $aliasValue = $this->identityProjection->projectField($agentId, $sessionId, $category, $realValueForAlias, null, $platformId ?? 'default');
            ($this->emit)(EventTypes::AGENT_DATA_ACCESS, [
                'agentId' => $agentId, 'category' => $category, 'sessionId' => $sessionId,
                'decision' => 'alias', 'wasAliased' => true, 'severity' => 'INFO', 'timestamp' => self::nowMs(),
            ]);

            return ['value' => $aliasValue, 'wasAliased' => true, 'denied' => false];
        }

        // decision === 'allow'
        ($this->emit)(EventTypes::AGENT_DATA_ACCESS, [
            'agentId' => $agentId, 'category' => $category, 'sessionId' => $sessionId,
            'decision' => 'allow', 'wasAliased' => false, 'severity' => 'INFO', 'timestamp' => self::nowMs(),
        ]);

        return ['value' => $realValue, 'wasAliased' => false, 'denied' => false];
    }

    /** @return array{detectedPatterns: list<string>, confidence: float}|null */
    private function detectPromptInjection(?string $reasoning): ?array
    {
        if ($reasoning === null) {
            return null;
        }
        $result = $this->identityInjectionFilter->scan($reasoning);
        if ($result['safe']) {
            return null;
        }

        return ['detectedPatterns' => $result['detectedPatterns'], 'confidence' => $result['confidence']];
    }

    private static function nowMs(): int
    {
        return (int) round(microtime(true) * 1000);
    }
}
