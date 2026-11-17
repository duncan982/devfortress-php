<?php

// PATENT-GATE: A19C — Filing 3 extension — FILED, PENDING GRANT. Do not expose.

declare(strict_types=1);

namespace DevFortress\Sdk\Tier2Gated;

/**
 * DevFortress SDK — A19C: Attestation Certificate Generation.
 *
 * Generates HMAC-SHA256 signed per-session attestation certificates
 * confirming which agent accessed which data categories, what consent
 * decisions applied, and that no real identity was transmitted. Mirrors
 * packages/devfortress-sdk/src/agent-identity/attestation.ts.
 *
 * @internal Gated surface — excluded from the distributed package.
 */
final class Attestation
{
    private function __construct()
    {
    }

    /**
     * $session['startedAt'] is accepted for parity with Node's
     * AgentIdentitySessionRecord shape but — matching Node's own
     * generateAttestation(), which likewise never includes startedAt in
     * the signed payload — is not part of the signed output below.
     *
     * @param array{sessionId: string, agentId: string, projectId: string, startedAt: int, dataAccessed: list<array{category: string, decision: string}>} $session
     * @return array{sessionId: string, agentId: string, projectId: string, issuedAt: int, dataAccessed: list<array{category: string, decision: string}>, realIdentityTransmitted: false, signature: string}
     */
    public static function generate(array $session, string $webhookSecret): array
    {
        $payload = [
            'sessionId' => $session['sessionId'],
            'agentId' => $session['agentId'],
            'projectId' => $session['projectId'],
            'issuedAt' => (int) floor(microtime(true)),
            'dataAccessed' => $session['dataAccessed'],
            'realIdentityTransmitted' => false,
        ];

        $canonical = json_encode($payload, JSON_THROW_ON_ERROR);
        $signature = hash_hmac('sha256', $canonical, $webhookSecret);

        return [...$payload, 'signature' => $signature];
    }

    /** @param array<string, mixed> $certificate */
    public static function verify(array $certificate, string $webhookSecret): bool
    {
        $signature = $certificate['signature'] ?? null;
        if (!is_string($signature)) {
            return false;
        }
        $payload = $certificate;
        unset($payload['signature']);

        $canonical = json_encode($payload, JSON_THROW_ON_ERROR);
        $expected = hash_hmac('sha256', $canonical, $webhookSecret);

        if (strlen($signature) !== strlen($expected)) {
            return false;
        }

        return hash_equals($expected, $signature);
    }
}
