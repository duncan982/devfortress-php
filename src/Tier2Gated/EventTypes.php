<?php

// PATENT-GATE: A19C — Filing 3 extension — FILED, PENDING GRANT. Do not expose.

declare(strict_types=1);

namespace DevFortress\Sdk\Tier2Gated;

/**
 * DevFortress SDK — A19C: Agent Identity Event Types.
 *
 * Canonical event type identifiers emitted by IdentityRelay and
 * AgentIdentitySession. Mirrors lib/events/event-types.ts on the platform
 * side and packages/devfortress-sdk/src/agent-identity/event-types.ts.
 *
 * @internal Gated surface — excluded from the distributed package.
 */
final class EventTypes
{
    public const AGENT_DATA_ACCESS = 'AGENT_DATA_ACCESS';
    public const AGENT_DATA_DENIAL = 'AGENT_DATA_DENIAL';
    public const AGENT_SESSION_ATTESTATION = 'AGENT_SESSION_ATTESTATION';
    public const PROMPT_INJECTION_IDENTITY_EXFILTRATION = 'PROMPT_INJECTION_IDENTITY_EXFILTRATION';

    private function __construct()
    {
    }
}
