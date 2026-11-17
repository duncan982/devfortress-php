<?php

// PATENT-GATE: A19C / B3 / B4 — gated. Do not expose. See .gitattributes'
// export-ignore exclusion.

declare(strict_types=1);

namespace DevFortress\Sdk;

use DevFortress\Sdk\Tier2Gated\AgentIdentitySession;
use DevFortress\Sdk\Tier2Gated\ConsentAliasLifecycle;
use DevFortress\Sdk\Tier2Gated\MultiHopTrustChain;

/**
 * Internal-only entry point for the gated Tier 2 surface (A19C agent
 * identity protection, B3 consent alias lifecycle, B4 multi-hop trust
 * chain). Excluded from the distributed package (see .gitattributes'
 * `export-ignore` of `src/Tier2Gated/` AND this file itself) and
 * reachable only by code that requires this file directly — mirroring
 * the Node SDK's `devfortress-sdk/internal` subpath export and the Ruby
 * SDK's `lib/devfortress/internal.rb`, both likewise excluded from what
 * gets published/distributed.
 *
 * ConsentAliasLifecycle (B3) and MultiHopTrustChain (B4) are gated again
 * as of TODO 420 (2026-11-03, Duncan's explicit decision): TODO 367's
 * 2026-10-16 decision to ship them public assumed Node already did so,
 * but commit 4a3e71e3 (2026-10-06) had already excluded them from Node's
 * npm tarball ten days earlier. This reinstates the pre-TODO-367 state,
 * matching Node's actual excluded posture — see
 * src/Tier2Gated/ConsentAliasLifecycle.php and
 * src/Tier2Gated/MultiHopTrustChain.php.
 *
 * Honest limit (see the session report for the full writeup): unlike
 * Node's subpath-export exclusion or Ruby's `private_constant` (which at
 * least blocks the naive `::`-qualified lookup even though it's
 * bypassable via `const_get`), PHP has no language-level mechanism to make
 * a declared class inaccessible to code that already has the file on its
 * include path — no "package-private" or "internal" visibility modifier,
 * no friend-class mechanism, and a private constructor can only be called
 * from inside the exact same class, so it cannot be used to force callers
 * through a *different* class's factory. Distribution exclusion (this
 * file and `Tier2Gated/` both being absent from a normal `composer
 * require` of this package) is therefore PHP's ONLY real boundary here —
 * there is no second layer. The classes below have ordinary public
 * constructors; adding a private-constructor-plus-public-static-factory
 * pattern was deliberately not done, since the factory would have to live
 * on the gated class itself to compile, which would recreate the exact
 * same access path `new` already offers and could misleadingly imply a
 * boundary that was not actually there.
 */
final class Internal
{
    private function __construct()
    {
    }

    /**
     * Construct an AgentIdentitySession (A19C). Mirrors Node's
     * `df.agent(agentId)` / the Go SDK's `tier2.NewAgentIdentitySession` /
     * the Ruby SDK's `Tier2Gated.agent_identity_session`.
     */
    public static function agentIdentitySession(
        string $agentId,
        string $projectId,
        string $webhookSecret,
        ?string $identityMasterKey = null,
        string $aliasMethod = 'csprng',
        string $platformId = 'default',
    ): AgentIdentitySession {
        return new AgentIdentitySession($agentId, $projectId, $webhookSecret, $identityMasterKey, $aliasMethod, $platformId);
    }

    /**
     * Construct a ConsentAliasLifecycle (B3).
     */
    public static function consentAliasLifecycle(...$args): ConsentAliasLifecycle
    {
        return new ConsentAliasLifecycle(...$args);
    }

    /**
     * Construct a MultiHopTrustChain (B4).
     */
    public static function multiHopTrustChain(...$args): MultiHopTrustChain
    {
        return new MultiHopTrustChain(...$args);
    }
}
