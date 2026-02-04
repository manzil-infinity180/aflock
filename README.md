# aflock

**Cryptographically signed policies that constrain AI agent behavior.**

> Like `package-lock.json` locks dependencies, `.aflock` locks what an agent can do.

## Vision

AI agents are increasingly autonomous. They run commands, access APIs, modify files, and spawn sub-agents. But how do you:

1. **Constrain** what an agent can do? (spend limits, tool restrictions, file access)
2. **Prove** the agent operated within bounds? (signed attestations)
3. **Verify** after the fact? (cryptographic verification)
4. **Delegate** to sub-agents with stricter constraints? (sublayouts)

**aflock** solves this with a policy file that:
- Defines limits, grants, and constraints
- Is cryptographically signed by a human (agent can't modify it)
- Binds to agent identity (model + environment + tools)
- Produces verifiable attestations for every action

## Key Insight: Agent Identity

An agent's identity is derived from its configuration, not assigned:

```
AgentIdentity = SHA256(model || environment || tools || policyDigest || parent)
```

| Component | Discovered From |
|-----------|-----------------|
| Model | `--model` flag, env var |
| Environment | PID introspection (UID, container ID, binary path) |
| Tools | MCP capabilities |
| Policy | `.aflock` in agent's working directory |
| Parent | Parent agent identity (if sub-agent) |

The agent connects to aflock via MCP. aflock gets the PID from the socket, introspects the process, and derives identity. **The agent cannot lie about its identity.**

## Key Insight: JWT + Signing Key Separation

Agents receive a **JWT** for authorization, but attestations are signed by a **key they cannot access**:

```
┌─────────────────────┐    ┌─────────────────────────────────┐
│  JWT (Agent Holds)  │    │  Signing Key (Server Holds)    │
│                     │    │                                 │
│  - Identity claims  │    │  - Never exposed to agent      │
│  - Granted scopes   │    │  - Signs all attestations      │
│  - Short-lived      │    │  - Bound to agent identity     │
└─────────────────────┘    └─────────────────────────────────┘
```

The agent **presents** the JWT but **cannot sign** attestations. All signatures go through the aflock server.

## Architecture

```
┌──────────────────────┐          ┌──────────────────────┐
│  AI Agent            │   MCP    │  aflock Server       │
│  (Claude Code)       │◄────────►│                      │
│                      │          │  - PID introspection │
│  - Calls MCP tools   │          │  - Identity derivation│
│  - Holds JWT         │          │  - Policy enforcement │
│  - Never sees keys   │          │  - Attestation signing│
└──────────────────────┘          └──────────────────────┘
```

Based on [SPIRE](https://github.com/spiffe/spire) architecture - battle-tested workload identity.

## Example Policy

```json
{
  "version": "1.0",
  "name": "feature-implementation",

  "identity": {
    "allowedModels": ["claude-opus-4-5-20251101"],
    "allowedEnvironments": ["container:ghcr.io/org/*"]
  },

  "grants": {
    "secrets": { "allow": ["vault:secret/data/readonly/*"] },
    "apis": { "allow": ["https://api.anthropic.com/*"] }
  },

  "limits": {
    "maxSpendUSD": { "value": 10.00, "enforcement": "fail-fast" },
    "maxTokensIn": { "value": 500000, "enforcement": "fail-fast" },
    "maxTurns": { "value": 50, "enforcement": "post-hoc" }
  },

  "tools": {
    "allow": ["Read", "Edit", "Bash", "Glob", "Grep"],
    "deny": ["Task"],
    "requireApproval": ["Bash:rm -rf *", "Bash:git push --force"]
  },

  "files": {
    "allow": ["src/**", "tests/**"],
    "deny": ["**/.env", "**/secrets/**"]
  },

  "materialsFrom": {
    "session": {
      "path": "${CLAUDE_SESSION_PATH}",
      "algorithm": "sha256"
    },
    "git": {
      "treeHash": "${GIT_TREE_HASH}"
    }
  },

  "evaluators": {
    "rego": [{
      "name": "spend-limit",
      "policy": "deny contains msg if { sum_spend > input.limits.maxSpendUSD.value }"
    }],
    "ai": [{
      "name": "quality-check",
      "prompt": "PASS if code is production-ready. FAIL otherwise."
    }]
  },

  "sublayouts": [{
    "name": "research-agent",
    "policy": "./policies/research.aflock",
    "limits": { "maxSpendUSD": { "value": 2.00 } },
    "inherit": ["domains", "functionaries"]
  }]
}
```

## Core Concepts

### Limits (with Enforcement Modes)

| Limit | Enforcement | Description |
|-------|-------------|-------------|
| `maxSpendUSD` | fail-fast | Abort immediately if exceeded |
| `maxTokensIn` | fail-fast | Abort immediately if exceeded |
| `maxTurns` | post-hoc | Verify at completion |
| `maxWallTimeSeconds` | fail-fast | Abort immediately if exceeded |

### Grants (Resource Access)

```json
{
  "grants": {
    "secrets": { "allow": ["vault:*"], "deny": ["vault:production/*"] },
    "apis": { "allow": ["https://api.anthropic.com/*"] },
    "storage": { "allow": ["s3://attestations/${RUN_ID}/*"] }
  }
}
```

### Materials (Ordering Proofs)

Session JSONL merkle tree proves:
- **Order**: Turn 3 came after turns 0-2
- **Completeness**: No turns skipped
- **Distance**: Turns are contiguous

### Sublayouts (Sub-Agent Delegation)

Inspired by [in-toto sublayouts](https://github.com/in-toto/specification):
- Sub-agent limits must be stricter than parent
- Cumulative spend counts toward parent total
- Attestations are namespaced with prefix
- Verification recurses into sublayouts

## Documentation

- **[Specification](docs/spec.md)** - Full schema, verification algorithm, SPIRE reference
- **[Examples](examples/)** - Compliance evaluation, todo app verification

## Status

Private development. Specification phase.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
