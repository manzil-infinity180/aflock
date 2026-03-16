---
sidebar_position: 3
---

# Example: Attestation Lifecycle

A complete walkthrough of policy enforcement + attestation generation + verification using `requiredAttestations`.

## Policy

```json
{
  "version": "1.0",
  "name": "attestation-demo",
  "tools": {
    "allow": ["Read", "Bash", "Edit", "Glob", "Grep"],
    "deny": ["Task"]
  },
  "files": {
    "allow": ["src/**", "tests/**", "README.md"],
    "deny": ["**/.env", "**/secrets/**"]
  },
  "limits": {
    "maxSpendUSD": { "value": 5.00, "enforcement": "fail-fast" },
    "maxTurns": { "value": 20, "enforcement": "post-hoc" }
  },
  "requiredAttestations": ["Read", "Bash"]
}
```

## What This Policy Does

- **Tool enforcement**: Only Read, Bash, Edit, Glob, Grep are allowed
- **File protection**: `.env` and `secrets/` are blocked
- **Spend limit**: $5 max, abort immediately
- **Attestation requirement**: Session cannot stop unless both `Read` and `Bash` tool calls have been attested

## How Attestations Work

Every `PostToolUse` hook generates a signed attestation:

```
PreToolUse (Read src/main.go)  → ALLOW
[Tool executes]
PostToolUse                    → Sign attestation → store .intoto.json

PreToolUse (Read .env)         → DENY (no attestation — tool was blocked)

PreToolUse (Bash: go test)     → ALLOW
[Tool executes]
PostToolUse                    → Sign attestation → store .intoto.json

Stop                           → Check: Read attestation? ✓  Bash attestation? ✓  → OK
```

## Setup

### Configure Claude Code hooks

Create `.claude/settings.local.json` in your project:

```json
{
  "hooks": {
    "SessionStart": [{
      "matcher": "",
      "hooks": [{"type": "command", "command": "aflock hook SessionStart", "timeout": 10}]
    }],
    "PreToolUse": [{
      "matcher": "*",
      "hooks": [{"type": "command", "command": "aflock hook PreToolUse", "timeout": 5}]
    }],
    "PostToolUse": [{
      "matcher": "*",
      "hooks": [{"type": "command", "command": "aflock hook PostToolUse", "timeout": 5}]
    }],
    "Stop": [{
      "matcher": "",
      "hooks": [{"type": "command", "command": "aflock hook Stop", "timeout": 10}]
    }]
  }
}
```

### Run with Claude Code

```bash
cd your-project/   # directory with .aflock and .claude/settings.local.json
claude              # hooks auto-attach
```

Every tool call will produce a signed attestation in `~/.aflock/sessions/<id>/attestations/`.

## Inspecting Attestations

### List sessions

```bash
ls ~/.aflock/sessions/*/attestations/
```

### Decode an attestation

Each `.intoto.json` file is a DSSE envelope. Decode the payload:

```bash
ATTEST=$(ls ~/.aflock/sessions/<session-id>/attestations/*.intoto.json | head -1)
python3 -c "
import json, base64
env = json.load(open('$ATTEST'))
stmt = json.loads(base64.b64decode(env['payload']))
print(json.dumps(stmt, indent=2))
"
```

### Attestation structure

```
DSSE Envelope (.intoto.json)
├── payloadType: "application/vnd.in-toto+json"
├── payload: base64(in-toto Statement)
└── signatures: [{keyid, sig, certificate}]
        │
        ▼  (base64 decode)
in-toto v1 Statement
├── _type: "https://in-toto.io/Statement/v1"
├── subject: [{name: "session:<id>/action:<toolUseId>", digest: {sha256: "..."}}]
├── predicateType: "https://aflock.ai/attestations/action/v0.1"
└── predicate:
    ├── toolName: "Read"
    ├── toolInput: {"file_path": "src/main.go"}
    ├── decision: "allow"
    ├── timestamp: "2026-03-16T23:10:37+05:30"
    ├── agentIdentity:
    │   ├── model: "claude-opus-4-6"
    │   ├── binary: "claude-code@2.1.76"
    │   ├── binaryHash: "ffe922f4..."
    │   └── identityHash: "193c9d34..."
    └── metrics:
        ├── cumulativeTokensIn: 15000
        ├── cumulativeCostUSD: 0.42
        └── turnNumber: 3
```

## Signing Modes

| Mode | When | Key ID | Trust |
|------|------|--------|-------|
| **SPIRE** | SPIRE agent running | `spiffe://aflock.ai/agent/claude-*` | CA-chained X509-SVID |
| **Ephemeral** | No SPIRE (default) | `spiffe://aflock.ai/agent/ephemeral/<hash>` | Self-signed ECDSA |

Both produce identical DSSE envelopes. Check which mode was used:

```bash
python3 -c "
import json
env = json.load(open('$ATTEST'))
keyid = env['signatures'][0]['keyid']
print('SPIRE' if 'ephemeral' not in keyid else 'Ephemeral', '-', keyid)
"
```

## Full Automated Test

Clone [aflock-example](https://github.com/aflock-ai/aflock) and run:

```bash
cd aflock-example/attestation-demo
./run-demo.sh
```

Or run the audit script on any session:

```bash
cd aflock-example
./scripts/audit-session.sh --list
./scripts/audit-session.sh <session-id>
```
