---
sidebar_position: 2
---

# Aflock Audit (Forensics UI)

This document captures the plan for a **separate project** that provides a local-first, browser-native forensics UI for aflock session evidence. Working name: **aflock-audit**.

## Why a separate project

The forensics UI has different users and goals than existing tools:

- **aflock-tui** is terminal-only and not acceptable for auditors or regulators.
- **aflock-replay** is post-hoc replay; overloading it with forensics would dilute its purpose.
- The forensics UI needs a deep verification view (six-phase verifier, attestation chain walk, policy/identity diffs, evidence exports) that is a distinct product.

## Product principles

- **Local-first**: open a browser tab, no daemon required.
- **Evidence-first**: cryptographic verification is a primary column, not an afterthought.
- **Shareable**: export a static HTML evidence package for regulator handoff.
- **Single-user**: no multi-team backend (the separate **judge** direction is a centralized attestation collector and is intentionally out of scope).

## Existing data sources (no new schema required for Phase 1)

```
~/.aflock/sessions/<session-id>/
├── state.json
├── attestations/
│   └── *.intoto.json
└── propagation/
    └── <sublayout-name>-<digest>.json
```

## Shared parsing (extract from aflock-tui)

The forensics UI should reuse the same Go parsing logic already implemented in `aflock-tui` by extracting it into a shared `pkg/audit/` package:

- `SessionInfo`, `SessionState`, `IdentityMeta`
- `DSSEEnvelope`, `InTotoStatement`, `ActionPredicate`
- Identity fallback chain: `state.Identity` → latest attestation → JWT claims (SPIFFE ID)
- Latest attestation key ID heuristic (treat key IDs containing `/ephemeral/` as ephemeral; treat `spiffe://` key IDs as SPIRE-rooted)
- Six-phase verifier JSON (`aflock verify --session <id>`)

This keeps parsing stable and avoids re-deriving logic in the browser.

## MVP architecture (Phase 1)

**Pure static SPA** (no backend required):

- React + Vite (or SolidJS), TanStack Router
- File System Access API (Chromium) + directory-upload fallback
- WASM module exposing parsing + verify routines
- IndexedDB for search index

**Optional Phase 2 local backend**:

- `aflock audit-server` with endpoints for sessions, attestations, verify, and events

## Roadmap

### Phase 1 — read-only viewer

- Session list + per-session inspect (browser version of aflock-tui Inspect)
- Attestation explorer (DSSE → in-toto → predicate tree)
- JWT decoder + SPIFFE ID parsing
- Six-phase verifier display
- Per-action ALLOW/DENY timeline
- Policy viewer (raw JSON + parsed)
- Static HTML export of a single session

### Phase 2 — cross-session intelligence

- Reverse index (identity hash, attestation digest, policy digest, Merkle root, SPIFFE ID)
- Sublayout DAG visualization
- Policy diff + sublayout attenuation diff
- Compliance export (OSCAL JSON)

### Phase 3 — live + cross-stack

- Live event stream (depends on manzil-infinity180/aflock#3 adding the events server)
- Cross-stack rendering (aflock + nono attestation bundle, depends on manzil-infinity180/aflock#1 for nono integration)
- Fulcio cert + OID decoding, Rekor inclusion proof verification

### Phase 4 — exports & integrations

- Evidence package zip (session + attestations + signed manifest)
- Local-only share link (static report)
- CLI: `aflock-audit export --session <id> --format oscal|pdf|html`

## Proposed repo layout

```
aflock-audit/
├── web/                          # SPA
│   ├── src/
│   │   ├── views/                # session / attestation / audit pillar views
│   │   ├── components/
│   │   └── lib/
│   │       ├── wasm/             # WASM bridge
│   │       └── parsers/
│   └── static/
│       ├── audit.wasm
│       └── wasm_exec.js
├── pkg/audit/                    # shared Go parsing lib
├── cmd/audit-server/             # optional local backend
└── README.md
```

## Decisions needed before Phase 1 starts

1. **Repo home**: personal incubation vs. aflock-ai org
2. **Name**: standardize on **aflock-audit** (earlier notes used *aflock-forensics*)
3. **Frontend stack**: React + Vite (default) vs. SolidJS/Svelte
4. **Bundling**: ship as static SPA only, or also via `aflock-audit serve`
5. **Sharing scope**: confirm static HTML export only (no multi-user backend)
