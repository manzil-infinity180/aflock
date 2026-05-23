---
sidebar_position: 6
---

# Defense in Depth (Kernel Sandbox)

aflock enforces policy at the **tool layer**: it approves or blocks MCP tool calls and records attestations for those calls. This works as long as the agent's actions route through aflock-controlled tools.

## Threat Model Boundary

The enforcement boundary is the MCP tool gate. If an agent can execute **native** tools outside aflock (for example via Claude Code `Task`/`Agent` subagents), those actions can bypass tool-level enforcement. This is the core risk highlighted in issue #100.

## How Kernel Sandboxing Closes the Gap

A kernel-enforced sandbox provides a floor that **all child processes inherit**, even if they bypass aflock’s MCP server. The recommended upstream today is [nono](https://github.com/always-further/nono), which enforces:

- **Landlock** (Linux) for irreversible filesystem restrictions
- **seccomp-notify** for syscall mediation
- **Supervisor/child trust split** so the untrusted agent never gains direct file/network capabilities

With nono in place, a subagent’s native `bash`/`write` calls still hit the kernel policy and are denied when out of bounds.

## Recommended Deployment

For production use, run aflock **inside** a kernel sandbox such as nono and require both layers:

1. **aflock policy** – logical constraints (tools, limits, sublayouts, budgets)
2. **nono profile** – kernel-enforced filesystem/network floor

The `requireKernelSandbox` policy field can be used to refuse startup unless a nono supervisor is detected.
