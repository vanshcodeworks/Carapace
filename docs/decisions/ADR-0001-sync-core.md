# ADR-0001: Synchronous core API, async facade later

Date: 2026-10-25 · Status: accepted · Milestone: C1

## Context
The original architecture sketch proposed `BoxStream<Bytes>` stdout/stderr
on `SandboxHandle`, implying an async runtime across the whole core. Tier 1
is fundamentally fork/clone/wait code, where async adds hazard (fork in a
multithreaded executor, signal safety, drop order across await points) with
no performance benefit: process spawn latency is dominated by kernel work
(namespaces, mounts, exec), not by our plumbing.

## Decision
- `carapace-core` defines a **synchronous** `Backend`/`SandboxHandle` trait:
  `spawn(&spec) -> Box<dyn SandboxHandle>`, `wait() -> ExitReport`,
  `kill(reason)`. Output is collected with byte caps and returned with the
  report (and later exposed incrementally via a callback/iterator).
- The MCP server and HTTP daemon (later milestones) may run their own async
  runtime at the edge and bridge to the sync core (`spawn_blocking`).
- If C8 (zygote pool) shows a need, revisit with a new ADR; the trait shape
  keeps that door open (an async wrapper trait can compose the sync one).

## Consequences
- No tokio dependency in core/native — smaller audit surface, Miri-friendlier.
- Streaming line-by-line output to callers arrives as a small extension
  (bounded channel + reader threads), not a trait change.
