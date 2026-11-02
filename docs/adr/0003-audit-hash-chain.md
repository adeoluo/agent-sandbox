# ADR 0003: JSON Lines audit log with a SHA-256 hash chain

- Status: accepted
- Date: 2026-11-01

## Context

The audit log answers "what did the agent try, and what happened". It must be easy to
consume (one JSON object per line, greppable, streamable into any log pipeline) and it
must make after-the-fact edits detectable.

## Decision

Each record is `{seq, ts_ms, prev_hash, event, hash}` where

```
hash = SHA-256( "{seq}\n{ts_ms}\n{prev_hash}\n" || canonical_json(event) )
```

`canonical_json` sorts object keys recursively, so the hash does not depend on serde
feature flags or field order. The first record's `prev_hash` is 64 zeros.

Appends take an exclusive `flock` and re-read the last line of the file, so several
sandbox processes can share one log without forking the chain (tested with four writer
threads). `audit verify` recomputes every hash and checks `seq` continuity and linkage.

## Consequences

- Editing, deleting, inserting, or reordering records is detected at the first affected
  line.
- Truncating the tail leaves a valid shorter chain. This is inherent to any hash chain
  without an external anchor; `verify --expect-head <hash>` detects it when the head hash
  was stored elsewhere (for example in the agent run's metadata).
- An attacker who can rewrite the whole file can recompute the whole chain. The log is
  tamper-evident relative to an anchored head, not tamper-proof; signing heads is on the
  roadmap.
- Outputs are not stored, only their byte counts and SHA-256, to keep logs small and to
  avoid copying secrets that a command printed.
