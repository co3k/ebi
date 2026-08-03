# ebi specification status (v0.1 implementation)

This repository implements the safepipe-style specification under the existing
product name `ebi`. It is an evidence and transparency tool, **not a safety
guarantee**.

## Milestones

| Milestone | Status | Evidence / qualification |
|---|---|---|
| M1 local execution gate | Implemented | exact-byte buffering, 10 MiB bound, static analysis, TTY-only confirmation, flagged override, safe shebang, child exit propagation, E2E tests |
| M2 transparency/storage | Implemented core | ordered leaf index, real tlog tiles/checkpoints, local + S3 stores, server sequencer, snapshot and monitor tests. Large 10k-load benchmarking is not a release gate in this repository |
| M3 authenticated lookup | Implemented | five-hex shard lookup, local signature/checkpoint/witness/inclusion/consistency verification, tamper tests and persisted checkpoint state |
| M4 contribution/privacy | Implemented core | opt-in delayed queue, server re-fetch, mismatch state, retraction, masked report gate, strict tombstone/moderation binding. Interactive mismatch-report CLI UX remains future work |
| M5 optional LLM | Implemented | OpenAI-compatible HTTP, fixed anti-injection prompt, strict JSON retries, self-consistency, mechanical claims, separate analyzer record |
| M6 distribution/deploy | Implemented core | snapshot verify/mirror/fork/publish+latest pointer, Cloudflare container/IaC, self-host MinIO/server/monitor, cross-build matrix. Production witness operation and very-large-tree soak tests remain deployment work |

## Deliberate safe limitations

- PowerShell, runtime sandboxing, behavior monitoring, and second-stage binary
  attestation are outside v1.
- A fork import refuses tombstoned snapshots; portability cannot recreate a
  signed envelope that was intentionally removed.
- With a nonzero quorum, the server can contact configured C2SP witness URLs.
  It also stages `v1/pending-checkpoint`, allowing an external process to
  supply a fully timestamped/cosigned `v1/witnessed-checkpoint`. Only a
  quorum-valid checkpoint is published.
- The storage lease is defense in depth. Operators must still enforce one
  sequencer instance because portable S3 APIs do not give this abstraction a
  universally atomic compare-and-swap lease.
- Auditor trust history is an input to the deterministic scorer. New keys start
  near zero; production communities still need a published trust-evolution and
  governance policy based on observed data.

## Stable wire rules

- record body: RFC 8785 JCS;
- record ID: `sha256(JCS(body))`;
- signature digest: `sha256("ebi-record-v1\n" || JCS(body))`;
- signer: Ed25519; auditor ID: SHA-256 of public key;
- log leaf: `sha256(recordID-bytes || auditorID-bytes || signature-bytes)`;
- target identity: normalized URL, exact received-byte SHA-256, and size;
- lookup: first five lowercase hash hex characters only;
- wire verdicts: `ok`, `info`, `danger`; display verdicts:
  `unknown`, `caution`, `trusted`, `flagged`.
