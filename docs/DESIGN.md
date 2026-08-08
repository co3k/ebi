# ebi design

## Security boundary

`ebi` is a pre-execution evidence tool, not a sandbox. The local host, selected
shell interpreter, and binaries invoked by the script remain trusted by the
user. Scripts, remote HTTP responses, record blobs, LLM responses, snapshots,
file paths, and object-store listings are all untrusted input.

The server is not an authority for verdicts. It sequences signed records and
publishes derived files; clients and monitors verify and recompute locally.

## Execution path

1. `stdin`, URL, or local file is copied to an `0600` temporary file with a
   10 MiB default limit. No bytes execute until EOF and hash/size finalization.
2. Community lookup requests only `v1/prefix/<first-5-hex>`.
3. Record signatures, checkpoint policy, witness quorum, inclusion, and prior
   checkpoint consistency are verified. Authenticated corruption is a hard fail.
4. `mvdan.cc/sh/v3/syntax` analysis always runs. A parse error becomes an
   evidence claim and also triggers bounded best-effort text rules.
5. Optional LLM analysis produces a separate `analyzer.kind=llm` record. The
   fixed system prompt and user prompt are hashed together; unverifiable claims
   are discarded. LLM output never independently permits or blocks execution.
6. Confirmation is read from `/dev/tty` (`CONIN$` on Windows), never from the
   script pipe. `--yes` cannot bypass flagged results; `--force-flagged` is
   separately required.
7. A safe shebang parser executes the temporary file as an argument rather than
   constructing a shell command string. Child exit status is propagated.

## Signed records

The wire types are `audit/v1`, `retract/v1`, and `moderation/v1`.

- body canonicalization: RFC 8785 JCS;
- ID: `sha256(JCS(body))`;
- signature digest: `sha256("ebi-record-v1\n" || JCS(body))`;
- signature: Ed25519;
- auditor ID: SHA-256 of raw public-key bytes.

Claims contain category, one-based line number, exact line hash (LF removed, CR
retained), and optional short note. Display excerpts are local-only and are
excluded from signed records. Unknown categories remain on the wire for forward
compatibility and display as `misc.other`; `misc.other` needs a note.

Retractions are effective only when signed by the target record's auditor.
Tombstones replace a blob but never remove its Merkle leaf. A later included
`moderation/v1` record must bind the original record ID and the exact tombstone
blob hash. Snapshot and monitor verification enforce that ordering and binding.

## Transparency log and static reads

`pkg/tlogx` uses `golang.org/x/mod/sumdb/tlog` and Go `note` signatures. The
stored `v1/leaf/<index>` object is the authoritative append-order mapping and
contains the record ID and base64 Merkle leaf hash. Tiles use `tlog.Tile.Path()`.

Published layout:

```text
v1/checkpoint
v1/leaf/<index>
v1/tile/<C2SP tile path>
v1/blob/<record-id>
v1/prefix/<5hex>
v1/snapshot/<tree-size>.tar.zst
```

Checkpoint publication is last. If a witness quorum is configured, the server
places the log-signed candidate at `v1/pending-checkpoint`, contacts configured
C2SP witness URLs when available, and also accepts a matching externally staged
`v1/witnessed-checkpoint`; it never silently downgrades to a log-only
checkpoint. Timestamped C2SP `cosignature/v1` Ed25519 signatures (algorithm
byte `0x04`) are verified locally.

## Scoring

Scoring is a deterministic pure function in `pkg/score` with versioned
parameters. Signals are deduplicated by `(auditor key, analyzer family)`;
`model_family` is the LLM family and static/human use their analyzer kind.
Danger signals require claims and receive the asymmetric negative multiplier.
New target hashes start fresh; delta inheritance is 0.5 per level for at most
three predecessor levels.

Trust-history evolution remains an input policy rather than server authority.
The current default for a previously unseen pseudonym is intentionally near
zero, so one new key cannot create a `trusted` result.

## Privacy

- Lookup sends no full target hash or URL.
- Normal client submissions contain URL/hash/claims, never script bytes. The
  server independently re-fetches a matching public HTTPS source and stores
  those exact bytes under their SHA-256 for reproducibility.
- Mismatch reports are a separate endpoint and require an exact typed
  acknowledgement plus server-side gitleaks scanning of the already-masked
  report. Matched secret values are never returned.
- Contribution is opt-in and may be delayed randomly before batch submission.
- Blob deletion is transparent and accompanied by signed moderation. Users are
  always told that deletion does not replace credential rotation.

## Storage and sequencing

Local storage confines paths under one root and writes atomically. S3-compatible
storage supports R2 and MinIO, applies public cache metadata, and publishes the
checkpoint through a temporary object/copy step.

The deployment must enforce one sequencer. Cloudflare uses a singleton Durable
Object and `max_instances: 1`; self-host compose declares one server. The
storage lease is an additional ownership check, but S3-compatible APIs do not
provide a portable transactional compare-and-swap through this abstraction, so
it is not advertised as a substitute for the single-instance requirement.

## Snapshots

A snapshot includes the signed checkpoint, exact ordered leaf objects, tiles,
record blobs, server-fetched public script artifacts, LLM prompt artifacts,
tombstones, deterministic prefix shards with original `log_index`, score
parameters, and a one-line-per-leaf JSONL convenience dataset. Verification
checks archive limits/traversal, manifest digest, checkpoint, every inclusion,
content-addressed artifacts, record/tombstone binding, retractions, and shard
reconstruction.

Mirror import preserves the original signed log. Fork import re-sequences
portable signed records into a new log; it rejects tombstoned input because the
original deleted envelope is intentionally unavailable.
