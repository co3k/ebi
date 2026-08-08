# ebi dataset snapshot format

Snapshots are zstd-compressed POSIX tar archives. Entries are regular files
only; duplicate paths, links, absolute paths, traversal, oversized files,
excessive file counts, and total-size overflow are rejected.

## Archive layout

```text
snapshot.json
v1/checkpoint
v1/leaf/<index>
v1/tile/<C2SP tlog tile path>
v1/blob/<record-id>
v1/prefix/<5hex>
v1/score/params.json
dataset/records.jsonl
```

The `v1/blob/` namespace also contains non-leaf reproducibility artifacts whose
path is `sha256(exact bytes)`, including server-retrieved public script bytes
and LLM prompt artifacts. These entries are verified by content hash and do not
create transparency-log leaves of their own.

`v1/leaf/<index>` is authoritative append order:

```json
{"index":0,"leaf":"<base64 Merkle leaf hash>","record_id":"<hex64>"}
```

The path suffix, JSON index, hash encoding, and record ID are strictly checked;
indexes must be contiguous from zero.

`dataset/records.jsonl` contains exactly one deterministic JSON object per leaf,
in leaf order. A normal line contains the complete signed envelope:

```json
{"index":0,"record_id":"<hex64>","record":{"body":{},"public_key":"...","signature":"..."}}
```

A deliberately deleted blob is represented without recreating the deleted
record:

```json
{"index":0,"record_id":"<hex64>","tombstone":true,"tombstone_sha256":"<hex64>"}
```

A tombstone is valid only when a later signed and included `moderation/v1`
record binds its original record ID and the exact tombstone blob hash.

`v1/prefix/<5hex>` is rebuilt from non-retracted, non-tombstoned audit records
and retains each record's original `log_index`. `v1/score/params.json` freezes
the scoring parameter version used when the snapshot was produced.

`snapshot.json` contains tree size, checkpoint text, origin, creation time, total
uncompressed content size, and a manifest of every other entry. Its `sha256`
field is the digest of that manifest (the compressed archive digest is returned
out of band by the creation API/latest metadata to avoid self-reference).

## Verification and import

```bash
ebi verify --policy ./trust-policy.toml snapshot.tar.zst
ebi-server import --mode=mirror snapshot.tar.zst
ebi-server import --mode=fork snapshot.tar.zst
```

An operator can publish the immutable archive and update the public pointer
last:

```bash
ebi-server snapshot --publish \
  --public-base-url https://log.example.com \
  --mirror-urls https://mirror.example.com/v1/snapshot/<tree-size>.tar.zst
```

This writes `v1/snapshot/<tree-size>.tar.zst` and then
`v1/snapshot/latest.json`. In the pointer, `size` is the compressed archive
size and `sha256` is the compressed archive digest.

Verification authenticates the checkpoint, all Merkle inclusions, records,
tombstones/moderation bindings, retractions, and reconstructed shards.

- `mirror` copies the original signed tree assets unchanged.
- `fork` verifies and re-sequences portable signed records into an independent
  log. It rejects snapshots containing tombstoned leaves because the original
  signed envelopes no longer exist and must not be fabricated.

All public record/dataset content is dedicated under `dataset/LICENSE`
(CC0-1.0). Source code remains under the repository's MIT license.
