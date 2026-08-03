# ebi trust policy

The policy is strict TOML. Unknown fields are rejected.

```toml
origin = "ebi.example.com"

# One valid signature from any configured log key is required.
log_keys = [
  "ebi.example.com+01234567+BASE64_GO_NOTE_VERIFIER_KEY",
]

# Distinct verified witness keys count toward this quorum. C2SP
# tlog-cosignature Ed25519 keys use algorithm byte 0x04.
witness_keys = [
  "witness-1.example+89abcdef+BASE64_C2SP_VERIFIER_KEY",
  "witness-2.example+fedcba98+BASE64_C2SP_VERIFIER_KEY",
]
required_witnesses = 2
```

These are the only supported fields:

| Field | Required | Meaning |
|---|---:|---|
| `origin` | yes | Exact first line expected in the checkpoint |
| `log_keys` | yes | Trusted Go-note log verifier keys |
| `witness_keys` | no | Trusted timestamped C2SP cosignature verifier keys |
| `required_witnesses` | yes | k in k-of-N; may be zero |

Checkpoint state is deliberately **not** a policy field. Configure it separately
with `checkpoint_path` in `~/.config/ebi/config.toml`, `EBI_CHECKPOINT_PATH`,
CLI `--checkpoint`, or monitor `--checkpoint-state`. This local state detects
rollback/equivocation and verifies a consistency proof whenever the tree grows.

Generate a policy matching a server key with:

```bash
ebi-server init-policy --data-dir ./data --output ./trust-policy.toml
```

For self-host compose this happens automatically into a shared read-only volume.
A public operator must distribute its real log and witness keys out of band;
the source repository intentionally cannot ship a universal trusted production
key.

Verification fails closed for malformed policies, unknown fields, duplicate
keys, a key listed as both log and witness, insufficient witness signatures,
wrong origin, rollback, equal-size equivocation, or invalid consistency proofs.

When rotating keys, overlap old and new keys in the policy while clients verify
a checkpoint bridging the transition, then remove the retired key. A production
rotation procedure must also define how users authenticate policy updates.
