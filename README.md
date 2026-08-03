# ebi

`ebi` replaces the `sh` in `curl … | sh` with a review gate. It buffers the
complete script, hashes the exact received bytes, verifies any community audit
records against an append-only transparency log, runs local static analysis,
optionally asks an OpenAI-compatible local LLM for advisory findings, and only
then asks whether to execute.

> **ebi does not guarantee that a script is safe.** It provides evidence,
> transparency, and a safer decision point. Execution still happens in the
> normal host shell; v1 does not sandbox or monitor runtime behavior.

The repository is a Go 1.24 monorepo. The public product and binary names remain
`ebi`, `ebi-server`, and `ebi-monitor`; user-visible naming is centralized in
`pkg/appmeta` so a future rename is localized.

## CLI

```bash
# Buffer stdin completely, review, confirm on /dev/tty, then execute.
curl -fsSL https://example.com/install.sh | ebi [flags] [-- script-args...]

# Let ebi fetch the URL (exact received bytes are hashed).
ebi run https://example.com/install.sh [flags] [-- script-args...]

# Analyze without execution.
ebi audit https://example.com/install.sh [--llm] [--llm-runs 5]
ebi audit ./install.sh --source-url https://example.com/install.sh
ebi audit ./new.sh --delta <previous-target-sha256>

# Verify an authenticated logged record, local envelope, or snapshot.
ebi verify --mirror https://static.example.com --policy ./policy.toml <record-id>
ebi verify --policy ./policy.toml snapshot.tar.zst
ebi verify record.json

ebi key {init|show|export}
ebi contribute {status|flush}
```

Important execution flags:

- `--yes`: skip the interactive confirmation. It does **not** bypass a flagged result.
- `--force-flagged`: explicit bypass required for a community or local static block.
- `--keep`: retain the private temporary script file.
- `--llm`, `--llm-runs N`: enable advisory LLM analysis.
- `--contribute`: opt in to queuing signed audit records under CC0-1.0.
- `--source-url URL`: attach a retrievable HTTPS source to piped/local content.
- `--mirror`, `--policy`, `--checkpoint`: override authenticated lookup settings.

Exit codes are the child exit code when execution starts; otherwise: `10`
(refused/no TTY), `11` (flagged), `12` (log/signature/proof failure), `13`
(fetch failure), and `14` (internal/configuration error).

## What is verified

For matching community data, the CLI locally verifies:

1. the auditor's Ed25519 signature and RFC 8785 JCS record ID;
2. the signed checkpoint and configured k-of-N witness policy;
3. the record's Merkle inclusion proof using C2SP-style tiles;
4. consistency with the last persisted checkpoint (rollback/equivocation detection);
5. exact prefix-shard membership and deterministic local scoring.

Lookup privacy uses only the first five hexadecimal SHA-256 characters. There is
no lookup API accepting a full target hash or URL.

## Configuration

Configuration lives at `~/.config/ebi/config.toml` (or `$XDG_CONFIG_HOME/ebi`).
Precedence is flags, then `EBI_*` environment variables, then TOML.

```toml
mirror_url = "https://static.example.com"
posting_urls = ["https://submit.example.com"]
policy_path = "/home/me/.config/ebi/trust-policy.toml"
# Defaults to ~/.config/ebi/checkpoint-state.toml when omitted.
checkpoint_path = "/home/me/.config/ebi/checkpoint-state.toml"
opt_in = false
contribution_delay_hours = 24

[llm]
endpoint = "http://localhost:11434/v1"
model = "qwen2.5-coder-7b-instruct"
backend = "ollama"
quantization = "q4_k_m"
runs = 5
timeout_sec = 30
```

Do not place a remote API key in a world-readable config. `EBI_LLM_API_KEY` is
supported when a user deliberately configures a remote endpoint. Normal use does
not require any API key.

## Build and validation

```bash
make build                    # CGO_ENABLED=0
go test ./...
go test -race ./...
go vet ./...
make cross-build              # all 3 binaries, 5 OS/architecture targets
make cross-clean
```

Cross-build targets are Darwin amd64/arm64, Linux amd64/arm64, and Windows
amd64 for all three binaries.

## Monitor

Verify a local filesystem store:

```bash
ebi-monitor --storage ./data \
  --policy ./trust-policy.toml \
  --checkpoint-state ./monitor-state.toml \
  --one-shot
```

Verify S3/R2/MinIO using `EBI_STORAGE_*` variables:

```bash
ebi-monitor --storage-env --policy ./trust-policy.toml --one-shot
```

A `--base-url` static mirror is also supported. HTTP monitoring fetches the
known leaf indexes and expected prefix shards directly; it does not depend on
object-store directory-listing HTML.

## Server, snapshots, and self-hosting

The server only exposes `POST /v1/records`, the secret-gated mismatch endpoint
`POST /v1/reports`, and `GET /healthz`. Public reads are static object-store
files. Useful administration commands include:

```bash
ebi-server init-policy --output ./trust-policy.toml
ebi-server snapshot --output snapshot.tar.zst
ebi-server snapshot --publish --public-base-url https://log.example.com
ebi-server import --mode=mirror snapshot.tar.zst
ebi-server import --mode=fork snapshot.tar.zst
ebi-server tombstone --record-id <record-id>
ebi-server healthcheck
```

Self-hosted MinIO + server + monitor:

```bash
cd deploy/selfhost
export EBI_MINIO_PASSWORD='replace-this'
docker compose up --build
```

The compose stack generates a matching trust policy, persists the log key and
checkpoint state, runs the monitor directly against MinIO, and uses the static
Go healthcheck subcommand (the distroless image contains no shell utilities).

Cloudflare deployment files are in `deploy/cloudflare/`. They use a singleton
Container-backed Durable Object, an R2 S3 endpoint, generated Worker runtime
types, Terraform for the bucket/WAF rule, and `max_instances: 1`. See that
directory's README.

## Dataset and licenses

Source code is MIT licensed. Public audit records and snapshot convenience data
are dedicated to the public domain under CC0-1.0; see `dataset/LICENSE` and
`dataset/SNAPSHOT.md`. Normal clients do not upload the script body. For a
successful public audit, the server independently re-fetches the already-public
HTTPS source, verifies its exact hash, and publishes those matching bytes as a
content-addressed artifact. Mismatch reports remain a separate masked,
secret-gated flow.

## Implementation status and limitations

- **M1 local CLI:** implemented and covered by no-TTY, block, argument, and exit-code tests.
- **M2 log/storage/server:** implemented for local FS and S3-compatible storage, including ordered leaf indexes and real Merkle tiles.
- **M3 lookup/witness policy:** implemented; production deployments must provide real log/witness keys and a witnessed checkpoint collector.
- **M4 contribution/mismatch/retraction:** signed contribution queue, server-side re-fetch, retractions, and secret-gated masked reports are implemented. A convenient interactive client command for the mismatch report remains future work.
- **M5 optional LLM:** implemented as advisory structured analysis with retries, self-consistency, prompt hashing, and claim verification.
- **M6 snapshots/deployment:** verify/mirror/fork/publish paths, the public `latest.json` pointer, and deployment manifests are implemented. The current fork import deliberately refuses snapshots containing tombstoned leaves because deleted signed envelopes cannot be reconstructed.

Further honest constraints:

- static analysis cannot detect every malicious or context-dependent behavior;
- the first-stage script can still download an unverified second-stage binary;
- the storage lease is defense in depth, not a substitute for configuring one sequencer instance;
- direct C2SP witness collection is available when `EBI_WITNESS_URLS` is
  configured; the staged `v1/pending-checkpoint` / `v1/witnessed-checkpoint`
  workflow remains available for external collectors;
- PowerShell/`iex`, runtime sandboxing, and binary attestation are outside v1.

See `docs/threat-model.md`, `docs/DESIGN.md`, `docs/trust-policy.md`, and
`docs/spec-v0.1.md`.

---

## 日本語概要

`ebi` は `curl … | sh` の `sh` を置き換え、**受信完了後**に正確な
SHA-256、コミュニティ監査ログ、ローカル静的解析、任意のローカル
LLM 所見を表示してから実行確認するツールです。

**安全性を保証するものではありません。** v1 はサンドボックス実行を
行わず、最終的な実行は通常のシェルに委譲します。

```bash
curl -fsSL https://example.com/install.sh | ebi
ebi run https://example.com/install.sh
ebi audit ./install.sh --source-url https://example.com/install.sh
ebi-monitor --storage-env --policy ./trust-policy.toml --one-shot
```

照合では完全ハッシュや URL を問い合わせず、SHA-256 先頭 5 桁だけを
取得元へ送り、完全一致と署名・Merkle inclusion・checkpoint・witness
定足数・consistency をローカル検証します。検証済みデータの破損は
`unknown` へ格下げせず exit 12 の hard fail です。

セルフホストは `deploy/selfhost/docker-compose.yml`、Cloudflare は
`deploy/cloudflare/` を参照してください。投稿は明示的 opt-in で、公開
レコード集合は CC0-1.0 です。
