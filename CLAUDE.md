# ebi Development Guidelines

## Active technologies

- Go 1.24+
- `mvdan.cc/sh/v3` for POSIX/Bash parsing
- standard `crypto/ed25519` + RFC 8785 JCS for portable records
- `golang.org/x/mod/sumdb/{tlog,note}` for transparency data
- AWS SDK v2 for R2/MinIO/S3-compatible storage
- embedded gitleaks v8 detector for redacted secret findings
- optional TypeScript only in `deploy/cloudflare/` for thin Container glue

## Repository structure

```text
cmd/ebi/              CLI
cmd/ebi-server/       submit server/sequencer/admin commands
cmd/ebi-monitor/      independent verifier
internal/             config, keys, contribution queue
pkg/                  reusable security/log/storage packages
deploy/               Cloudflare and self-host manifests
dataset/              CC0 dataset format/license
docs/                 design, threat model, policy format
```

## Required validation

```bash
gofmt -w $(find cmd internal pkg -name '*.go' -type f)
go test ./...
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build ./cmd/...
make cross-build
```

For Cloudflare changes:

```bash
cd deploy/cloudflare
npm ci
npx wrangler types --check worker-configuration.d.ts
npx tsc --noEmit
npx wrangler deploy --dry-run
```

## Security rules

- Never execute input before it is fully buffered, bounded, and hashed.
- Treat scripts, LLM output, records, object-store data, and archives as untrusted.
- Verification corruption is a hard failure; do not silently downgrade it.
- Do not add a full-hash or URL lookup endpoint.
- Never print or persist matched secret values.
- Keep source naming derived from `pkg/appmeta` where practical.
- All binaries must remain buildable with `CGO_ENABLED=0`.
- New dependencies require a clear supply-chain justification.
- `ebi` provides evidence, not a safety guarantee.

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
