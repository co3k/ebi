# Cloudflare deployment

This directory contains a thin Worker plus a singleton Workers Container for
`ebi-server`, an R2 bucket, and a WAF rate-limit rule. Security logic remains in
the Go binary; `worker.ts` only selects the fixed Durable Object instance,
forwards an explicit allow-list of runtime vars/secrets, and proxies requests.

## Validate locally

From this directory:

```bash
npm ci
npx wrangler types --check worker-configuration.d.ts
npx tsc --noEmit
npx wrangler deploy --dry-run
```

The container Docker build context is the repository root, configured by
`image_build_context: "../.."`.

## Provision infrastructure

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Set account_id and zone_id. Do not commit terraform.tfvars.
terraform init
terraform plan
terraform apply
cd ..
```

Terraform creates the R2 bucket, attaches `r2_public_domain` as its production
custom domain, makes extensionless `/v1/*` objects cache-eligible while
respecting their origin `Cache-Control`, and installs an IP-based WAF rate limit
for `POST /v1/records`.

## Set required secrets

Use Wrangler's interactive secret input; do not put values in source or shell
history:

```bash
npx wrangler secret put EBI_LOG_KEY
npx wrangler secret put EBI_STORAGE_ENDPOINT
npx wrangler secret put EBI_STORAGE_BUCKET
npx wrangler secret put EBI_STORAGE_ACCESS_KEY
npx wrangler secret put EBI_STORAGE_SECRET_KEY
```

Optional witness settings:

```bash
npx wrangler secret put EBI_WITNESS_KEYS
npx wrangler secret put EBI_WITNESS_URLS
npx wrangler secret put EBI_REQUIRED_WITNESSES
```

`EBI_LOG_KEY` is a **private Go-note signer key** (`PRIVATE+KEY+...`), not the
public verifier key. Distribute the corresponding verifier through the trust
policy. If `EBI_REQUIRED_WITNESSES` is nonzero, the server contacts the
comma-separated `EBI_WITNESS_URLS`. It also writes `v1/pending-checkpoint`, so
an external collector may instead place a matching, timestamped, fully
cosigned checkpoint at `v1/witnessed-checkpoint`. The server does not publish
an unwitnessed fallback.

The R2 S3 endpoint and bucket are runtime container secrets because the Go
server uses the S3-compatible API. `worker.ts` forwards only explicitly listed
string bindings.

## Deploy

```bash
npx wrangler deploy
```

Then check:

```bash
curl -fsS https://<worker-host>/healthz
```

## Operational notes

- The Durable Object name is fixed to `singleton` and `max_instances` is `1`.
- `sleepAfter = "5m"`; the next POST wakes the container.
- The container has outbound Internet access so it can re-fetch submitted public
  HTTPS targets. The Go fetcher performs its own strict redirect/DNS/IP checks.
- Container local disk is ephemeral. The persistent log key must therefore be
  supplied by `EBI_LOG_KEY`; public log objects live in R2.
- Public reads (`checkpoint`, tiles, blobs, prefix shards, snapshots) should be
  served directly from the R2 custom domain/CDN, not through the submit Worker.
- `wrangler.jsonc` uses the current generated runtime types in
  `worker-configuration.d.ts`; regenerate them after binding changes.
