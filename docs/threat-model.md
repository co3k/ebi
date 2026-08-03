# ebi threat model

## Protected properties

- No partial `curl | sh` execution: the complete input is buffered and hashed.
- A lookup cannot reveal the full hash or source URL to the static mirror.
- The sequencing server cannot forge auditor records.
- A client can detect corrupt records/tiles, checkpoint rollback/equivocation,
  and insufficient witness cosignatures.
- Normal contribution cannot upload the script body.
- Secret findings expose only line number and rule ID, never matched values.

## Trust assumptions

- The local host, user account, selected interpreter, CA roots, and installed
  tools are trusted.
- At least the configured witness quorum is honest and available.
- Users authenticate the initial trust policy and future key rotations.
- The deployment really runs one sequencer; the storage lease is secondary.
- Static/LLM analysis is fallible and does not establish safety.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Truncated network response executes | write to private temp file, EOF, size/hash first | a complete malicious script can still be approved |
| Malicious target URL causes SSRF | server accepts HTTPS only; credentials rejected; every DNS answer and redirect is checked; dial uses validated IP | DNS/CA/network stack and public destinations remain trusted |
| Server fabricates audit | Ed25519 signatures and record IDs | compromised auditor keys can sign lies |
| Server rewrites/splits history | signed checkpoint, persisted consistency, witness quorum, independent monitor | first-use trust and witness governance remain operational concerns |
| Prefix/shard manipulation | reconstruct from verified records with real log indexes | availability attacks can still prevent lookup |
| Sybil positive voting | unseen keys have near-zero weight; per-key/family dedupe | production trust-history policy needs ongoing tuning |
| Unsupported LLM claim | strict structured output, retries, line-hash/category checks, majority aggregation, advisory-only display | models can still omit real threats |
| Prompt injection in script comments | fixed system instruction, explicit untrusted delimiters, prompt hash | no prompt can make an LLM authoritative |
| Secret in mismatch body | client design requires masking; server scans submitted masked body; exact acknowledgement | deletion cannot undo disclosure; rotate secrets immediately |
| Privacy deletion hides history | original leaf hash remains; strict tombstone plus later signed moderation | deleted record body is unavailable to future dataset consumers by design |
| Unsafe second-stage payload | URL/pinning status is shown and scored | v1 does not inspect downloaded binary contents |
| CI/noninteractive accidental run | confirmation only from controlling TTY; no TTY exits 10 unless `--yes` | explicit automation can still choose `--yes` |

## Failure policy

Network absence before authenticated lookup data is accepted produces an
`unknown` community result so local review remains usable. Once authenticated
material is obtained, signature/proof/checkpoint/shard corruption is a hard
verification failure (CLI exit 12), never silently downgraded.
