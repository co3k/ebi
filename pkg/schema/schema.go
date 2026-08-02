// Package schema defines the signed audit/retraction records used by ebi.
// It handles RFC 8785 JCS canonicalization, Ed25519 signatures, schema
// validation, and deterministic record identifiers.
package schema

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
)

const (
	SchemaVersion    = "1.0"
	SchemaAuditV1    = "audit/v1"
	SchemaRetractV1  = "retract/v1"
	SchemaTombstoneV1 = "tombstone/v1"

	RecordSigDomain = "ebi-record-v1"
	HashLen         = 64
)

//go:generate go run ./gen_categories.go
// (categories are defined below manually)

// KnownCategories lists the claim categories that have dedicated semantics.
// Unknown categories are accepted and displayed as misc.other.
var KnownCategories = []string{
	"net.fetch",
	"exec.remote_pipe",
	"exec.eval",
	"obfuscation.base64",
	"obfuscation.misc",
	"fs.delete_broad",
	"priv.sudo",
	"priv.persist",
	"env.exfil",
	"pkg.install",
	"download.unpinned",
	"misc.other",
}

var knownCategorySet = map[string]struct{}{}

func init() {
	for _, c := range KnownCategories {
		knownCategorySet[c] = struct{}{}
	}
}

// DisplayCategory returns the canonical category for display. Unknown values
// are mapped to misc.other.
func DisplayCategory(c string) string {
	if _, ok := knownCategorySet[c]; ok {
		return c
	}
	return "misc.other"
}

// IsKnownCategory reports whether c is one of the known categories.
func IsKnownCategory(c string) bool {
	_, ok := knownCategorySet[c]
	return ok
}

// Verdict values for audit records.
const (
	VerdictOK      = "ok"
	VerdictInfo    = "info"
	VerdictCaution = "caution"
	VerdictDanger  = "danger"
	VerdictFlagged = "flagged"
)

// ValidVerdicts for audit records.
var ValidVerdicts = []string{VerdictOK, VerdictInfo, VerdictCaution, VerdictDanger, VerdictFlagged}

var verdictSet = map[string]struct{}{}

func init() {
	for _, v := range ValidVerdicts {
		verdictSet[v] = struct{}{}
	}
}

// AnalyzerFamily values for non-LLM records.
const (
	FamilyStatic = "static"
	FamilyHuman  = "human"
)

// Claim is a single piece of evidence produced by an analyzer.
type Claim struct {
	Category     string `json:"category"`
	Line         int    `json:"line"`
	LineHash     string `json:"line_hash"`
	Excerpt      string `json:"excerpt,omitempty"`
	Note         string `json:"note,omitempty"`
	Model        string `json:"model,omitempty"`
	ModelFamily  string `json:"model_family,omitempty"`
	Analyzer     string `json:"analyzer,omitempty"`
	AnalyzerKind string `json:"analyzer_kind,omitempty"`
}

// SecondStage describes an external resource referenced by the analyzed script.
type SecondStage struct {
	URL      string `json:"url,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Resource string `json:"resource,omitempty"` // "url" or "domain"
	Pinned   bool   `json:"pinned"`
	Hash     string `json:"hash,omitempty"`
}

// RecordBody is the signed payload of an audit or retraction record.
// Only fields relevant to the schema are serialized; the exact layout depends
// on the Schema value.
type RecordBody struct {
	// Common fields.
	Schema    string `json:"schema"`
	Version   string `json:"version"`
	CreatedAt string `json:"created_at"`

	// audit/v1 fields.
	Target         string        `json:"target,omitempty"`
	Hash           string        `json:"hash,omitempty"`
	Size           int64         `json:"size,omitempty"`
	Analyzer       string        `json:"analyzer,omitempty"`
	AnalyzerFamily string        `json:"analyzer_family,omitempty"`
	Model          string        `json:"model,omitempty"`
	ModelFamily    string        `json:"model_family,omitempty"`
	Kind           string        `json:"kind,omitempty"`
	Verdict        string        `json:"verdict,omitempty"`
	Claims         []Claim       `json:"claims,omitempty"`
	SecondStage    []SecondStage `json:"second_stage,omitempty"`
	PrevSHA256     string        `json:"prev_sha256,omitempty"`

	// retract/v1 fields.
	TargetRecordID string `json:"target_record_id,omitempty"`
	Reason         string `json:"reason,omitempty"`

	// tombstone/v1 fields.
	ModeratorID string `json:"moderator_id,omitempty"`
	Message     string `json:"message,omitempty"`
}

// Record is a signed record envelope.
type Record struct {
	Body      RecordBody `json:"body"`
	PublicKey string     `json:"public_key"`
	Signature string     `json:"signature"`
}

var hexRe = regexp.MustCompile(`^[0-9a-f]+$`)

// IsHexHash reports whether s is a 64-character lowercase hex SHA-256.
func IsHexHash(s string) bool {
	return len(s) == HashLen && hexRe.MatchString(s)
}

// CanonicalBytes returns the RFC 8785 JCS canonical JSON for body.
func CanonicalBytes(body RecordBody) ([]byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}
	cb, err := jcs.Transform(b)
	if err != nil {
		return nil, fmt.Errorf("jcs canonicalize: %w", err)
	}
	return cb, nil
}

// RecordID returns sha256(JCS(body)) as a 64-character hex string.
func RecordID(body RecordBody) (string, error) {
	cb, err := CanonicalBytes(body)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(cb)
	return hex.EncodeToString(h[:]), nil
}

// SigningDigest returns sha256("ebi-record-v1\n" + JCS(body)) as raw bytes.
func SigningDigest(body RecordBody) ([]byte, error) {
	cb, err := CanonicalBytes(body)
	if err != nil {
		return nil, err
	}
	msg := []byte(RecordSigDomain + "\n")
	msg = append(msg, cb...)
	h := sha256.Sum256(msg)
	return h[:], nil
}

// Sign signs body with the provided Ed25519 private key and returns a Record.
func Sign(body RecordBody, priv ed25519.PrivateKey) (*Record, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size %d", len(priv))
	}
	if err := ValidateBody(&body, body.Size); err != nil {
		return nil, fmt.Errorf("validate body: %w", err)
	}
	digest, err := SigningDigest(body)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, digest)
	rec := &Record{
		Body:      body,
		PublicKey: hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
		Signature: hex.EncodeToString(sig),
	}
	return rec, nil
}

// Verify checks the signature, canonicalization, and schema of rec.
// It returns the validated body and the auditor ID (SHA-256 of public key).
func Verify(rec *Record) (*RecordBody, string, error) {
	if rec == nil {
		return nil, "", fmt.Errorf("nil record")
	}
	pubBytes, err := hex.DecodeString(rec.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("decode public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("invalid public key length %d", len(pubBytes))
	}
	sigBytes, err := hex.DecodeString(rec.Signature)
	if err != nil {
		return nil, "", fmt.Errorf("decode signature: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return nil, "", fmt.Errorf("invalid signature length %d", len(sigBytes))
	}
	if err := ValidateBody(&rec.Body, rec.Body.Size); err != nil {
		return nil, "", fmt.Errorf("validate body: %w", err)
	}
	digest, err := SigningDigest(rec.Body)
	if err != nil {
		return nil, "", err
	}
	if !ed25519.Verify(pubBytes, digest, sigBytes) {
		return nil, "", fmt.Errorf("signature verification failed")
	}
	pubHash := sha256.Sum256(pubBytes)
	return &rec.Body, hex.EncodeToString(pubHash[:]), nil
}

// AuditorID returns SHA-256(public key) as a 64-character hex string.
func AuditorID(publicKey string) (string, error) {
	b, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", fmt.Errorf("decode public key: %w", err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// ValidateBody performs schema validation on body.
// exactSize is the actual byte size of the target; pass a negative value to
// skip the size/hash checks for tests that validate a record in isolation.
func ValidateBody(body *RecordBody, exactSize int64) error {
	if body == nil {
		return fmt.Errorf("body is nil")
	}
	if body.Schema != SchemaAuditV1 && body.Schema != SchemaRetractV1 && body.Schema != SchemaTombstoneV1 {
		return fmt.Errorf("unsupported schema %q", body.Schema)
	}
	if body.Version != SchemaVersion {
		return fmt.Errorf("unsupported version %q", body.Version)
	}
	if body.CreatedAt == "" {
		return fmt.Errorf("created_at is required")
	}
	if _, err := time.Parse(time.RFC3339, body.CreatedAt); err != nil {
		return fmt.Errorf("created_at must be RFC3339: %w", err)
	}

	switch body.Schema {
	case SchemaAuditV1:
		return validateAudit(body, exactSize)
	case SchemaRetractV1:
		return validateRetract(body)
	case SchemaTombstoneV1:
		return validateTombstone(body)
	}
	return nil
}

func validateAudit(body *RecordBody, exactSize int64) error {
	if body.Target == "" {
		return fmt.Errorf("target is required for audit")
	}
	if body.Hash == "" {
		return fmt.Errorf("hash is required for audit")
	}
	if !IsHexHash(body.Hash) {
		return fmt.Errorf("hash must be 64-character lowercase hex")
	}
	if body.Size < 0 {
		return fmt.Errorf("size must be non-negative")
	}
	if exactSize >= 0 && body.Size != exactSize {
		return fmt.Errorf("record size %d does not match expected size %d", body.Size, exactSize)
	}
	if body.Analyzer == "" {
		return fmt.Errorf("analyzer is required")
	}
	if body.AnalyzerFamily == "" {
		return fmt.Errorf("analyzer_family is required")
	}
	if body.Verdict == "" {
		return fmt.Errorf("verdict is required")
	}
	if _, ok := verdictSet[body.Verdict]; !ok {
		return fmt.Errorf("invalid verdict %q", body.Verdict)
	}
	if body.PrevSHA256 != "" && !IsHexHash(body.PrevSHA256) {
		return fmt.Errorf("prev_sha256 must be 64-character lowercase hex")
	}

	if body.Kind == "llm" || body.Model != "" || body.ModelFamily != "" {
		if body.Model == "" {
			return fmt.Errorf("model is required for LLM records")
		}
		if body.ModelFamily == "" {
			return fmt.Errorf("model_family is required for LLM records")
		}
	}

	// Danger verdicts must have at least one evidence claim.
	if body.Verdict == VerdictDanger && len(body.Claims) == 0 {
		return fmt.Errorf("danger audits require at least one evidence claim")
	}
	if body.Verdict == VerdictFlagged && len(body.Claims) == 0 {
		return fmt.Errorf("flagged audits require at least one evidence claim")
	}

	seenLines := map[string]struct{}{}
	for i, c := range body.Claims {
		cat := DisplayCategory(c.Category)
		if c.Category != "" && cat == "misc.other" && !IsKnownCategory(c.Category) {
			// Accept but map to misc.other; note required.
		}
		if cat == "misc.other" && strings.TrimSpace(c.Note) == "" {
			return fmt.Errorf("claim %d: misc.other requires a note", i)
		}
		if c.Line <= 0 {
			return fmt.Errorf("claim %d: line must be > 0", i)
		}
		if c.LineHash != "" && !IsHexHash(c.LineHash) {
			return fmt.Errorf("claim %d: line_hash must be 64-character lowercase hex", i)
		}
		key := fmt.Sprintf("%d:%s", c.Line, c.LineHash)
		if _, ok := seenLines[key]; ok {
			return fmt.Errorf("claim %d: duplicate line hash", i)
		}
		seenLines[key] = struct{}{}
	}
	for i, s := range body.SecondStage {
		if s.URL == "" && s.Domain == "" {
			return fmt.Errorf("second_stage %d: url or domain required", i)
		}
		if s.Resource != "" && s.Resource != "url" && s.Resource != "domain" {
			return fmt.Errorf("second_stage %d: invalid resource %q", i, s.Resource)
		}
		if s.Hash != "" && !IsHexHash(s.Hash) {
			return fmt.Errorf("second_stage %d: hash must be 64-character lowercase hex", i)
		}
	}
	return nil
}

func validateRetract(body *RecordBody) error {
	if body.TargetRecordID == "" {
		return fmt.Errorf("target_record_id is required")
	}
	if !IsHexHash(body.TargetRecordID) {
		return fmt.Errorf("target_record_id must be 64-character lowercase hex")
	}
	if body.Reason == "" {
		return fmt.Errorf("reason is required")
	}
	return nil
}

func validateTombstone(body *RecordBody) error {
	if body.TargetRecordID == "" {
		return fmt.Errorf("target_record_id is required")
	}
	if !IsHexHash(body.TargetRecordID) {
		return fmt.Errorf("target_record_id must be 64-character lowercase hex")
	}
	if body.ModeratorID == "" {
		return fmt.Errorf("moderator_id is required")
	}
	if !IsHexHash(body.ModeratorID) {
		return fmt.Errorf("moderator_id must be 64-character lowercase hex")
	}
	return nil
}

// LineHash computes the SHA-256 of a line (with newline removed).
func LineHash(line string) string {
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	h := sha256.Sum256([]byte(line))
	return hex.EncodeToString(h[:])
}

// SafeExcerpt returns a bounded display excerpt for a line.
func SafeExcerpt(line string, max int) string {
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if max <= 0 {
		max = 120
	}
	if len(line) <= max {
		return line
	}
	return line[:max] + "…"
}

// IsSameAuditor checks whether rec is signed by the same auditor as target.
func IsSameAuditor(rec, target *Record) bool {
	if rec == nil || target == nil {
		return false
	}
	return rec.PublicKey == target.PublicKey
}

// NormalizeTimestamp returns a deterministic RFC3339 timestamp.
func NormalizeTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// NewTimestamp returns the current UTC time formatted as RFC3339.
func NewTimestamp() string {
	return NormalizeTimestamp(time.Now())
}
