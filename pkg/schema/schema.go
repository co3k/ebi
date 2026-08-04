// Package schema defines the signed audit/retraction/moderation records used by ebi.
// It handles RFC 8785 JCS canonicalization, Ed25519 signatures, schema
// validation, and deterministic record identifiers.
package schema

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/co3k/ebi/pkg/appmeta"
	"github.com/gowebpki/jcs"
)

const (
	SchemaAuditV1      = "audit/v1"
	SchemaRetractV1    = "retract/v1"
	SchemaModerationV1 = "moderation/v1"

	RecordSigDomain = appmeta.AppName + "-record-v1"
	HashLen         = 64
)

// Verdict values for audit records. Only ok, danger, and info are valid wire
// verdicts for audit/v1. The local display layers may derive caution/flagged.
const (
	VerdictOK     = "ok"
	VerdictInfo   = "info"
	VerdictDanger = "danger"
)

// ValidVerdicts for audit records on the wire.
var ValidVerdicts = []string{VerdictOK, VerdictInfo, VerdictDanger}

var verdictSet = map[string]struct{}{}

func init() {
	for _, v := range ValidVerdicts {
		verdictSet[v] = struct{}{}
	}
}

// ValidRetractionReasons for retract/v1 records.
var ValidRetractionReasons = []string{
	"false-positive",
	"privacy",
	"superseded",
	"other",
}

var retractionReasonSet = map[string]struct{}{}

func init() {
	for _, r := range ValidRetractionReasons {
		retractionReasonSet[r] = struct{}{}
	}
}

// AnalyzerFamily values for non-LLM records.
const (
	FamilyStatic = "static"
	FamilyHuman  = "human"
	KindLLM      = "llm"
	KindStatic   = "static"
	KindHuman    = "human"
)

// Target is the audit target: normalized URL + exact received bytes SHA-256 + size.
type Target struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Analyzer describes the analyzer that produced the audit claims.
// For LLM records, the analyzer includes model, model_family, quantization,
// backend, prompt_sha256, runs, and agreement.
type Analyzer struct {
	Kind         string  `json:"kind"`
	Model        string  `json:"model,omitempty"`
	ModelFamily  string  `json:"model_family,omitempty"`
	Quantization string  `json:"quantization,omitempty"`
	Backend      string  `json:"backend,omitempty"`
	PromptSHA256 string  `json:"prompt_sha256,omitempty"`
	Runs         int     `json:"runs,omitempty"`
	Agreement    float64 `json:"agreement,omitempty"`

	// Compatibility fields are kept for local Go use but are never serialized
	// into the canonical signed record.
	ID      string `json:"-"`
	Version string `json:"-"`
}

// Claim is a single piece of evidence produced by an analyzer.
type Claim struct {
	Category   string `json:"category"`
	Line       int    `json:"line"`
	LineSHA256 string `json:"line_sha256"`
	Note       string `json:"note,omitempty"`

	// Excerpt is for local display only and must never appear in signed records
	// or server uploads.
	Excerpt string `json:"-"`
}

// SecondStage describes an external resource referenced by the analyzed script.
type SecondStage struct {
	URLPattern string `json:"url_pattern"`
	Pinned     bool   `json:"pinned"`

	// Hash is local analysis metadata. The v1 wire schema only contains
	// url_pattern and pinned.
	Hash string `json:"-"`
}

// RecordBody is the signed payload of an audit, retraction, or moderation record.
// The JSON field "type" selects the record kind.
type RecordBody struct {
	// Common fields.
	Type      string `json:"type"`
	CreatedAt int64  `json:"created_at"`
	Auditor   string `json:"auditor"`

	// audit/v1 fields.
	Target      Target        `json:"target,omitempty"`
	Analyzer    Analyzer      `json:"analyzer,omitempty"`
	Verdict     string        `json:"verdict,omitempty"`
	Claims      []Claim       `json:"claims,omitempty"`
	SecondStage []SecondStage `json:"second_stage,omitempty"`
	PrevSHA256  string        `json:"prev_sha256,omitempty"`

	// retract/v1 fields.
	RecordID string `json:"record_id,omitempty"`
	Reason   string `json:"reason,omitempty"`

	// moderation/v1 fields.
	// Moderation also uses the shared Target field for its target and Reason field.
	BlobSHA256      string `json:"blob_sha256,omitempty"`
	TombstoneSHA256 string `json:"tombstone_sha256,omitempty"`
}

// MarshalJSON emits the exact type-specific v1 wire representation. Using a
// custom marshaler prevents zero-valued nested structs (target/analyzer) from
// leaking into retract/v1 or moderation/v1 canonical JSON.
func (b RecordBody) MarshalJSON() ([]byte, error) {
	switch b.Type {
	case SchemaAuditV1:
		return json.Marshal(struct {
			Type        string        `json:"type"`
			Target      Target        `json:"target"`
			Verdict     string        `json:"verdict"`
			Claims      []Claim       `json:"claims,omitempty"`
			Analyzer    Analyzer      `json:"analyzer"`
			SecondStage []SecondStage `json:"second_stage,omitempty"`
			PrevSHA256  string        `json:"prev_sha256,omitempty"`
			CreatedAt   int64         `json:"created_at"`
			Auditor     string        `json:"auditor"`
		}{
			Type: b.Type, Target: b.Target, Verdict: b.Verdict, Claims: b.Claims,
			Analyzer: b.Analyzer, SecondStage: b.SecondStage,
			PrevSHA256: b.PrevSHA256, CreatedAt: b.CreatedAt, Auditor: b.Auditor,
		})
	case SchemaRetractV1:
		return json.Marshal(struct {
			Type      string `json:"type"`
			RecordID  string `json:"record_id"`
			Reason    string `json:"reason"`
			CreatedAt int64  `json:"created_at"`
			Auditor   string `json:"auditor"`
		}{
			Type: b.Type, RecordID: b.RecordID, Reason: b.Reason,
			CreatedAt: b.CreatedAt, Auditor: b.Auditor,
		})
	case SchemaModerationV1:
		return json.Marshal(struct {
			Type            string `json:"type"`
			Target          Target `json:"target,omitempty"`
			BlobSHA256      string `json:"blob_sha256,omitempty"`
			TombstoneSHA256 string `json:"tombstone_sha256,omitempty"`
			Reason          string `json:"reason"`
			CreatedAt       int64  `json:"created_at"`
			Auditor         string `json:"auditor"`
		}{
			Type: b.Type, Target: b.Target, BlobSHA256: b.BlobSHA256,
			TombstoneSHA256: b.TombstoneSHA256, Reason: b.Reason,
			CreatedAt: b.CreatedAt, Auditor: b.Auditor,
		})
	default:
		// Preserve enough information for validation to return the useful
		// unsupported-type error.
		type plain RecordBody
		return json.Marshal(plain(b))
	}
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
// The body must already be valid and must contain the auditor hash.
func Sign(body RecordBody, priv ed25519.PrivateKey) (*Record, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size %d", len(priv))
	}
	pub := priv.Public().(ed25519.PublicKey)
	pubHex := hex.EncodeToString(pub)
	wantAuditor := AuditorHash(pubHex)
	if body.Auditor != wantAuditor {
		return nil, fmt.Errorf("body auditor %s does not match derived auditor %s", body.Auditor, wantAuditor)
	}
	if err := ValidateBody(&body, body.Target.Size); err != nil {
		return nil, fmt.Errorf("validate body: %w", err)
	}
	digest, err := SigningDigest(body)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, digest)
	rec := &Record{
		Body:      body,
		PublicKey: pubHex,
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
	if err := ValidateBody(&rec.Body, rec.Body.Target.Size); err != nil {
		return nil, "", fmt.Errorf("validate body: %w", err)
	}
	wantAuditor := AuditorHash(rec.PublicKey)
	if rec.Body.Auditor != wantAuditor {
		return nil, "", fmt.Errorf("body auditor %s does not match public key auditor %s", rec.Body.Auditor, wantAuditor)
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

// AuditorHash returns SHA-256(public key bytes) as a 64-character hex string.
func AuditorHash(publicKey string) string {
	b, err := hex.DecodeString(publicKey)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// AuditorIDFromKey returns SHA-256(public key bytes) as a 64-character hex string.
func AuditorIDFromKey(publicKey string) (string, error) {
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
	if body.Type != SchemaAuditV1 && body.Type != SchemaRetractV1 && body.Type != SchemaModerationV1 {
		return fmt.Errorf("unsupported type %q", body.Type)
	}
	if body.CreatedAt <= 0 {
		return fmt.Errorf("created_at must be a positive unix timestamp")
	}
	if body.Auditor == "" {
		return fmt.Errorf("auditor is required")
	}
	if !IsHexHash(body.Auditor) {
		return fmt.Errorf("auditor must be 64-character lowercase hex")
	}

	switch body.Type {
	case SchemaAuditV1:
		return validateAudit(body, exactSize)
	case SchemaRetractV1:
		return validateRetract(body)
	case SchemaModerationV1:
		return validateModeration(body)
	}
	return nil
}

func validateAudit(body *RecordBody, exactSize int64) error {
	if body.Target.URL == "" {
		return fmt.Errorf("target.url is required")
	}
	normalizedURL, err := NormalizeURL(body.Target.URL)
	if err != nil {
		return fmt.Errorf("target.url: %w", err)
	}
	if body.Target.URL != normalizedURL {
		return fmt.Errorf("target.url is not normalized (want %q)", normalizedURL)
	}
	if body.Target.SHA256 == "" {
		return fmt.Errorf("target.sha256 is required")
	}
	if !IsHexHash(body.Target.SHA256) {
		return fmt.Errorf("target.sha256 must be 64-character lowercase hex")
	}
	if body.Target.Size < 0 {
		return fmt.Errorf("target.size must be non-negative")
	}
	if exactSize >= 0 && body.Target.Size != exactSize {
		return fmt.Errorf("record size %d does not match expected size %d", body.Target.Size, exactSize)
	}
	if body.Analyzer.Kind == "" {
		return fmt.Errorf("analyzer.kind is required")
	}
	if body.Analyzer.Kind != KindStatic && body.Analyzer.Kind != KindHuman && body.Analyzer.Kind != KindLLM {
		return fmt.Errorf("analyzer.kind must be static, human, or llm")
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

	if body.Analyzer.Kind == KindLLM {
		if body.Analyzer.Model == "" {
			return fmt.Errorf("analyzer.model is required for LLM records")
		}
		if body.Analyzer.ModelFamily == "" {
			return fmt.Errorf("analyzer.model_family is required for LLM records")
		}
		if body.Analyzer.Quantization == "" {
			return fmt.Errorf("analyzer.quantization is required for LLM records")
		}
		switch body.Analyzer.Backend {
		case "foundry-local", "ollama", "other":
		default:
			return fmt.Errorf("analyzer.backend must be foundry-local, ollama, or other")
		}
		if !IsHexHash(body.Analyzer.PromptSHA256) {
			return fmt.Errorf("analyzer.prompt_sha256 must be 64-character lowercase hex")
		}
		if body.Analyzer.Runs <= 0 {
			return fmt.Errorf("analyzer.runs must be positive for LLM records")
		}
		if body.Analyzer.Agreement < 0 || body.Analyzer.Agreement > 1 {
			return fmt.Errorf("analyzer.agreement must be between 0 and 1")
		}
	} else {
		if body.Analyzer.Model != "" || body.Analyzer.ModelFamily != "" || body.Analyzer.Quantization != "" || body.Analyzer.Backend != "" || body.Analyzer.PromptSHA256 != "" || body.Analyzer.Runs != 0 || body.Analyzer.Agreement != 0 {
			return fmt.Errorf("analyzer LLM fields must be empty for non-LLM records")
		}
	}

	if body.Verdict == VerdictDanger && len(body.Claims) == 0 {
		return fmt.Errorf("danger audits require at least one evidence claim")
	}

	seenLines := map[string]struct{}{}
	for i, c := range body.Claims {
		cat := DisplayCategory(c.Category)
		if cat == "misc.other" && strings.TrimSpace(c.Note) == "" {
			return fmt.Errorf("claim %d: misc.other requires a note", i)
		}
		if c.Line <= 0 {
			return fmt.Errorf("claim %d: line must be > 0", i)
		}
		if c.LineSHA256 == "" || !IsHexHash(c.LineSHA256) {
			return fmt.Errorf("claim %d: line_sha256 must be a non-empty 64-character lowercase hex", i)
		}
		key := fmt.Sprintf("%s:%d:%s", c.Category, c.Line, c.LineSHA256)
		if _, ok := seenLines[key]; ok {
			return fmt.Errorf("claim %d: duplicate line hash", i)
		}
		seenLines[key] = struct{}{}
	}
	for i, s := range body.SecondStage {
		if s.URLPattern == "" {
			return fmt.Errorf("second_stage %d: url_pattern is required", i)
		}
		if _, err := NormalizeURL(s.URLPattern); err != nil {
			return fmt.Errorf("second_stage %d: invalid url_pattern: %w", i, err)
		}
	}
	if body.RecordID != "" || body.Reason != "" || body.BlobSHA256 != "" || body.TombstoneSHA256 != "" {
		return fmt.Errorf("audit/v1 contains fields for another record type")
	}
	return nil
}

// NormalizeURL returns the canonical URL representation used in target
// records. It strips credentials and fragments, lowercases scheme/host,
// removes default ports, and sorts query keys and values.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https")
	}
	if u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("must be an absolute URL")
	}
	if u.User != nil {
		return "", fmt.Errorf("credentials are not allowed")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		u.Fragment = ""
		u.RawFragment = ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		u.Host = urlHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	if u.RawQuery != "" {
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return "", fmt.Errorf("query: %w", err)
		}
		for key := range values {
			sort.Strings(values[key])
		}
		u.RawQuery = values.Encode()
	}
	return u.String(), nil
}

func urlHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

func validateRetract(body *RecordBody) error {
	if body.RecordID == "" {
		return fmt.Errorf("record_id is required")
	}
	if !IsHexHash(body.RecordID) {
		return fmt.Errorf("record_id must be 64-character lowercase hex")
	}
	if body.Reason == "" {
		return fmt.Errorf("reason is required")
	}
	if _, ok := retractionReasonSet[body.Reason]; !ok {
		return fmt.Errorf("invalid retraction reason %q", body.Reason)
	}
	if !zeroTarget(body.Target) || !zeroAnalyzer(body.Analyzer) || body.Verdict != "" ||
		len(body.Claims) != 0 || len(body.SecondStage) != 0 || body.PrevSHA256 != "" ||
		body.BlobSHA256 != "" || body.TombstoneSHA256 != "" {
		return fmt.Errorf("retract/v1 contains fields for another record type")
	}
	return nil
}

func validateModeration(body *RecordBody) error {
	if body.BlobSHA256 == "" && body.Target.SHA256 == "" {
		return fmt.Errorf("moderation requires target or blob_sha256")
	}
	if body.BlobSHA256 != "" && !IsHexHash(body.BlobSHA256) {
		return fmt.Errorf("blob_sha256 must be 64-character lowercase hex")
	}
	if body.Target.SHA256 != "" && !IsHexHash(body.Target.SHA256) {
		return fmt.Errorf("target.sha256 must be 64-character lowercase hex")
	}
	if !zeroTarget(body.Target) {
		if body.Target.URL == "" {
			return fmt.Errorf("moderation target.url is required when target is present")
		}
		normalized, err := NormalizeURL(body.Target.URL)
		if err != nil || body.Target.URL != normalized {
			return fmt.Errorf("moderation target.url must be a normalized absolute URL")
		}
		if body.Target.Size < 0 {
			return fmt.Errorf("moderation target.size must be non-negative")
		}
	}
	if body.Reason == "" {
		return fmt.Errorf("reason is required")
	}
	if body.TombstoneSHA256 != "" && !IsHexHash(body.TombstoneSHA256) {
		return fmt.Errorf("tombstone_sha256 must be 64-character lowercase hex")
	}
	if body.Reason == "tombstone" {
		if body.BlobSHA256 == "" || body.TombstoneSHA256 == "" || !zeroTarget(body.Target) {
			return fmt.Errorf("tombstone moderation requires blob_sha256 and tombstone_sha256 only")
		}
	} else if body.BlobSHA256 != "" || body.TombstoneSHA256 != "" {
		return fmt.Errorf("blob_sha256 and tombstone_sha256 are only valid for tombstone moderation")
	}
	if body.Reason == "pending_mismatch" && zeroTarget(body.Target) {
		return fmt.Errorf("pending_mismatch moderation requires target")
	}
	if !zeroAnalyzer(body.Analyzer) || body.Verdict != "" || len(body.Claims) != 0 ||
		len(body.SecondStage) != 0 || body.PrevSHA256 != "" || body.RecordID != "" {
		return fmt.Errorf("moderation/v1 contains fields for another record type")
	}
	return nil
}

func zeroTarget(t Target) bool {
	return t.URL == "" && t.SHA256 == "" && t.Size == 0
}

func zeroAnalyzer(a Analyzer) bool {
	return a.Kind == "" && a.Model == "" && a.ModelFamily == "" &&
		a.Quantization == "" && a.Backend == "" && a.PromptSHA256 == "" &&
		a.Runs == 0 && a.Agreement == 0 && a.ID == "" && a.Version == ""
}

// LineHash computes the SHA-256 of a line with only the line-feed (LF) removed.
// A carriage return (CR) before LF remains part of the evidence.
func LineHash(line string) string {
	line = strings.TrimSuffix(line, "\n")
	h := sha256.Sum256([]byte(line))
	return hex.EncodeToString(h[:])
}

// SafeExcerpt returns a bounded display excerpt for a line.
func SafeExcerpt(line string, max int) string {
	line = strings.TrimSuffix(line, "\n")
	if max <= 0 {
		max = 120
	}
	line = strings.ToValidUTF8(line, "�")
	var out strings.Builder
	truncated := false
	for len(line) > 0 {
		r, size := utf8.DecodeRuneInString(line)
		line = line[size:]
		var piece string
		switch {
		case r == '\t':
			piece = `\t`
		case r == '\r':
			piece = `\r`
		case r == '\n':
			piece = `\n`
		case unicode.IsControl(r):
			if r <= 0xff {
				piece = fmt.Sprintf(`\x%02x`, r)
			} else {
				piece = fmt.Sprintf(`\u%04x`, r)
			}
		default:
			piece = string(r)
		}
		if out.Len()+len(piece) > max {
			truncated = true
			break
		}
		out.WriteString(piece)
	}
	if line != "" {
		truncated = true
	}
	if truncated {
		return out.String() + "…"
	}
	return out.String()
}

// IsSameAuditor checks whether rec is signed by the same auditor as target.
func IsSameAuditor(rec, target *Record) bool {
	if rec == nil || target == nil {
		return false
	}
	recKey, err := hex.DecodeString(rec.PublicKey)
	if err != nil || len(recKey) != ed25519.PublicKeySize {
		return false
	}
	targetKey, err := hex.DecodeString(target.PublicKey)
	if err != nil || len(targetKey) != ed25519.PublicKeySize {
		return false
	}
	return bytes.Equal(recKey, targetKey)
}

// NormalizeTimestamp returns a deterministic RFC3339 timestamp.
func NormalizeTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// NewTimestamp returns the current UTC time formatted as RFC3339.
func NewTimestamp() string {
	return NormalizeTimestamp(time.Now())
}

// UnixNow returns the current time as a Unix timestamp.
func UnixNow() int64 {
	return time.Now().UTC().Unix()
}

// SortRecords returns a stable, deterministic ordering of records by ID.
func SortRecords(records []Record) []Record {
	out := make([]Record, len(records))
	copy(out, records)
	sort.Slice(out, func(i, j int) bool {
		idI, _ := RecordID(out[i].Body)
		idJ, _ := RecordID(out[j].Body)
		return idI < idJ
	})
	return out
}

// RetractionMatchesTarget reports whether a retraction record validly targets
// the provided record. It verifies same-auditor and record ID.
func RetractionMatchesTarget(retract, target *Record) bool {
	if retract == nil || target == nil {
		return false
	}
	if retract.Body.Type != SchemaRetractV1 {
		return false
	}
	if !IsSameAuditor(retract, target) {
		return false
	}
	id, _ := RecordID(target.Body)
	return retract.Body.RecordID == id
}

// DecodeRecordStrict decodes a record envelope with DisallowUnknownFields and
// rejects trailing data.
func DecodeRecordStrict(r io.Reader) (*Record, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var rec Record
	if err := dec.Decode(&rec); err != nil {
		return nil, fmt.Errorf("decode record: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing data after record")
		}
		return nil, fmt.Errorf("trailing data after record: %w", err)
	}
	return &rec, nil
}

// DecodeRecordBodyStrict decodes a record body with DisallowUnknownFields and
// rejects trailing data.
func DecodeRecordBodyStrict(r io.Reader) (*RecordBody, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var body RecordBody
	if err := dec.Decode(&body); err != nil {
		return nil, fmt.Errorf("decode body: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing data after body")
		}
		return nil, fmt.Errorf("trailing data after body: %w", err)
	}
	return &body, nil
}

// CanonicalEnvelope returns the canonical JCS JSON bytes for a record envelope.
func CanonicalEnvelope(rec *Record) ([]byte, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(b)
}

// CanonicalBody returns the canonical JCS JSON bytes for a record body.
func CanonicalBody(body *RecordBody) ([]byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(b)
}

// ContainsField checks whether a canonical JSON byte slice contains a given
// top-level field name. It is used for tests that assert the absence of
// wire-only inventions.
func ContainsField(data []byte, name string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return false
	}
	_, ok := m[name]
	return ok
}
