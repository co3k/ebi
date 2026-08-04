package schema

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func hash64(c byte) string {
	return string(c) + repeat("0", 63)
}

func TestCanonicalAndID(t *testing.T) {
	b := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64('a'),
		Target:    Target{URL: "https://example.com/install.sh", SHA256: hash64('b'), Size: 12},
		Analyzer:  Analyzer{Kind: FamilyStatic},
		Verdict:   VerdictOK,
	}
	cb, err := CanonicalBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if ContainsField(cb, "version") {
		t.Fatal("canonical body must not contain version")
	}
	if ContainsField(cb, "excerpt") {
		t.Fatal("canonical body must not contain excerpt")
	}
	if ContainsField(cb, "id") {
		t.Fatal("canonical body must not contain analyzer id")
	}
	id, err := RecordID(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 64 {
		t.Fatalf("record id length: %d", len(id))
	}
	want := sha256.Sum256(cb)
	if id != hex.EncodeToString(want[:]) {
		t.Fatalf("record id mismatch")
	}
}

func TestSignVerify(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	wantAuditor := sha256.Sum256(pub)
	b := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(wantAuditor[:]),
		Target:    Target{URL: "https://example.com/install.sh", SHA256: hash64('a'), Size: 12},
		Analyzer:  Analyzer{Kind: FamilyStatic},
		Verdict:   VerdictOK,
	}
	rec, err := Sign(b, priv)
	if err != nil {
		t.Fatal(err)
	}
	body, auditorID, err := Verify(rec)
	if err != nil {
		t.Fatal(err)
	}
	if body.Target.URL != b.Target.URL {
		t.Fatalf("target mismatch")
	}
	if auditorID != hex.EncodeToString(wantAuditor[:]) {
		t.Fatalf("auditor id mismatch: got %s want %s", auditorID, hex.EncodeToString(wantAuditor[:]))
	}
}

func TestDangerRequiresEvidence(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	aud := sha256.Sum256(pub)
	b := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(aud[:]),
		Target:    Target{URL: "https://example.com/x", SHA256: hash64('b'), Size: 5},
		Analyzer:  Analyzer{Kind: FamilyStatic},
		Verdict:   VerdictDanger,
	}
	_, err = Sign(b, priv)
	if err == nil {
		t.Fatal("expected danger without evidence to fail")
	}
	b.Claims = []Claim{{Category: "priv.sudo", Line: 1, LineSHA256: hash64('c')}}
	_, err = Sign(b, priv)
	if err != nil {
		t.Fatalf("expected sign with evidence to succeed: %v", err)
	}
}

func TestUnknownCategoryMapped(t *testing.T) {
	if DisplayCategory("net.fetch") != "net.fetch" {
		t.Fatal("known category changed")
	}
	if DisplayCategory("weird.custom") != "misc.other" {
		t.Fatal("unknown category not mapped to misc.other")
	}
	b := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64('a'),
		Target:    Target{URL: "https://example.com/x", SHA256: hash64('d'), Size: 5},
		Analyzer:  Analyzer{Kind: FamilyStatic},
		Verdict:   VerdictOK,
		Claims: []Claim{{
			Category:   "weird.custom",
			Line:       1,
			LineSHA256: hash64('e'),
			Note:       "custom analyzer",
		}},
	}
	if err := ValidateBody(&b, b.Target.Size); err != nil {
		t.Fatal(err)
	}
}

func TestLineHash(t *testing.T) {
	want := sha256.Sum256([]byte("echo hello"))
	if LineHash("echo hello\n") != hex.EncodeToString(want[:]) {
		t.Fatal("line hash mismatch: LF should be removed")
	}
	// CR before LF must remain part of the line.
	want2 := sha256.Sum256([]byte("echo hello\r"))
	if LineHash("echo hello\r\n") != hex.EncodeToString(want2[:]) {
		t.Fatal("CR before LF must be part of line")
	}
}

func TestRetract(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	aud := sha256.Sum256(pub)
	b := RecordBody{
		Type:      SchemaRetractV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(aud[:]),
		RecordID:  hash64('a'),
		Reason:    "false-positive",
	}
	rec, err := Sign(b, priv)
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := Verify(rec)
	if err != nil {
		t.Fatal(err)
	}
	if body.RecordID != b.RecordID {
		t.Fatal("retract target mismatch")
	}
	if body.Reason != b.Reason {
		t.Fatal("retract reason mismatch")
	}
}

func TestRetractInvalidReason(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	aud := sha256.Sum256(pub)
	b := RecordBody{
		Type:      SchemaRetractV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(aud[:]),
		RecordID:  hash64('a'),
		Reason:    "bogus",
	}
	_, err = Sign(b, priv)
	if err == nil {
		t.Fatal("expected invalid retraction reason to fail")
	}
}

func TestTimestampParsing(t *testing.T) {
	b := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: time.Now().UTC().Unix(),
		Auditor:   hash64('a'),
		Target:    Target{URL: "https://example.com/x", SHA256: hash64('f'), Size: 1},
		Analyzer:  Analyzer{Kind: FamilyStatic},
		Verdict:   VerdictOK,
	}
	if err := ValidateBody(&b, b.Target.Size); err != nil {
		t.Fatal(err)
	}
	b.CreatedAt = -1
	if err := ValidateBody(&b, b.Target.Size); err == nil {
		t.Fatal("expected invalid timestamp to fail")
	}
}

func TestAuditorHash(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	want := sha256.Sum256(pub)
	got := AuditorHash(hex.EncodeToString(pub))
	if got != hex.EncodeToString(want[:]) {
		t.Fatal("AuditorHash mismatch")
	}
}

func TestAuditorMismatchAudit(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	b := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64('z'),
		Target:    Target{URL: "https://example.com/x", SHA256: hash64('a'), Size: 1},
		Analyzer:  Analyzer{Kind: FamilyStatic},
		Verdict:   VerdictOK,
	}
	_, err = Sign(b, priv)
	if err == nil {
		t.Fatal("expected auditor mismatch to fail signing")
	}
}

func TestAuditorMismatchRetract(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	b := RecordBody{
		Type:      SchemaRetractV1,
		CreatedAt: 1704067200,
		Auditor:   hash64('z'),
		RecordID:  hash64('a'),
		Reason:    "false-positive",
	}
	_, err = Sign(b, priv)
	if err == nil {
		t.Fatal("expected auditor mismatch on retraction to fail signing")
	}
}

func TestTamperSignature(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	aud := sha256.Sum256(pub)
	b := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(aud[:]),
		Target:    Target{URL: "https://example.com/x", SHA256: hash64('a'), Size: 1},
		Analyzer:  Analyzer{Kind: FamilyStatic},
		Verdict:   VerdictOK,
	}
	rec, err := Sign(b, priv)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(rec.Signature)
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xff
	rec.Signature = hex.EncodeToString(sig)
	_, _, err = Verify(rec)
	if err == nil {
		t.Fatal("expected tampered signature to fail")
	}
}

func TestDecodeRecordStrict(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	aud := sha256.Sum256(pub)
	b := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(aud[:]),
		Target:    Target{URL: "https://example.com/x", SHA256: hash64('a'), Size: 1},
		Analyzer:  Analyzer{Kind: FamilyStatic},
		Verdict:   VerdictOK,
	}
	rec, err := Sign(b, priv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRecordStrict(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got.Body.Type != SchemaAuditV1 {
		t.Fatal("decode type mismatch")
	}
	// Trailing data should be rejected.
	_, err = DecodeRecordStrict(bytes.NewReader(append(data, []byte("\nextra")...)))
	if err == nil {
		t.Fatal("expected trailing data to fail")
	}
	// Unknown field should be rejected.
	_, err = DecodeRecordStrict(bytes.NewReader([]byte(`{"body":{"type":"audit/v1","created_at":1,"auditor":"` + hex.EncodeToString(aud[:]) + `","target":{"url":"x","sha256":"` + hash64('a') + `","size":1},"analyzer":{"kind":"static"},"verdict":"ok"},"public_key":"` + hex.EncodeToString(pub) + `","signature":"` + rec.Signature + `","unknown_field":1}`)))
	if err == nil {
		t.Fatal("expected unknown field to fail")
	}
}

func TestModerationRecord(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	aud := sha256.Sum256(pub)
	b := RecordBody{
		Type:      SchemaModerationV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(aud[:]),
		Target:    Target{URL: "https://example.com/x", SHA256: hash64('a'), Size: 1},
		Reason:    "privacy",
	}
	rec, err := Sign(b, priv)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = Verify(rec)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRetractionSameAuditor(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	aud := sha256.Sum256(pub)
	auditBody := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(aud[:]),
		Target:    Target{URL: "https://example.com/x", SHA256: hash64('a'), Size: 1},
		Analyzer:  Analyzer{Kind: FamilyStatic},
		Verdict:   VerdictOK,
	}
	auditRec, err := Sign(auditBody, priv)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := RecordID(auditRec.Body)

	retractBody := RecordBody{
		Type:      SchemaRetractV1,
		CreatedAt: 1704067201,
		Auditor:   hex.EncodeToString(aud[:]),
		RecordID:  id,
		Reason:    "false-positive",
	}
	retractRec, err := Sign(retractBody, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !RetractionMatchesTarget(retractRec, auditRec) {
		t.Fatal("retraction should match target")
	}
	uppercaseTarget := *auditRec
	uppercaseTarget.PublicKey = strings.ToUpper(uppercaseTarget.PublicKey)
	if !RetractionMatchesTarget(retractRec, &uppercaseTarget) {
		t.Fatal("public key hex case should not change auditor identity")
	}

	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub := otherPriv.Public().(ed25519.PublicKey)
	otherAud := sha256.Sum256(otherPub)
	badRetractBody := RecordBody{
		Type:      SchemaRetractV1,
		CreatedAt: 1704067202,
		Auditor:   hex.EncodeToString(otherAud[:]),
		RecordID:  id,
		Reason:    "false-positive",
	}
	badRetractRec, err := Sign(badRetractBody, otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	if RetractionMatchesTarget(badRetractRec, auditRec) {
		t.Fatal("retraction from different auditor should not match")
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func TestNewTimestamp(t *testing.T) {
	if _, err := time.Parse(time.RFC3339, NewTimestamp()); err != nil {
		t.Fatal(err)
	}
}

func TestAnalyzerLLMFields(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	aud := sha256.Sum256(pub)
	b := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(aud[:]),
		Target:    Target{URL: "https://example.com/x", SHA256: hash64('a'), Size: 1},
		Analyzer: Analyzer{
			Kind:         KindLLM,
			Model:        "model",
			ModelFamily:  "family",
			Quantization: "unknown",
			Backend:      "other",
			PromptSHA256: hash64('a'),
			Runs:         5,
			Agreement:    0.8,
		},
		Verdict: VerdictOK,
	}
	_, err = Sign(b, priv)
	if err != nil {
		t.Fatal(err)
	}

	// Missing required LLM fields.
	b2 := b
	b2.Analyzer.Model = ""
	_, err = Sign(b2, priv)
	if err == nil {
		t.Fatal("expected missing model to fail")
	}

	// LLM fields on non-LLM record.
	b3 := b
	b3.Analyzer.Kind = FamilyStatic
	_, err = Sign(b3, priv)
	if err == nil {
		t.Fatal("expected LLM fields on static record to fail")
	}
}

func TestSecondStageURLPattern(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	aud := sha256.Sum256(pub)
	b := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(aud[:]),
		Target:    Target{URL: "https://example.com/x", SHA256: hash64('a'), Size: 1},
		Analyzer:  Analyzer{Kind: FamilyStatic},
		Verdict:   VerdictOK,
		SecondStage: []SecondStage{
			{URLPattern: "https://example.com/install.sh", Pinned: false},
		},
	}
	_, err = Sign(b, priv)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCategoryMiscOtherRequiresNote(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	aud := sha256.Sum256(pub)
	b := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(aud[:]),
		Target:    Target{URL: "https://example.com/x", SHA256: hash64('a'), Size: 1},
		Analyzer:  Analyzer{Kind: FamilyStatic},
		Verdict:   VerdictOK,
		Claims: []Claim{{
			Category:   "misc.other",
			Line:       1,
			LineSHA256: hash64('b'),
		}},
	}
	_, err = Sign(b, priv)
	if err == nil {
		t.Fatal("expected misc.other without note to fail")
	}
	b.Claims[0].Note = "note"
	_, err = Sign(b, priv)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLineHashCRLF(t *testing.T) {
	want := sha256.Sum256([]byte("echo hello\r"))
	if LineHash("echo hello\r\n") != hex.EncodeToString(want[:]) {
		t.Fatal("CRLF line hash mismatch")
	}
}

func TestExcerptNotInCanonical(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	aud := sha256.Sum256(pub)
	b := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(aud[:]),
		Target:    Target{URL: "https://example.com/x", SHA256: hash64('a'), Size: 1},
		Analyzer:  Analyzer{Kind: FamilyStatic},
		Verdict:   VerdictOK,
		Claims: []Claim{{
			Category:   "priv.sudo",
			Line:       1,
			LineSHA256: hash64('b'),
			Excerpt:    "sudo ls",
		}},
	}
	rec, err := Sign(b, priv)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := CanonicalBytes(rec.Body)
	if strings.Contains(string(cb), "excerpt") {
		t.Fatal("excerpt must not appear in canonical signed body")
	}
}

func TestSafeExcerptEscapesControlsAndInvalidUTF8(t *testing.T) {
	got := SafeExcerpt("echo\x1b[31m\r\t"+string([]byte{0xff})+"\n", 120)
	if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\r') ||
		strings.ContainsRune(got, '\t') {
		t.Fatalf("control characters leaked into excerpt: %q", got)
	}
	if !strings.Contains(got, `\x1b`) || !strings.Contains(got, `\r`) ||
		!strings.Contains(got, `\t`) || !strings.Contains(got, "�") {
		t.Fatalf("excerpt was not safely escaped: %q", got)
	}
}

func TestAnalyzerCompatibilityFields(t *testing.T) {
	b := RecordBody{
		Type:      SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64('a'),
		Target:    Target{URL: "https://example.com/x", SHA256: hash64('a'), Size: 1},
		Analyzer: Analyzer{
			Kind:    FamilyStatic,
			ID:      "local-id",
			Version: "local-version",
		},
		Verdict: VerdictOK,
	}
	cb, err := CanonicalBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if ContainsField(cb, "id") || ContainsField(cb, "version") || ContainsField(cb, "family") {
		t.Fatal("compatibility fields must not be in canonical output")
	}
}
