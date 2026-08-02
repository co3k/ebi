package schema

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestCanonicalAndID(t *testing.T) {
	b := RecordBody{
		Schema:    SchemaAuditV1,
		Version:   SchemaVersion,
		CreatedAt: "2024-01-01T00:00:00Z",
		Target:    "https://example.com/install.sh",
		Hash:      "a" + repeat("0", 63),
		Size:      12,
		Analyzer:  "test",
		AnalyzerFamily: "static",
		Verdict:   VerdictOK,
	}
	cb, err := CanonicalBytes(b)
	if err != nil {
		t.Fatal(err)
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
	b := RecordBody{
		Schema:    SchemaAuditV1,
		Version:   SchemaVersion,
		CreatedAt: "2024-01-01T00:00:00Z",
		Target:    "https://example.com/install.sh",
		Hash:      "a" + repeat("0", 63),
		Size:      12,
		Analyzer:  "ebi-static",
		AnalyzerFamily: "static",
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
	if body.Target != b.Target {
		t.Fatalf("target mismatch")
	}
	pubHash := sha256.Sum256([]byte(rec.PublicKey))
	if auditorID != hex.EncodeToString(pubHash[:]) {
		t.Fatalf("auditor id mismatch")
	}
}

func TestDangerRequiresEvidence(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	b := RecordBody{
		Schema:    SchemaAuditV1,
		Version:   SchemaVersion,
		CreatedAt: "2024-01-01T00:00:00Z",
		Target:    "https://example.com/x",
		Hash:      "b" + repeat("0", 63),
		Size:      5,
		Analyzer:  "a",
		AnalyzerFamily: "static",
		Verdict:   VerdictDanger,
	}
	_, err = Sign(b, priv)
	if err == nil {
		t.Fatal("expected danger without evidence to fail")
	}
	b.Claims = []Claim{{Category: "priv.sudo", Line: 1, LineHash: "c" + repeat("0", 63)}}
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
		Schema:    SchemaAuditV1,
		Version:   SchemaVersion,
		CreatedAt: "2024-01-01T00:00:00Z",
		Target:    "https://example.com/x",
		Hash:      "d" + repeat("0", 63),
		Size:      5,
		Analyzer:  "a",
		AnalyzerFamily: "static",
		Verdict:   VerdictOK,
		Claims: []Claim{{
			Category: "weird.custom",
			Line:     1,
			LineHash: "e" + repeat("0", 63),
			Note:     "custom analyzer",
		}},
	}
	if err := ValidateBody(&b, b.Size); err != nil {
		t.Fatal(err)
	}
}

func TestLineHash(t *testing.T) {
	want := sha256.Sum256([]byte("echo hello"))
	if LineHash("echo hello\n") != hex.EncodeToString(want[:]) {
		t.Fatal("line hash mismatch")
	}
	if LineHash("echo hello\r\n") != hex.EncodeToString(want[:]) {
		t.Fatal("CR before LF must be part of line (or normalized)")
	}
}

func TestRetract(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	b := RecordBody{
		Schema:         SchemaRetractV1,
		Version:        SchemaVersion,
		CreatedAt:      "2024-01-01T00:00:00Z",
		TargetRecordID: "a" + repeat("0", 63),
		Reason:         "false positive",
	}
	rec, err := Sign(b, priv)
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := Verify(rec)
	if err != nil {
		t.Fatal(err)
	}
	if body.TargetRecordID != b.TargetRecordID {
		t.Fatal("retract target mismatch")
	}
}

func TestTimestampParsing(t *testing.T) {
	b := RecordBody{
		Schema:    SchemaAuditV1,
		Version:   SchemaVersion,
		CreatedAt: NewTimestamp(),
		Target:    "x",
		Hash:      "f" + repeat("0", 63),
		Size:      1,
		Analyzer:  "a",
		AnalyzerFamily: "static",
		Verdict:   VerdictOK,
	}
	if err := ValidateBody(&b, b.Size); err != nil {
		t.Fatal(err)
	}
	b.CreatedAt = "not a timestamp"
	if err := ValidateBody(&b, b.Size); err == nil {
		t.Fatal("expected invalid timestamp to fail")
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
