package score

import (
	"testing"

	"github.com/co3k/ebi/pkg/schema"
)

func mk(body schema.RecordBody) VerifiedRecord {
	id := "id-" + body.Hash
	return VerifiedRecord{ID: id, AuditorID: "aud-" + body.Analyzer, Body: body}
}

func hash(s string) string {
	if len(s) < 64 {
		for len(s) < 64 {
			s += "0"
		}
	}
	return s[:64]
}

func TestScoreUnknown(t *testing.T) {
	r := Score(nil, nil)
	if r.Verdict != VerdictUnknown {
		t.Fatalf("expected unknown, got %s", r.Verdict)
	}
}

func TestScoreTrusted(t *testing.T) {
	body := schema.RecordBody{
		Schema:    schema.SchemaAuditV1,
		Version:   schema.SchemaVersion,
		CreatedAt: "2024-01-01T00:00:00Z",
		Target:    "https://example.com/x",
		Hash:      hash("a"),
		Size:      1,
		Analyzer:  "static-1",
		AnalyzerFamily: "static",
		Verdict:   schema.VerdictOK,
	}
	r := Score([]VerifiedRecord{mk(body)}, nil)
	if r.Verdict != VerdictTrusted {
		t.Fatalf("expected trusted, got %s (total %.3f)", r.Verdict, r.Total)
	}
	if r.Positive < 1.0 {
		t.Fatalf("expected positive >= 1.0, got %.3f", r.Positive)
	}
	if r.Negative != 0 {
		t.Fatalf("expected no negative, got %.3f", r.Negative)
	}
}

func TestScoreFlagged(t *testing.T) {
	body := schema.RecordBody{
		Schema:    schema.SchemaAuditV1,
		Version:   schema.SchemaVersion,
		CreatedAt: "2024-01-01T00:00:00Z",
		Target:    "https://example.com/x",
		Hash:      hash("b"),
		Size:      1,
		Analyzer:  "llm-1",
		ModelFamily: "gpt",
		Model:     "gpt-mini",
		Verdict:   schema.VerdictFlagged,
		Claims: []schema.Claim{
			{Category: "exec.eval", Line: 1, LineHash: hash("c")},
		},
	}
	r := Score([]VerifiedRecord{mk(body)}, nil)
	if r.Verdict != VerdictFlagged {
		t.Fatalf("expected flagged, got %s", r.Verdict)
	}
}

func TestScoreDangerNegative(t *testing.T) {
	body := schema.RecordBody{
		Schema:    schema.SchemaAuditV1,
		Version:   schema.SchemaVersion,
		CreatedAt: "2024-01-01T00:00:00Z",
		Target:    "https://example.com/x",
		Hash:      hash("d"),
		Size:      1,
		Analyzer:  "static-1",
		AnalyzerFamily: "static",
		Verdict:   schema.VerdictDanger,
		Claims: []schema.Claim{
			{Category: "priv.sudo", Line: 1, LineHash: hash("e")},
		},
	}
	r := Score([]VerifiedRecord{mk(body)}, nil)
	if r.Total >= 0 {
		t.Fatalf("expected negative total, got %.3f", r.Total)
	}
	if r.Verdict != VerdictFlagged {
		t.Fatalf("expected flagged for danger, got %s", r.Verdict)
	}
}

func TestScoreDeduplication(t *testing.T) {
	b1 := schema.RecordBody{
		Schema:    schema.SchemaAuditV1,
		Version:   schema.SchemaVersion,
		CreatedAt: "2024-01-01T00:00:00Z",
		Target:    "https://example.com/x",
		Hash:      hash("f1"),
		Size:      1,
		Analyzer:  "a1",
		AnalyzerFamily: "static",
		Verdict:   schema.VerdictOK,
	}
	b2 := schema.RecordBody{
		Schema:    schema.SchemaAuditV1,
		Version:   schema.SchemaVersion,
		CreatedAt: "2024-01-01T00:00:01Z",
		Target:    "https://example.com/x",
		Hash:      hash("f2"),
		Size:      1,
		Analyzer:  "a1",
		AnalyzerFamily: "static",
		Verdict:   schema.VerdictDanger,
		Claims:    []schema.Claim{{Category: "exec.eval", Line: 1, LineHash: hash("f3")}},
	}
	recs := []VerifiedRecord{mk(b1), mk(b2)}
	r := Score(recs, NewRecordsByID(recs))
	if r.SignalsUsed != 1 {
		t.Fatalf("expected 1 signal after dedup, got %d", r.SignalsUsed)
	}
	// b1 is earlier, so it should win.
	if r.Verdict != VerdictTrusted {
		t.Fatalf("expected trusted after dedup, got %s", r.Verdict)
	}
}

func TestScoreDelta(t *testing.T) {
	b1 := schema.RecordBody{
		Schema:    schema.SchemaAuditV1,
		Version:   schema.SchemaVersion,
		CreatedAt: "2024-01-01T00:00:00Z",
		Target:    "https://example.com/x",
		Hash:      hash("g1"),
		Size:      1,
		Analyzer:  "a1",
		AnalyzerFamily: "static",
		Verdict:   schema.VerdictDanger,
		Claims:    []schema.Claim{{Category: "exec.eval", Line: 1, LineHash: hash("g2")}},
	}
	b2 := schema.RecordBody{
		Schema:    schema.SchemaAuditV1,
		Version:   schema.SchemaVersion,
		CreatedAt: "2024-01-01T00:00:01Z",
		Target:    "https://example.com/x",
		Hash:      hash("g3"),
		Size:      1,
		Analyzer:  "a1",
		AnalyzerFamily: "static",
		Verdict:   schema.VerdictOK,
		PrevSHA256: hash("g1"),
	}
	recs := []VerifiedRecord{mk(b2), mk(b1)}
	byID := NewRecordsByID(recs)
	// b2 positive, plus 0.5*b1 negative.
	r := Score(recs, byID)
	if r.Positive <= 0 {
		t.Fatalf("expected positive from ok: %.3f", r.Positive)
	}
	if r.Negative <= 0 {
		t.Fatalf("expected negative from delta inheritance: %.3f", r.Negative)
	}
	if r.DeltaInheritance { // not currently set, placeholder
		// field kept for future reporting
	}
}

func TestScoreFamilyDiversity(t *testing.T) {
	b1 := schema.RecordBody{
		Schema:    schema.SchemaAuditV1,
		Version:   schema.SchemaVersion,
		CreatedAt: "2024-01-01T00:00:00Z",
		Target:    "https://example.com/x",
		Hash:      hash("h1"),
		Size:      1,
		Analyzer:  "a1",
		AnalyzerFamily: "static",
		Verdict:   schema.VerdictOK,
	}
	b2 := schema.RecordBody{
		Schema:    schema.SchemaAuditV1,
		Version:   schema.SchemaVersion,
		CreatedAt: "2024-01-01T00:00:00Z",
		Target:    "https://example.com/x",
		Hash:      hash("h2"),
		Size:      1,
		Analyzer:  "a2",
		ModelFamily: "gpt",
		Model:     "gpt-mini",
		Verdict:   schema.VerdictOK,
	}
	recs := []VerifiedRecord{mk(b1), mk(b2)}
	r := Score(recs, nil)
	if r.FamiliesUsed != 2 {
		t.Fatalf("expected 2 families, got %d", r.FamiliesUsed)
	}
	want := TrustDefault * (PositiveMultiplierBase + FamilyDiversityBonusPerExtra)
	if r.Positive < want-1e-9 || r.Positive > want+1e-9 {
		t.Fatalf("expected positive %.3f, got %.3f", want, r.Positive)
	}
}

func TestScoreCaution(t *testing.T) {
	body := schema.RecordBody{
		Schema:    schema.SchemaAuditV1,
		Version:   schema.SchemaVersion,
		CreatedAt: "2024-01-01T00:00:00Z",
		Target:    "https://example.com/x",
		Hash:      hash("i"),
		Size:      1,
		Analyzer:  "a1",
		AnalyzerFamily: "static",
		Verdict:   schema.VerdictInfo,
	}
	r := Score([]VerifiedRecord{mk(body)}, nil)
	if r.Verdict != VerdictCaution {
		t.Fatalf("expected caution, got %s", r.Verdict)
	}
}
