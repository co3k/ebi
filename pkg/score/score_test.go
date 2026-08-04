package score

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/co3k/ebi/pkg/schema"
)

func hash64(s string) string {
	out := s
	for len(out) < 64 {
		out += "0"
	}
	return out[:64]
}

func mk(body schema.RecordBody) VerifiedRecord {
	id := "id-" + body.Target.SHA256
	return VerifiedRecord{ID: id, AuditorID: "aud-" + body.Analyzer.Kind, Body: body}
}

func TestScoreUnknown(t *testing.T) {
	r := Compute(Input{TargetHash: hash64("x")})
	if r.Verdict != VerdictUnknown {
		t.Fatalf("expected unknown, got %s", r.Verdict)
	}
}

func TestScoreTrusted(t *testing.T) {
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("a"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("a"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictOK,
	}
	tr := mk(body)
	r := Compute(Input{
		TargetHash: tr.Body.Target.SHA256,
		Records:    []VerifiedRecord{tr},
		Trust:      map[string]float64{tr.AuditorID: 1.0},
	})
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
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("a"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("b"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindLLM, ModelFamily: "gpt", Model: "gpt-mini"},
		Verdict:   schema.VerdictDanger,
		Claims: []schema.Claim{
			{Category: "exec.eval", Line: 1, LineSHA256: hash64("c")},
		},
	}
	tr := mk(body)
	r := Compute(Input{
		TargetHash: tr.Body.Target.SHA256,
		Records:    []VerifiedRecord{tr},
		Trust:      map[string]float64{tr.AuditorID: 1.0},
	})
	if r.Verdict != VerdictFlagged {
		t.Fatalf("expected flagged, got %s", r.Verdict)
	}
}

func TestScoreDangerNegative(t *testing.T) {
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("a"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("d"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictDanger,
		Claims: []schema.Claim{
			{Category: "priv.sudo", Line: 1, LineSHA256: hash64("e")},
		},
	}
	tr := mk(body)
	r := Compute(Input{
		TargetHash: tr.Body.Target.SHA256,
		Records:    []VerifiedRecord{tr},
		Trust:      map[string]float64{tr.AuditorID: 1.0},
	})
	if r.Total >= 0 {
		t.Fatalf("expected negative total, got %.3f", r.Total)
	}
	if r.Verdict != VerdictFlagged {
		t.Fatalf("expected flagged for danger, got %s", r.Verdict)
	}
}

func TestScoreDeduplication(t *testing.T) {
	b1 := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("a"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("f"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictOK,
	}
	b2 := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067201,
		Auditor:   hash64("a"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("f"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictDanger,
		Claims:    []schema.Claim{{Category: "exec.eval", Line: 1, LineSHA256: hash64("ab")}},
	}
	recs := []VerifiedRecord{mk(b1), mk(b2)}
	r := Compute(Input{
		TargetHash: hash64("f"),
		Records:    recs,
		Trust:      map[string]float64{recs[0].AuditorID: 1.0},
	})
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
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("a"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("ac"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictDanger,
		Claims:    []schema.Claim{{Category: "exec.eval", Line: 1, LineSHA256: hash64("ad")}},
	}
	b2 := schema.RecordBody{
		Type:       schema.SchemaAuditV1,
		CreatedAt:  1704067201,
		Auditor:    hash64("a"),
		Target:     schema.Target{URL: "https://example.com/x", SHA256: hash64("ae"), Size: 1},
		Analyzer:   schema.Analyzer{Kind: schema.KindStatic},
		Verdict:    schema.VerdictOK,
		PrevSHA256: hash64("ac"),
	}
	cur := mk(b2)
	prev := mk(b1)
	r := Compute(Input{
		TargetHash:   cur.Body.Target.SHA256,
		Records:      []VerifiedRecord{cur},
		Trust:        map[string]float64{cur.AuditorID: 1.0},
		PriorRecords: []VerifiedRecord{prev},
	})
	if r.Positive <= 0 {
		t.Fatalf("expected positive from ok: %.3f", r.Positive)
	}
	if r.Negative <= 0 {
		t.Fatalf("expected negative from delta inheritance: %.3f", r.Negative)
	}
	if !r.DeltaInheritance {
		t.Fatal("expected delta inheritance flag")
	}
}

func TestScoreFamilyDiversity(t *testing.T) {
	b1 := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("a"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("ae"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictOK,
	}
	b2 := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("b"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("ae"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindLLM, ModelFamily: "gpt", Model: "gpt-mini"},
		Verdict:   schema.VerdictOK,
	}
	recs := []VerifiedRecord{mk(b1), mk(b2)}
	r := Compute(Input{
		TargetHash: hash64("ae"),
		Records:    recs,
		Trust:      map[string]float64{recs[0].AuditorID: 1.0, recs[1].AuditorID: 1.0},
	})
	if r.FamiliesUsed != 2 {
		t.Fatalf("expected 2 families, got %d", r.FamiliesUsed)
	}
	want := (1.0 + 1.0) * (PositiveMultiplierBase + FamilyDiversityBonusPerExtra)
	if r.Positive < want-1e-9 || r.Positive > want+1e-9 {
		t.Fatalf("expected positive %.3f, got %.3f", want, r.Positive)
	}
}

func TestScoreDistinctKeyCount(t *testing.T) {
	target := hash64("key-count")
	static := VerifiedRecord{
		ID:        "static",
		AuditorID: "same-auditor",
		Body: schema.RecordBody{
			Type:      schema.SchemaAuditV1,
			CreatedAt: 1,
			Target:    schema.Target{SHA256: target},
			Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
			Verdict:   schema.VerdictOK,
		},
	}
	llm := VerifiedRecord{
		ID:        "llm",
		AuditorID: "same-auditor",
		Body: schema.RecordBody{
			Type:      schema.SchemaAuditV1,
			CreatedAt: 2,
			Target:    schema.Target{SHA256: target},
			Analyzer:  schema.Analyzer{Kind: schema.KindLLM, ModelFamily: "qwen"},
			Verdict:   schema.VerdictOK,
		},
	}
	report := Compute(Input{
		TargetHash: target,
		Records:    []VerifiedRecord{static, llm},
		Trust:      map[string]float64{"same-auditor": 1},
	})
	if report.SignalsUsed != 2 || report.FamiliesUsed != 2 || report.KeysUsed != 1 {
		t.Fatalf("unexpected counts: signals=%d families=%d keys=%d", report.SignalsUsed, report.FamiliesUsed, report.KeysUsed)
	}
}

func TestScoreDeltaSharedPredecessorInheritedOnce(t *testing.T) {
	oldHash := hash64("old-shared")
	newHash := hash64("new-shared")
	prior := VerifiedRecord{
		ID:        "prior",
		AuditorID: "prior-auditor",
		Body: schema.RecordBody{
			Type:      schema.SchemaAuditV1,
			CreatedAt: 1,
			Target:    schema.Target{SHA256: oldHash},
			Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
			Verdict:   schema.VerdictOK,
		},
	}
	currentA := VerifiedRecord{
		ID:        "current-a",
		AuditorID: "auditor-a",
		Body: schema.RecordBody{
			Type:       schema.SchemaAuditV1,
			CreatedAt:  2,
			Target:     schema.Target{SHA256: newHash},
			Analyzer:   schema.Analyzer{Kind: schema.KindStatic},
			Verdict:    schema.VerdictOK,
			PrevSHA256: oldHash,
		},
	}
	currentB := VerifiedRecord{
		ID:        "current-b",
		AuditorID: "auditor-b",
		Body: schema.RecordBody{
			Type:       schema.SchemaAuditV1,
			CreatedAt:  3,
			Target:     schema.Target{SHA256: newHash},
			Analyzer:   schema.Analyzer{Kind: schema.KindHuman},
			Verdict:    schema.VerdictOK,
			PrevSHA256: oldHash,
		},
	}
	report := Compute(Input{
		TargetHash:   newHash,
		Records:      []VerifiedRecord{currentA, currentB},
		PriorRecords: []VerifiedRecord{prior},
		Trust: map[string]float64{
			"prior-auditor": 1,
			"auditor-a":     1,
			"auditor-b":     1,
		},
	})
	// Direct score: two families => 2 * 1.2 = 2.4.
	// One predecessor inheritance: 1 * 0.5 = 0.5.
	const want = 2.9
	if report.Positive < want-1e-9 || report.Positive > want+1e-9 {
		t.Fatalf("shared predecessor was not inherited exactly once: got %.3f, want %.3f", report.Positive, want)
	}
}

func TestScoreDeltaCycleTerminates(t *testing.T) {
	hashA := hash64("cycle-a")
	hashB := hash64("cycle-b")
	a := VerifiedRecord{
		ID:        "a",
		AuditorID: "aud-a",
		Body: schema.RecordBody{
			Type:       schema.SchemaAuditV1,
			CreatedAt:  1,
			Target:     schema.Target{SHA256: hashA},
			Analyzer:   schema.Analyzer{Kind: schema.KindStatic},
			Verdict:    schema.VerdictOK,
			PrevSHA256: hashB,
		},
	}
	b := VerifiedRecord{
		ID:        "b",
		AuditorID: "aud-b",
		Body: schema.RecordBody{
			Type:       schema.SchemaAuditV1,
			CreatedAt:  2,
			Target:     schema.Target{SHA256: hashB},
			Analyzer:   schema.Analyzer{Kind: schema.KindStatic},
			Verdict:    schema.VerdictOK,
			PrevSHA256: hashA,
		},
	}
	report := Compute(Input{
		TargetHash:   hashA,
		Records:      []VerifiedRecord{a},
		PriorRecords: []VerifiedRecord{b},
		Trust:        map[string]float64{"aud-a": 1, "aud-b": 1},
	})
	if report.Positive < 1.49 || report.Positive > 1.51 {
		t.Fatalf("cycle should inherit B once and stop, got %.3f", report.Positive)
	}
}

func TestScoreDeltaIsDeterministicAcrossInputOrder(t *testing.T) {
	oldHash := hash64("deterministic-old")
	newHash := hash64("deterministic-new")
	current := VerifiedRecord{
		ID:        "current",
		AuditorID: "current-auditor",
		Body: schema.RecordBody{
			Type:       schema.SchemaAuditV1,
			Target:     schema.Target{SHA256: newHash},
			Analyzer:   schema.Analyzer{Kind: schema.KindStatic},
			Verdict:    schema.VerdictOK,
			PrevSHA256: oldHash,
		},
	}
	prior := []VerifiedRecord{
		{
			ID:        "large",
			AuditorID: "large-auditor",
			Body: schema.RecordBody{
				Type:     schema.SchemaAuditV1,
				Target:   schema.Target{SHA256: oldHash},
				Analyzer: schema.Analyzer{Kind: schema.KindStatic},
				Verdict:  schema.VerdictOK,
			},
		},
		{
			ID:        "small-a",
			AuditorID: "small-auditor",
			Body: schema.RecordBody{
				Type:     schema.SchemaAuditV1,
				Target:   schema.Target{SHA256: oldHash},
				Analyzer: schema.Analyzer{Kind: schema.KindHuman},
				Verdict:  schema.VerdictOK,
			},
		},
		{
			ID:        "small-b",
			AuditorID: "small-b-auditor",
			Body: schema.RecordBody{
				Type:     schema.SchemaAuditV1,
				Target:   schema.Target{SHA256: oldHash},
				Analyzer: schema.Analyzer{Kind: schema.KindLLM, ModelFamily: "qwen"},
				Verdict:  schema.VerdictOK,
			},
		},
	}
	trust := map[string]float64{
		"current-auditor": 1,
		"large-auditor":   1e16,
		"small-auditor":   1,
		"small-b-auditor": 1,
	}
	var want float64
	for i := 0; i < 100; i++ {
		shuffled := append([]VerifiedRecord(nil), prior...)
		rand.New(rand.NewSource(int64(i))).Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		got := Compute(Input{
			TargetHash:   newHash,
			Records:      []VerifiedRecord{current},
			PriorRecords: shuffled,
			Trust:        trust,
		}).Positive
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("delta score changed with input order: got %.17g, want %.17g", got, want)
		}
	}
}

func TestScoreCaution(t *testing.T) {
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("a"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("ba"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictInfo,
	}
	tr := mk(body)
	r := Compute(Input{
		TargetHash: tr.Body.Target.SHA256,
		Records:    []VerifiedRecord{tr},
	})
	if r.Verdict != VerdictCaution {
		t.Fatalf("expected caution, got %s", r.Verdict)
	}
}

func TestScoreRetraction(t *testing.T) {
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("a"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("x"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictDanger,
		Claims:    []schema.Claim{{Category: "priv.sudo", Line: 1, LineSHA256: hash64("c")}},
	}
	tr := mk(body)
	retr := VerifiedRecord{
		ID:        "retr",
		AuditorID: tr.AuditorID,
		Body: schema.RecordBody{
			Type:      schema.SchemaRetractV1,
			CreatedAt: 1704067201,
			Auditor:   body.Auditor,
			RecordID:  tr.ID,
			Reason:    "false-positive",
		},
	}
	r := Compute(Input{
		TargetHash:  tr.Body.Target.SHA256,
		Records:     []VerifiedRecord{tr},
		Retractions: []VerifiedRecord{retr},
		Trust:       map[string]float64{tr.AuditorID: 1.0},
	})
	if r.Verdict != VerdictUnknown {
		t.Fatalf("expected unknown after retraction, got %s", r.Verdict)
	}
}

func TestScoreDefaultTrustNearZero(t *testing.T) {
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("a"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("z"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictOK,
	}
	tr := mk(body)
	r := Compute(Input{
		TargetHash: tr.Body.Target.SHA256,
		Records:    []VerifiedRecord{tr},
	})
	if r.Positive >= TrustedPositiveThreshold {
		t.Fatalf("expected near-zero trust to stay below threshold, got %.3f", r.Positive)
	}
	if r.Verdict != VerdictCaution {
		t.Fatalf("expected caution with near-zero trust, got %s", r.Verdict)
	}
}

func TestScoreRealAuditor(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	aud := sha256.Sum256(pub)
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(aud[:]),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("bb"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictOK,
	}
	rec, err := schema.Sign(body, priv)
	if err != nil {
		t.Fatal(err)
	}
	vbody, vAuditor, err := schema.Verify(rec)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := schema.RecordID(*vbody)
	vr := VerifiedRecord{ID: id, AuditorID: vAuditor, Body: *vbody, PublicKey: rec.PublicKey, Signature: rec.Signature}
	r := Compute(Input{
		TargetHash: vr.Body.Target.SHA256,
		Records:    []VerifiedRecord{vr},
		Trust:      map[string]float64{vr.AuditorID: 1.0},
	})
	if r.Verdict != VerdictTrusted {
		t.Fatalf("expected trusted, got %s", r.Verdict)
	}
}

func TestScoreOnlyTargetHash(t *testing.T) {
	b1 := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("a"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("t1"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictOK,
	}
	b2 := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("b"),
		Target:    schema.Target{URL: "https://example.com/y", SHA256: hash64("t2"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictOK,
	}
	recs := []VerifiedRecord{mk(b1), mk(b2)}
	r := Compute(Input{
		TargetHash: hash64("t1"),
		Records:    recs,
		Trust:      map[string]float64{recs[0].AuditorID: 1.0, recs[1].AuditorID: 1.0},
	})
	if r.SignalsUsed != 1 {
		t.Fatalf("expected only one signal for target t1, got %d", r.SignalsUsed)
	}
}

func TestScoreRetractionDifferentAuditor(t *testing.T) {
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("a"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("x"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictDanger,
		Claims:    []schema.Claim{{Category: "priv.sudo", Line: 1, LineSHA256: hash64("c")}},
	}
	tr := mk(body)
	retr := VerifiedRecord{
		ID:        "retr",
		AuditorID: "aud-other",
		Body: schema.RecordBody{
			Type:      schema.SchemaRetractV1,
			CreatedAt: 1704067201,
			Auditor:   hash64("b"),
			RecordID:  tr.ID,
			Reason:    "false-positive",
		},
	}
	r := Compute(Input{
		TargetHash:  tr.Body.Target.SHA256,
		Records:     []VerifiedRecord{tr},
		Retractions: []VerifiedRecord{retr},
		Trust:       map[string]float64{tr.AuditorID: 1.0},
	})
	if r.Verdict != VerdictFlagged {
		t.Fatalf("expected retraction from other auditor not to apply, got %s", r.Verdict)
	}
}

func TestScoreCompatibility(t *testing.T) {
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hash64("a"),
		Target:    schema.Target{URL: "https://example.com/x", SHA256: hash64("c"), Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictOK,
	}
	r := Score([]VerifiedRecord{mk(body)}, nil)
	if r.Verdict != VerdictCaution {
		t.Fatalf("expected caution with default near-zero trust, got %s", r.Verdict)
	}
}
