// Package score implements deterministic scoring of verified ebi records.
package score

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/co3k/ebi/pkg/schema"
)

// ParamsVersion identifies the scoring parameter set used.
const ParamsVersion = "v0.1.0"

// Scoring parameters. These are versioned and intentionally conservative.
const (
	TrustDefault              = 1.0
	PositiveMultiplierBase      = 1.0
	FamilyDiversityBonusPerExtra = 0.2
	FamilyDiversityBonusMax      = 2.0
	NegativeMultiplier           = 3.0
	TrustedPositiveThreshold     = 1.0
	DeltaInheritanceCoefficient  = 0.5
	DeltaMaxDepth                = 3
)

// Severity assigns a weight to each claim category. Unknown values are
// normalized to misc.other before lookup.
var Severity = map[string]float64{
	"net.fetch":         0.5,
	"exec.remote_pipe":  1.0,
	"exec.eval":         1.0,
	"obfuscation.base64":  0.8,
	"obfuscation.misc":  0.8,
	"fs.delete_broad":   0.7,
	"priv.sudo":         0.6,
	"priv.persist":      0.9,
	"env.exfil":         0.8,
	"pkg.install":       0.5,
	"download.unpinned": 0.3,
	"misc.other":        0.4,
}

// VerifiedRecord is a record that has already passed signature/schema checks.
type VerifiedRecord struct {
	ID        string
	AuditorID string
	Body      schema.RecordBody
	PublicKey string
	Signature string
}

// Report is the deterministic score output.
type Report struct {
	ParamsVersion    string
	Verdict          string
	Positive         float64
	Negative         float64
	Total            float64
	RecordsUsed      int
	SignalsUsed      int
	KeysUsed         int
	FamiliesUsed     int
	RecordIDs        []string
	Reason           string
	DeltaInheritance bool
}

// Verdict values.
const (
	VerdictUnknown = "unknown"
	VerdictCaution = "caution"
	VerdictTrusted = "trusted"
	VerdictFlagged = "flagged"
)

// family returns the scoring family for a record.
func family(r VerifiedRecord) string {
	if r.Body.ModelFamily != "" {
		return r.Body.ModelFamily
	}
	if r.Body.AnalyzerFamily != "" {
		return r.Body.AnalyzerFamily
	}
	return schema.FamilyStatic
}

// dedupeKey returns the aggregation key for a record.
func dedupeKey(r VerifiedRecord) string {
	return r.AuditorID + "|" + family(r)
}

// Score computes a deterministic score from the given records.
// retractionMap and recordsByID are used for delta inheritance and retraction
// exclusion. Records already known to be retractions should be excluded before
// calling Score.
func Score(records []VerifiedRecord, recordsByID map[string]VerifiedRecord) Report {
	if recordsByID == nil {
		recordsByID = map[string]VerifiedRecord{}
	}
	for _, r := range records {
		if _, ok := recordsByID[r.ID]; !ok {
			recordsByID[r.ID] = r
		}
	}

	// Deduplicate by (auditor, family): earliest created_at, tie by ID.
	groups := map[string][]VerifiedRecord{}
	for _, r := range records {
		key := dedupeKey(r)
		groups[key] = append(groups[key], r)
	}
	selected := make([]VerifiedRecord, 0, len(groups))
	for _, grp := range groups {
		best := grp[0]
		bestTime, _ := time.Parse(time.RFC3339, best.Body.CreatedAt)
		for _, r := range grp[1:] {
			t, _ := time.Parse(time.RFC3339, r.Body.CreatedAt)
			if t.Before(bestTime) || (t.Equal(bestTime) && r.ID < best.ID) {
				best = r
				bestTime = t
			}
		}
		selected = append(selected, best)
	}
	// Deterministic order by ID.
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })

	families := map[string]struct{}{}
	for _, r := range selected {
		families[family(r)] = struct{}{}
	}
	familyCount := len(families)
	familyBonus := PositiveMultiplierBase
	if familyCount > 1 {
		extra := float64(familyCount-1) * FamilyDiversityBonusPerExtra
		if extra > FamilyDiversityBonusMax-PositiveMultiplierBase {
			extra = FamilyDiversityBonusMax - PositiveMultiplierBase
		}
		familyBonus += extra
	}

	positive := 0.0
	negative := 0.0
	hasOK := false
	hasFlagged := false
	recordIDs := []string{}

	for _, r := range selected {
		recordIDs = append(recordIDs, r.ID)
		base := baseScore(r, familyBonus)
		if base > 0 {
			hasOK = true
		}
		if r.Body.Verdict == schema.VerdictFlagged {
			hasFlagged = true
		}
		if base > 0 {
			positive += base
		} else {
			negative += -base
		}
		// Delta inheritance.
		if r.Body.PrevSHA256 != "" {
			prev, ok := recordsByID[r.Body.PrevSHA256]
			if ok {
				delta := deltaScore(prev, familyBonus, recordsByID, 1)
				if delta > 0 {
					positive += delta
				} else {
					negative += -delta
				}
			}
		}
	}

	if hasOK && positive == 0 {
		positive = TrustDefault * familyBonus
	}

	report := Report{
		ParamsVersion: ParamsVersion,
		Positive:      positive,
		Negative:      negative,
		Total:         positive - negative,
		RecordsUsed:   len(records),
		SignalsUsed:   len(selected),
		KeysUsed:      len(groups),
		FamiliesUsed:  familyCount,
		RecordIDs:     recordIDs,
	}

	report.Reason = fmt.Sprintf("score=%.3f families=%d keys=%d signals=%d", report.Total, familyCount, len(groups), len(selected))

	// Verdict priority.
	switch {
	case hasFlagged || negative >= TrustedPositiveThreshold:
		report.Verdict = VerdictFlagged
	case positive >= TrustedPositiveThreshold && negative == 0:
		report.Verdict = VerdictTrusted
	case len(selected) > 0:
		report.Verdict = VerdictCaution
	default:
		report.Verdict = VerdictUnknown
	}
	return report
}

// baseScore computes the contribution of a single record without delta inheritance.
func baseScore(r VerifiedRecord, familyBonus float64) float64 {
	trust := TrustDefault
	switch r.Body.Verdict {
	case schema.VerdictInfo:
		return 0
	case schema.VerdictOK:
		return trust * familyBonus
	case schema.VerdictCaution:
		return 0
	case schema.VerdictDanger, schema.VerdictFlagged:
		sev := 0.0
		for _, c := range r.Body.Claims {
			cat := schema.DisplayCategory(c.Category)
			sev += Severity[cat]
		}
		return -(trust * sev * NegativeMultiplier)
	}
	return 0
}

// deltaScore recursively applies delta inheritance at coefficient .5, max depth 3.
func deltaScore(r VerifiedRecord, familyBonus float64, recordsByID map[string]VerifiedRecord, depth int) float64 {
	if depth > DeltaMaxDepth {
		return 0
	}
	base := baseScore(r, familyBonus)
	score := base * DeltaInheritanceCoefficient
	if r.Body.PrevSHA256 != "" {
		prev, ok := recordsByID[r.Body.PrevSHA256]
		if ok {
			score += deltaScore(prev, familyBonus, recordsByID, depth+1) * DeltaInheritanceCoefficient
		}
	}
	return score
}

// TrustFor returns the trust coefficient for an auditor. Default is 1.0.
func TrustFor(auditorID string) float64 {
	if strings.TrimSpace(auditorID) == "" {
		return 0
	}
	return TrustDefault
}

// IsBlocking returns true when the report verdict blocks execution even with --yes.
func IsBlocking(r Report) bool {
	return r.Verdict == VerdictFlagged
}

// NewRecordsByID builds a lookup map from a slice of verified records.
func NewRecordsByID(records []VerifiedRecord) map[string]VerifiedRecord {
	m := make(map[string]VerifiedRecord, len(records))
	for _, r := range records {
		m[r.ID] = r
	}
	return m
}
