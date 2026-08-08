// Package score implements deterministic scoring of verified ebi records.
package score

import (
	"fmt"
	"sort"

	"github.com/co3k/ebi/pkg/schema"
)

// VerifiedRecord is a record that has already passed signature/schema checks.
type VerifiedRecord struct {
	ID        string
	AuditorID string
	Body      schema.RecordBody
	PublicKey string
	Signature string
}

// Input is the deterministic scoring input.
type Input struct {
	// TargetHash is the SHA-256 hex of the script being scored.
	TargetHash string

	// Records are verified audit records for TargetHash.
	Records []VerifiedRecord

	// Retractions are verified retract/v1 records. A retraction removes a
	// target record only when it is signed by the same auditor.
	Retractions []VerifiedRecord

	// Trust maps auditor ID to a trust coefficient. Missing or empty keys
	// default to a near-zero value.
	Trust map[string]float64

	// PriorRecords are verified audit records for other target hashes. They
	// are used for delta inheritance when a record references a previous
	// target hash via prev_sha256.
	PriorRecords []VerifiedRecord
}

// Report is the deterministic score output.
type Report struct {
	ParamsVersion       string
	Verdict             string
	Positive            float64
	Negative            float64
	Total               float64
	RecordsUsed         int
	SignalsUsed         int
	KeysUsed            int
	FamiliesUsed        int
	RecordIDs           []string
	Reason              string
	DeltaInheritance    bool
	RetractionsExcluded int
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
	if r.Body.Analyzer.Kind == schema.KindLLM && r.Body.Analyzer.ModelFamily != "" {
		return r.Body.Analyzer.ModelFamily
	}
	if r.Body.Analyzer.Kind == schema.KindStatic {
		return schema.FamilyStatic
	}
	if r.Body.Analyzer.Kind == schema.KindHuman {
		return schema.FamilyHuman
	}
	// Fallback to analyzer kind for any other analyzer.
	if r.Body.Analyzer.Kind != "" {
		return r.Body.Analyzer.Kind
	}
	return schema.FamilyStatic
}

// dedupeKey returns the aggregation key for a record.
func dedupeKey(r VerifiedRecord) string {
	return r.AuditorID + "|" + family(r)
}

// Compute scores a single target hash deterministically.
func Compute(input Input) Report {
	records := filterByTarget(input.Records, input.TargetHash)
	beforeRetractions := len(records)
	records = applyRetractions(records, input.Retractions)
	retractionsExcluded := beforeRetractions - len(records)

	// Build lookup by target hash for delta inheritance.
	byTarget := make(map[string][]VerifiedRecord)
	for _, r := range input.PriorRecords {
		byTarget[r.Body.Target.SHA256] = append(byTarget[r.Body.Target.SHA256], r)
	}
	// Include current records in the lookup for deeper chains.
	for _, r := range records {
		byTarget[r.Body.Target.SHA256] = append(byTarget[r.Body.Target.SHA256], r)
	}

	// Deduplicate by (auditor, family): earliest created_at, tie by record ID.
	groups := map[string][]VerifiedRecord{}
	for _, r := range records {
		key := dedupeKey(r)
		groups[key] = append(groups[key], r)
	}
	selected := make([]VerifiedRecord, 0, len(groups))
	for _, grp := range groups {
		best := grp[0]
		bestTime := best.Body.CreatedAt
		for _, r := range grp[1:] {
			if r.Body.CreatedAt < bestTime || (r.Body.CreatedAt == bestTime && r.ID < best.ID) {
				best = r
				bestTime = r.Body.CreatedAt
			}
		}
		selected = append(selected, best)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })

	families := map[string]struct{}{}
	keys := map[string]struct{}{}
	for _, r := range selected {
		families[family(r)] = struct{}{}
		keys[r.AuditorID] = struct{}{}
	}
	familyCount := len(families)
	familyBonus := familyDiversityBonus(familyCount)

	recordIDs := []string{}
	positiveRaw := 0.0
	negative := 0.0
	inheritedPositive := 0.0
	inheritedNegative := 0.0
	deltaInheritance := false
	inheritedTargets := map[string]struct{}{}

	for _, r := range selected {
		recordIDs = append(recordIDs, r.ID)
		tr := trustFor(input.Trust, r.AuditorID)
		switch r.Body.Verdict {
		case schema.VerdictOK:
			positiveRaw += tr
		case schema.VerdictDanger:
			if len(r.Body.Claims) > 0 {
				sev := maxSeverity(r.Body.Claims)
				negative += tr * sev * NegativeMultiplier
			}
		}
		// Delta inheritance follows target hashes, coefficient .5, max 3 levels.
		if r.Body.PrevSHA256 != "" {
			if _, alreadyInherited := inheritedTargets[r.Body.PrevSHA256]; alreadyInherited {
				continue
			}
			if prev, ok := byTarget[r.Body.PrevSHA256]; ok && len(prev) > 0 {
				inheritedTargets[r.Body.PrevSHA256] = struct{}{}
				deltaInheritance = true
				delta := computeDelta(Input{
					TargetHash:   r.Body.PrevSHA256,
					Records:      prev,
					Retractions:  nil,
					Trust:        input.Trust,
					PriorRecords: nil,
				}, byTarget, 1, map[string]bool{input.TargetHash: true})
				inheritedPositive += delta.Positive * DeltaInheritanceCoefficient
				inheritedNegative += delta.Negative * DeltaInheritanceCoefficient
			}
		}
	}

	positive := positiveRaw*familyBonus + inheritedPositive
	negative += inheritedNegative

	report := Report{
		ParamsVersion:       ParamsVersion,
		Positive:            positive,
		Negative:            negative,
		Total:               positive - negative,
		RecordsUsed:         len(records),
		SignalsUsed:         len(selected),
		KeysUsed:            len(keys),
		FamiliesUsed:        familyCount,
		RecordIDs:           recordIDs,
		DeltaInheritance:    deltaInheritance,
		RetractionsExcluded: retractionsExcluded,
	}

	report.Reason = fmt.Sprintf("score=%.3f families=%d keys=%d signals=%d", report.Total, familyCount, len(keys), len(selected))

	// Verdict priority.
	switch {
	case negative >= TrustedPositiveThreshold:
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

// computeDelta recursively computes inherited score at a given depth.
// The depth parameter is the current level (1 means first predecessor).
func computeDelta(input Input, byTarget map[string][]VerifiedRecord, depth int, visiting map[string]bool) Report {
	if visiting[input.TargetHash] {
		return Report{ParamsVersion: ParamsVersion, Verdict: VerdictUnknown}
	}
	nextVisiting := make(map[string]bool, len(visiting)+1)
	for hash, active := range visiting {
		nextVisiting[hash] = active
	}
	nextVisiting[input.TargetHash] = true

	// Filter to the target hash.
	records := filterByTarget(input.Records, input.TargetHash)
	// Deduplicate.
	groups := map[string][]VerifiedRecord{}
	for _, r := range records {
		key := dedupeKey(r)
		groups[key] = append(groups[key], r)
	}
	selected := make([]VerifiedRecord, 0, len(groups))
	for _, grp := range groups {
		best := grp[0]
		bestTime := best.Body.CreatedAt
		for _, r := range grp[1:] {
			if r.Body.CreatedAt < bestTime || (r.Body.CreatedAt == bestTime && r.ID < best.ID) {
				best = r
				bestTime = r.Body.CreatedAt
			}
		}
		selected = append(selected, best)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })

	positiveRaw := 0.0
	negative := 0.0
	inheritedPositive := 0.0
	inheritedNegative := 0.0
	families := map[string]struct{}{}
	inheritedTargets := map[string]struct{}{}

	for _, r := range selected {
		families[family(r)] = struct{}{}
		tr := trustFor(input.Trust, r.AuditorID)
		switch r.Body.Verdict {
		case schema.VerdictOK:
			positiveRaw += tr
		case schema.VerdictDanger:
			if len(r.Body.Claims) > 0 {
				sev := maxSeverity(r.Body.Claims)
				negative += tr * sev * NegativeMultiplier
			}
		}
		// Chain deeper.
		if depth < DeltaMaxDepth && r.Body.PrevSHA256 != "" {
			if _, alreadyInherited := inheritedTargets[r.Body.PrevSHA256]; alreadyInherited {
				continue
			}
			if prev, ok := byTarget[r.Body.PrevSHA256]; ok && len(prev) > 0 {
				inheritedTargets[r.Body.PrevSHA256] = struct{}{}
				delta := computeDelta(Input{
					TargetHash:   r.Body.PrevSHA256,
					Records:      prev,
					Retractions:  nil,
					Trust:        input.Trust,
					PriorRecords: nil,
				}, byTarget, depth+1, nextVisiting)
				inheritedPositive += delta.Positive * DeltaInheritanceCoefficient
				inheritedNegative += delta.Negative * DeltaInheritanceCoefficient
			}
		}
	}

	positive := positiveRaw*familyDiversityBonus(len(families)) + inheritedPositive
	negative += inheritedNegative
	verdict := VerdictUnknown
	if negative >= TrustedPositiveThreshold {
		verdict = VerdictFlagged
	} else if positive >= TrustedPositiveThreshold && negative == 0 {
		verdict = VerdictTrusted
	} else if len(selected) > 0 {
		verdict = VerdictCaution
	}
	return Report{
		ParamsVersion: ParamsVersion,
		Verdict:       verdict,
		Positive:      positive,
		Negative:      negative,
		Total:         positive - negative,
	}
}

func familyDiversityBonus(familyCount int) float64 {
	bonus := PositiveMultiplierBase
	if familyCount <= 1 {
		return bonus
	}
	extra := float64(familyCount-1) * FamilyDiversityBonusPerExtra
	if extra > FamilyDiversityBonusMax-PositiveMultiplierBase {
		extra = FamilyDiversityBonusMax - PositiveMultiplierBase
	}
	return bonus + extra
}

func filterByTarget(records []VerifiedRecord, targetHash string) []VerifiedRecord {
	out := make([]VerifiedRecord, 0, len(records))
	for _, r := range records {
		if r.Body.Target.SHA256 == targetHash {
			out = append(out, r)
		}
	}
	return out
}

func applyRetractions(records, retractions []VerifiedRecord) []VerifiedRecord {
	out := make([]VerifiedRecord, 0, len(records))
	for _, r := range records {
		retracted := false
		for _, retr := range retractions {
			if retr.Body.Type != schema.SchemaRetractV1 {
				continue
			}
			if retr.AuditorID != r.AuditorID {
				continue
			}
			if retr.Body.RecordID == r.ID {
				retracted = true
				break
			}
		}
		if !retracted {
			out = append(out, r)
		}
	}
	return out
}

func maxSeverity(claims []schema.Claim) float64 {
	max := 0.0
	for _, c := range claims {
		cat := schema.DisplayCategory(c.Category)
		sev := Severity[cat]
		if sev > max {
			max = sev
		}
	}
	if max == 0 {
		return 1.0
	}
	return max
}

func trustFor(trust map[string]float64, auditorID string) float64 {
	if trust != nil {
		if v, ok := trust[auditorID]; ok {
			if v < 0 {
				return 0
			}
			return v
		}
	}
	if auditorID == "" {
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

// FilterRetractions removes retraction and moderation records from the list.
func FilterRetractions(records []VerifiedRecord) []VerifiedRecord {
	out := make([]VerifiedRecord, 0, len(records))
	for _, r := range records {
		if r.Body.Type == schema.SchemaRetractV1 || r.Body.Type == schema.SchemaModerationV1 {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Score is a compatibility wrapper around Compute.
func Score(records []VerifiedRecord, recordsByID map[string]VerifiedRecord) Report {
	trust := map[string]float64{}
	retractions := []VerifiedRecord{}
	var targetHash string
	for _, r := range records {
		if r.Body.Type == schema.SchemaRetractV1 {
			retractions = append(retractions, r)
			continue
		}
		if targetHash == "" {
			targetHash = r.Body.Target.SHA256
		}
		if r.Body.Target.SHA256 == targetHash {
			trust[r.AuditorID] = TrustFor(r.AuditorID, nil)
		}
	}
	return Compute(Input{
		TargetHash:   targetHash,
		Records:      records,
		Retractions:  retractions,
		Trust:        trust,
		PriorRecords: nil,
	})
}

// TrustFor returns the trust coefficient for an auditor.
// If history is nil, it returns the default trust value. Callers may supply a
// history map to override trust for specific auditors.
func TrustFor(auditorID string, history map[string]float64) float64 {
	if history != nil {
		if v, ok := history[auditorID]; ok {
			return v
		}
	}
	if auditorID == "" {
		return 0
	}
	return TrustDefault
}

// NewRecordsByTarget builds a lookup map keyed by auditor|target hash.
func NewRecordsByTarget(records []VerifiedRecord) map[string]VerifiedRecord {
	m := make(map[string]VerifiedRecord, len(records))
	for _, r := range records {
		m[r.AuditorID+"|"+r.Body.Target.SHA256] = r
	}
	return m
}
