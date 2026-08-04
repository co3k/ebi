// Command ebi-monitor verifies a transparency log and reports structured output.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/co3k/ebi/pkg/appmeta"

	"github.com/co3k/ebi/pkg/prefixdb"
	"github.com/co3k/ebi/pkg/schema"
	"github.com/co3k/ebi/pkg/score"
	"github.com/co3k/ebi/pkg/storage"
	"github.com/co3k/ebi/pkg/tlogx"
	"golang.org/x/mod/sumdb/tlog"
)

func main() {
	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx := context.Background()

	if cfg.oneShot {
		result, err := runWithConfig(ctx, cfg)
		if err != nil || result == nil || result.Corrupt {
			if result == nil {
				result = &monitorResult{
					Time:    time.Now().UTC().Format(time.RFC3339),
					Error:   fmt.Sprintf("monitor: %v", err),
					Corrupt: true,
				}
			}
			if err := writeResult(result, os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "write result: %v\n", err)
			}
			os.Exit(2)
		}
		if err := writeResult(result, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "write result: %v\n", err)
			os.Exit(2)
		}
		return
	}

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	for {
		result, err := runWithConfig(ctx, cfg)
		if err != nil || result == nil || result.Corrupt {
			if result == nil {
				result = &monitorResult{
					Time:    time.Now().UTC().Format(time.RFC3339),
					Error:   fmt.Sprintf("monitor: %v", err),
					Corrupt: true,
				}
			}
			if err := writeResult(result, os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "write result: %v\n", err)
			}
			os.Exit(2)
		}
		if err := writeResult(result, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "write result: %v\n", err)
			os.Exit(2)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type config struct {
	storage        string
	storageEnv     bool
	baseURL        string
	policyPath     string
	checkpointPath string
	oneShot        bool
	interval       time.Duration
	webhook        string
	webhookRetries int
	webhookTimeout time.Duration
}

func parseConfig() (*config, error) {
	cfg := &config{}
	flag.StringVar(&cfg.storage, "storage", "", "local storage root")
	flag.BoolVar(&cfg.storageEnv, "storage-env", false, "open storage from EBI_STORAGE_* environment variables")
	flag.StringVar(&cfg.baseURL, "base-url", "", "base URL for HTTP fetch")
	flag.StringVar(&cfg.policyPath, "policy", "", "trust policy file (TOML)")
	flag.StringVar(&cfg.checkpointPath, "checkpoint-state", "", "persisted checkpoint state file")
	flag.BoolVar(&cfg.oneShot, "one-shot", false, "run once and exit")
	flag.DurationVar(&cfg.interval, "interval", 5*time.Minute, "poll interval")
	flag.StringVar(&cfg.webhook, "webhook", "", "optional alert webhook URL")
	flag.IntVar(&cfg.webhookRetries, "webhook-retries", 3, "webhook retries")
	flag.DurationVar(&cfg.webhookTimeout, "webhook-timeout", 10*time.Second, "webhook timeout")
	flag.Parse()

	sources := 0
	if cfg.storage != "" {
		sources++
	}
	if cfg.storageEnv {
		sources++
	}
	if cfg.baseURL != "" {
		sources++
	}
	if sources != 1 {
		return nil, fmt.Errorf("usage: ebi-monitor (--storage=<root> | --storage-env | --base-url=<url>) --policy=<path>")
	}
	if cfg.policyPath == "" {
		return nil, fmt.Errorf("usage: --policy=<path> is required")
	}
	if cfg.webhookRetries < 0 {
		cfg.webhookRetries = 0
	}
	return cfg, nil
}

type monitorResult struct {
	Time        string   `json:"time"`
	Origin      string   `json:"origin,omitempty"`
	Size        int64    `json:"size,omitempty"`
	Root        string   `json:"root,omitempty"`
	Verified    bool     `json:"verified,omitempty"`
	Shards      int      `json:"shards,omitempty"`
	Records     int      `json:"records,omitempty"`
	Retractions int      `json:"retractions,omitempty"`
	ScoreParams string   `json:"score_params,omitempty"`
	Agent       string   `json:"agent,omitempty"`
	Error       string   `json:"error,omitempty"`
	Corrupt     bool     `json:"corrupt,omitempty"`
	Details     []string `json:"details,omitempty"`
}

func runWithConfig(ctx context.Context, cfg *config) (*monitorResult, error) {
	policy, err := tlogx.LoadPolicy(cfg.policyPath)
	if err != nil {
		return nil, fmt.Errorf("load policy: %w", err)
	}

	var store storage.Store
	if cfg.storageEnv {
		store, err = storage.NewFromEnv(ctx)
		if err != nil {
			return nil, fmt.Errorf("environment storage: %w", err)
		}
	} else if cfg.storage != "" {
		local, err := storage.NewLocal(cfg.storage)
		if err != nil {
			return nil, fmt.Errorf("local storage: %w", err)
		}
		store = local
	} else {
		store = newHTTPStore(cfg.baseURL)
	}
	defer store.Close()

	priorTree, hasPrior, err := loadPriorState(cfg.checkpointPath)
	if err != nil {
		return nil, err
	}

	result, signed, tree, err := verifyLog(ctx, store, policy, priorTree, hasPrior)
	if err != nil {
		return result, err
	}
	if result.Corrupt {
		if cfg.webhook != "" {
			_ = sendWebhook(ctx, cfg.webhook, result, cfg.webhookRetries, cfg.webhookTimeout)
		}
		return result, nil
	}

	if cfg.checkpointPath != "" {
		if err := tlogx.SaveCheckpointState(cfg.checkpointPath, tree, signed); err != nil {
			return nil, fmt.Errorf("save checkpoint state: %w", err)
		}
	}
	return result, nil
}

func loadPriorState(path string) (tlog.Tree, bool, error) {
	if path == "" {
		return tlog.Tree{}, false, nil
	}
	priorTree, _, err := tlogx.LoadCheckpointState(path)
	if err == nil {
		return priorTree, true, nil
	}
	if os.IsNotExist(err) {
		return tlogx.NewTree().TlogTree(), true, nil
	}
	return tlog.Tree{}, false, fmt.Errorf("load checkpoint state: %w", err)
}

func verifyLog(ctx context.Context, store storage.Store, policy tlogx.Policy, priorTree tlog.Tree, hasPrior bool) (*monitorResult, []byte, tlog.Tree, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	result := &monitorResult{
		Time:   now,
		Origin: policy.LogName,
		Agent:  appmeta.UserAgent(),
	}

	cpRaw, err := fetchCheckpoint(ctx, store)
	if err != nil {
		result.Corrupt = true
		result.Error = "checkpoint fetch failed"
		result.Details = append(result.Details, err.Error())
		return result, nil, tlog.Tree{}, nil
	}

	var tree tlog.Tree
	var signed []byte
	if hasPrior {
		tree, signed, err = tlogx.VerifyCheckpointState(cpRaw, priorTree, policy, store)
	} else {
		tree, _, err = tlogx.VerifyCheckpoint(cpRaw, policy)
		signed = cpRaw
	}
	if err != nil {
		result.Corrupt = true
		result.Error = "checkpoint verification failed"
		result.Details = append(result.Details, err.Error())
		return result, nil, tlog.Tree{}, nil
	}
	result.Size = tree.N
	result.Root = tlogx.HexHash(tree.Hash)

	leaves, details, err := listLeaves(ctx, store, tree.N)
	if err != nil {
		result.Corrupt = true
		result.Error = "leaf index enumeration failed"
		result.Details = append(result.Details, err.Error())
		return result, nil, tlog.Tree{}, nil
	}
	result.Details = append(result.Details, details...)
	for _, d := range details {
		if d != "" {
			result.Corrupt = true
		}
	}
	for _, d := range details {
		if strings.Contains(d, "duplicate leaf index") {
			result.Corrupt = true
		}
	}
	if result.Corrupt {
		result.Error = "leaf index errors"
		return result, nil, tlog.Tree{}, nil
	}

	// Missing/unpublished leaves.
	for i := int64(0); i < tree.N; i++ {
		if _, ok := leaves[i]; !ok {
			result.Corrupt = true
			result.Details = append(result.Details, fmt.Sprintf("missing leaf index %d", i))
		}
	}

	// Enumerate blobs now; validate leaf and content-artifact references after
	// all record bodies have been authenticated.
	var blobIDs []string
	if _, staticHTTP := store.(*httpStore); !staticHTTP {
		blobIDs, err = listBlobIDs(ctx, store)
		if err != nil {
			result.Corrupt = true
			result.Details = append(result.Details, fmt.Sprintf("list blobs: %v", err))
		}
	}

	records, retractions, indices, leafDetails := verifyLeaves(ctx, store, policy, tree, leaves)
	result.Details = append(result.Details, leafDetails...)
	for _, d := range leafDetails {
		if d != "" {
			result.Corrupt = true
		}
	}

	if result.Corrupt {
		result.Error = "log verification failed"
		return result, nil, tlog.Tree{}, nil
	}
	for _, detail := range validateRetractions(records, indices) {
		result.Corrupt = true
		result.Details = append(result.Details, detail)
	}
	if result.Corrupt {
		result.Error = "invalid retraction records"
		return result, nil, tlog.Tree{}, nil
	}
	recordIDs := make(map[string]bool, len(leaves))
	for _, id := range leaves {
		recordIDs[id] = true
	}
	contentRefs := referencedBlobIDs(records)

	// Verify every content blob referenced by authenticated audit records
	// (target hash and LLM prompt hash). This runs even in HTTP mode, where
	// listings are unavailable but known references can be fetched directly.
	for id := range contentRefs {
		if !schema.IsHexHash(id) {
			result.Details = append(result.Details, fmt.Sprintf("invalid referenced content blob id %s", id))
			result.Corrupt = true
			continue
		}
		data, err := store.Get(ctx, storage.BlobPath(id))
		if err != nil {
			result.Details = append(result.Details, fmt.Sprintf("missing referenced content blob %s: %v", id, err))
			result.Corrupt = true
			continue
		}
		if storage.ContentHash(data) != id {
			result.Details = append(result.Details, fmt.Sprintf("referenced content blob hash mismatch %s", id))
			result.Corrupt = true
		}
	}

	// Enumerate unreferenced listed blobs (local/S3 only).
	if len(blobIDs) > 0 {
		for _, id := range blobIDs {
			if recordIDs[id] || contentRefs[id] {
				continue
			}
			data, err := store.Get(ctx, storage.BlobPath(id))
			if err != nil || !schema.IsHexHash(id) || storage.ContentHash(data) != id {
				result.Details = append(result.Details, fmt.Sprintf("orphan blob %s", id))
			} else {
				result.Details = append(result.Details, fmt.Sprintf("unreferenced content blob %s", id))
			}
			result.Corrupt = true
		}
	}
	if result.Corrupt {
		result.Error = "blob reference verification failed"
		return result, nil, tlog.Tree{}, nil
	}

	shards, shardDetails, err := verifyShards(ctx, store, records, retractions, indices)
	if err != nil {
		result.Corrupt = true
		result.Details = append(result.Details, fmt.Sprintf("shard verification: %v", err))
		result.Error = "shard verification failed"
		return result, nil, tlog.Tree{}, nil
	}
	result.Details = append(result.Details, shardDetails...)
	result.Shards = len(shards)

	retractedRecords, recordsAfter, _ := applyRetractions(records, retractions, nil)
	result.Records = len(recordsAfter)
	result.Retractions = len(retractions)
	_ = retractedRecords

	scoreDetails := recomputeScores(records, retractions)
	result.Details = append(result.Details, scoreDetails...)
	result.ScoreParams = scoreParamsString()

	result.Verified = true
	return result, signed, tree, nil
}

func referencedBlobIDs(records []schema.Record) map[string]bool {
	referenced := make(map[string]bool)
	for _, record := range records {
		if record.Body.Type != schema.SchemaAuditV1 {
			continue
		}
		referenced[record.Body.Target.SHA256] = true
		if record.Body.Analyzer.Kind == schema.KindLLM {
			referenced[record.Body.Analyzer.PromptSHA256] = true
		}
	}
	return referenced
}

func validateRetractions(records []schema.Record, indices []int64) []string {
	var details []string
	for i, retract := range records {
		if retract.Body.Type != schema.SchemaRetractV1 {
			continue
		}
		matched := false
		for j, target := range records {
			if target.Body.Type != schema.SchemaAuditV1 || indices[j] >= indices[i] {
				continue
			}
			if schema.RetractionMatchesTarget(&retract, &target) {
				matched = true
				break
			}
		}
		if !matched {
			details = append(details, fmt.Sprintf(
				"leaf %d: retraction %s has no earlier matching audit record",
				indices[i], retract.Body.RecordID,
			))
		}
	}
	return details
}

func fetchCheckpoint(ctx context.Context, store storage.Store) ([]byte, error) {
	return store.Get(ctx, storage.CheckpointPath())
}

func listLeaves(ctx context.Context, store storage.Store, treeSize int64) (map[int64]string, []string, error) {
	if _, ok := store.(*httpStore); ok {
		leaves := make(map[int64]string, treeSize)
		var details []string
		for i := int64(0); i < treeSize; i++ {
			key := fmt.Sprintf("v1/leaf/%d", i)
			idx, id, err := parseLeafIndexPathAndContent(ctx, store, key)
			if err != nil {
				details = append(details, fmt.Sprintf("leaf index %d: %v", i, err))
				continue
			}
			if idx != i {
				details = append(details, fmt.Sprintf("leaf path %d resolved to index %d", i, idx))
				continue
			}
			leaves[i] = id
		}
		return leaves, details, nil
	}
	keys, err := store.List(ctx, "v1/leaf")
	if err != nil {
		return nil, nil, err
	}
	leaves := map[int64]string{}
	recordIDs := map[string]int64{}
	var details []string
	for _, key := range keys {
		idx, id, err := parseLeafIndexPathAndContent(ctx, store, key)
		if err != nil {
			details = append(details, err.Error())
			continue
		}
		if _, exists := leaves[idx]; exists {
			details = append(details, fmt.Sprintf("duplicate leaf index %d", idx))
			continue
		}
		if prior, exists := recordIDs[id]; exists {
			details = append(details, fmt.Sprintf("record %s appears at leaf indexes %d and %d", id, prior, idx))
			continue
		}
		leaves[idx] = id
		recordIDs[id] = idx
	}
	return leaves, details, nil
}

func parseLeafIndexPathAndContent(ctx context.Context, store storage.Store, key string) (int64, string, error) {
	data, err := store.Get(ctx, key)
	if err != nil {
		return 0, "", fmt.Errorf("read leaf index %s: %w", key, err)
	}
	idx, _, err := tlogx.DecodeLeafIndex(key, data)
	if err != nil {
		return 0, "", err
	}
	return idx.Index, idx.RecordID, nil
}

func listBlobIDs(ctx context.Context, store storage.Store) ([]string, error) {
	keys, err := store.List(ctx, "v1/blob")
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, key := range keys {
		id := strings.TrimPrefix(key, "v1/blob/")
		if id == "" || strings.Contains(id, "/") {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func verifyLeaves(ctx context.Context, store storage.Store, policy tlogx.Policy, tree tlog.Tree, leaves map[int64]string) ([]schema.Record, []schema.Record, []int64, []string) {
	var details []string
	var records []schema.Record
	var retractions []schema.Record
	var leafIndices []int64
	type tombstonedLeaf struct {
		index int64
		id    string
		hash  string
	}
	var tombstones []tombstonedLeaf

	indices := make([]int64, 0, len(leaves))
	for idx := range leaves {
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })

	for _, idx := range indices {
		if idx < 0 || idx >= tree.N {
			details = append(details, fmt.Sprintf("leaf index %d out of range", idx))
			continue
		}
		id := leaves[idx]
		if !schema.IsHexHash(id) {
			details = append(details, fmt.Sprintf("leaf %d: invalid record id", idx))
			continue
		}
		indexPath := fmt.Sprintf("v1/leaf/%d", idx)
		indexData, err := store.Get(ctx, indexPath)
		if err != nil {
			details = append(details, fmt.Sprintf("leaf %d: missing leaf index: %v", idx, err))
			continue
		}
		indexDoc, indexedHash, err := tlogx.DecodeLeafIndex(indexPath, indexData)
		if err != nil {
			details = append(details, fmt.Sprintf("leaf %d: %v", idx, err))
			continue
		}
		if indexDoc.RecordID != id {
			details = append(details, fmt.Sprintf("leaf %d: record id changed during enumeration", idx))
			continue
		}
		blobPath := "v1/blob/" + id
		data, err := store.Get(ctx, blobPath)
		if err != nil {
			details = append(details, fmt.Sprintf("leaf %d: missing blob %s: %v", idx, id, err))
			continue
		}
		if _, isTombstone, err := tlogx.DecodeTombstoneBlob(data, id); err != nil {
			details = append(details, fmt.Sprintf("leaf %d: invalid tombstone: %v", idx, err))
			continue
		} else if isTombstone {
			if err := tlogx.VerifyInclusionAt(store, idx, indexedHash, tree, policy); err != nil {
				details = append(details, fmt.Sprintf("leaf %d: tombstone inclusion proof: %v", idx, err))
				continue
			}
			tombstones = append(tombstones, tombstonedLeaf{
				index: idx,
				id:    id,
				hash:  tlogx.TombstoneSHA256(data),
			})
			continue
		}

		rec, err := schema.DecodeRecordStrict(bytes.NewReader(data))
		if err != nil {
			details = append(details, fmt.Sprintf("leaf %d: unmarshal record: %v", idx, err))
			continue
		}
		body, _, err := schema.Verify(rec)
		if err != nil {
			details = append(details, fmt.Sprintf("leaf %d: signature verify: %v", idx, err))
			continue
		}
		gotID, err := schema.RecordID(*body)
		if err != nil {
			details = append(details, fmt.Sprintf("leaf %d: record id: %v", idx, err))
			continue
		}
		if gotID != id {
			details = append(details, fmt.Sprintf("leaf %d: record id mismatch: got %s, want %s", idx, gotID, id))
			continue
		}
		leaf, err := tlogx.RecordToLeaf(*rec)
		if err != nil {
			details = append(details, fmt.Sprintf("leaf %d: to leaf: %v", idx, err))
			continue
		}
		lh, err := tlogx.LeafHash(leaf)
		if err != nil {
			details = append(details, fmt.Sprintf("leaf %d: leaf hash: %v", idx, err))
			continue
		}
		if lh != indexedHash {
			details = append(details, fmt.Sprintf("leaf %d: leaf hash does not match index", idx))
			continue
		}
		if err := tlogx.VerifyInclusionAt(store, idx, lh, tree, policy); err != nil {
			details = append(details, fmt.Sprintf("leaf %d: inclusion proof: %v", idx, err))
			continue
		}
		records = append(records, *rec)
		leafIndices = append(leafIndices, idx)
		if rec.Body.Type == schema.SchemaRetractV1 {
			retractions = append(retractions, *rec)
		}
	}

	for _, tombstone := range tombstones {
		matched := false
		for i, rec := range records {
			if leafIndices[i] <= tombstone.index || rec.Body.Type != schema.SchemaModerationV1 {
				continue
			}
			if rec.Body.Reason == "tombstone" &&
				rec.Body.BlobSHA256 == tombstone.id &&
				rec.Body.TombstoneSHA256 == tombstone.hash {
				matched = true
				break
			}
		}
		if !matched {
			details = append(details, fmt.Sprintf(
				"leaf %d: tombstoned record %s has no later matching moderation record",
				tombstone.index, tombstone.id,
			))
		}
	}
	return records, retractions, leafIndices, details
}

func applyRetractions(records, retractions []schema.Record, indices []int64) (int, []schema.Record, []int64) {
	kept := make([]schema.Record, 0, len(records))
	keptIndices := make([]int64, 0, len(records))
	if indices == nil {
		indices = make([]int64, len(records))
		for i := range records {
			indices[i] = int64(i)
		}
	}
	retracted := 0
	for i, rec := range records {
		if rec.Body.Type != schema.SchemaAuditV1 {
			continue
		}
		r := rec
		matched := false
		for _, retr := range retractions {
			if schema.RetractionMatchesTarget(&retr, &r) {
				matched = true
				break
			}
		}
		if matched {
			retracted++
			continue
		}
		kept = append(kept, rec)
		keptIndices = append(keptIndices, indices[i])
	}
	return retracted, kept, keptIndices
}

func verifyShards(ctx context.Context, store storage.Store, records, retractions []schema.Record, indices []int64) (map[string][]byte, []string, error) {
	_, auditRecords, auditIndices := applyRetractions(records, retractions, indices)
	if _, ok := store.(*httpStore); ok {
		want, err := prefixdb.BuildShardsWithIndex(auditRecords, auditIndices)
		if err != nil {
			return nil, nil, err
		}
		got := make(map[string][]byte, len(want))
		for prefix, expected := range want {
			data, err := store.Get(ctx, storage.PrefixPath(prefix))
			if err != nil {
				return nil, nil, fmt.Errorf("fetch prefix %s: %w", prefix, err)
			}
			if !bytes.Equal(data, expected) {
				return nil, nil, fmt.Errorf("prefix %s shard mismatch", prefix)
			}
			got[prefix] = data
		}
		return got, nil, nil
	}
	keys, err := store.List(ctx, "v1/prefix")
	if err != nil {
		return nil, nil, err
	}
	got := map[string][]byte{}
	var details []string
	for _, key := range keys {
		prefix := strings.TrimPrefix(key, "v1/prefix/")
		if prefix == "" || strings.Contains(prefix, "/") {
			continue
		}
		data, err := store.Get(ctx, key)
		if err != nil {
			return nil, nil, err
		}
		got[prefix] = data
	}
	if err := prefixdb.VerifyShardsWithIndex(auditRecords, auditIndices, got); err != nil {
		return nil, details, err
	}
	return got, details, nil
}

func recomputeScores(records []schema.Record, retractions []schema.Record) []string {
	byTarget := map[string][]schema.Record{}
	for _, rec := range records {
		if rec.Body.Type == schema.SchemaAuditV1 && rec.Body.Target.SHA256 != "" {
			byTarget[rec.Body.Target.SHA256] = append(byTarget[rec.Body.Target.SHA256], rec)
		}
	}
	var details []string
	for target, recs := range byTarget {
		_, kept, _ := applyRetractions(recs, retractions, nil)
		input := score.Input{
			TargetHash:   target,
			Records:      toVerified(kept),
			Retractions:  toVerified(retractions),
			Trust:        map[string]float64{},
			PriorRecords: nil,
		}
		for _, r := range kept {
			input.Trust[schema.AuditorHash(r.PublicKey)] = score.TrustDefault
		}
		_ = score.Compute(input)
	}
	return details
}

func toVerified(records []schema.Record) []score.VerifiedRecord {
	out := make([]score.VerifiedRecord, 0, len(records))
	for _, rec := range records {
		id, _ := schema.RecordID(rec.Body)
		auditorID := schema.AuditorHash(rec.PublicKey)
		out = append(out, score.VerifiedRecord{
			ID:        id,
			AuditorID: auditorID,
			Body:      rec.Body,
			PublicKey: rec.PublicKey,
			Signature: rec.Signature,
		})
	}
	return out
}

type severityMap map[string]float64

func (m severityMap) MarshalJSON() ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(k)
		b.WriteString(`":`)
		fmt.Fprintf(&b, "%g", m[k])
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func scoreParamsString() string {
	params := struct {
		Version                      string      `json:"version"`
		TrustDefault                 float64     `json:"trust_default"`
		PositiveMultiplierBase       float64     `json:"positive_multiplier_base"`
		FamilyDiversityBonusPerExtra float64     `json:"family_diversity_bonus_per_extra"`
		FamilyDiversityBonusMax      float64     `json:"family_diversity_bonus_max"`
		NegativeMultiplier           float64     `json:"negative_multiplier"`
		TrustedPositiveThreshold     float64     `json:"trusted_positive_threshold"`
		DeltaInheritanceCoefficient  float64     `json:"delta_inheritance_coefficient"`
		DeltaMaxDepth                int         `json:"delta_max_depth"`
		Severity                     severityMap `json:"severity"`
	}{
		Version:                      score.ParamsVersion,
		TrustDefault:                 score.TrustDefault,
		PositiveMultiplierBase:       score.PositiveMultiplierBase,
		FamilyDiversityBonusPerExtra: score.FamilyDiversityBonusPerExtra,
		FamilyDiversityBonusMax:      score.FamilyDiversityBonusMax,
		NegativeMultiplier:           score.NegativeMultiplier,
		TrustedPositiveThreshold:     score.TrustedPositiveThreshold,
		DeltaInheritanceCoefficient:  score.DeltaInheritanceCoefficient,
		DeltaMaxDepth:                score.DeltaMaxDepth,
		Severity:                     severityMap(score.Severity),
	}
	b, _ := json.Marshal(params)
	return string(b)
}

func writeResult(result *monitorResult, w io.Writer) error {
	out, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(out))
	return err
}

func sendWebhook(ctx context.Context, webhook string, result *monitorResult, retries int, timeout time.Duration) error {
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{ForceAttemptHTTP2: false}}
	var lastErr error
	for i := 0; i <= retries; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(i) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, strings.NewReader(string(body)))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", appmeta.UserAgent())
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			return nil
		}
		lastErr = fmt.Errorf("webhook %d", resp.StatusCode)
	}
	return lastErr
}

// httpStore is a read-only storage.Store adapter over an HTTP base URL.
type httpStore struct {
	baseURL string
	client  *http.Client
}

func newHTTPStore(baseURL string) *httpStore {
	return &httpStore{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				ForceAttemptHTTP2: false,
			},
		},
	}
}

func (s *httpStore) Get(ctx context.Context, path string) ([]byte, error) {
	u := s.baseURL + "/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", appmeta.UserAgent())
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (64<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64<<20 {
		return nil, fmt.Errorf("http object exceeds 64 MiB")
	}
	return data, nil
}

func (s *httpStore) Put(ctx context.Context, obj storage.Object) error {
	return fmt.Errorf("httpStore is read-only")
}

func (s *httpStore) Delete(ctx context.Context, path string) error {
	return fmt.Errorf("httpStore is read-only")
}

func (s *httpStore) List(ctx context.Context, prefix string) ([]string, error) {
	u := s.baseURL
	if prefix == "" {
		u += "/"
	} else {
		u += "/" + strings.TrimSuffix(prefix, "/") + "/"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", appmeta.UserAgent())
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("directory listing exceeds 1 MiB")
	}
	return parseDirList(u, string(data), prefix)
}

func (s *httpStore) Publish(ctx context.Context, obj storage.Object) error {
	return s.Put(ctx, obj)
}

func (s *httpStore) Close() error { return nil }

var hrefRe = regexp.MustCompile(`<a[^>]*href\s*=\s*"([^"]*)"`)

func parseDirList(baseURL, html, prefix string) ([]string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range hrefRe.FindAllStringSubmatch(html, -1) {
		if len(m) < 2 {
			continue
		}
		href := m[1]
		if href == "" || href == "../" || strings.HasPrefix(href, "..") {
			continue
		}
		u, err := base.Parse(href)
		if err != nil {
			continue
		}
		if u.Host != base.Host {
			continue
		}
		path := strings.TrimPrefix(u.Path, "/")
		if prefix != "" && !strings.HasPrefix(path, prefix+"/") {
			continue
		}
		rel := strings.TrimPrefix(path, prefix+"/")
		if rel == "" || strings.Contains(rel, "/") {
			continue
		}
		out = append(out, path)
	}
	return out, nil
}
