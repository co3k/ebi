package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/co3k/ebi/internal/config"
	"github.com/co3k/ebi/pkg/appmeta"
	"github.com/co3k/ebi/pkg/prefixdb"
	"github.com/co3k/ebi/pkg/schema"
	"github.com/co3k/ebi/pkg/score"
	"github.com/co3k/ebi/pkg/storage"
	"github.com/co3k/ebi/pkg/tlogx"
	"golang.org/x/mod/sumdb/tlog"
)

// remoteStore implements storage.Store by fetching assets from a mirror URL.
// It is used to lazily retrieve checkpoint, tile, and blob data during
// transparency-log verification.
type remoteStore struct {
	mirror string
	client *http.Client
	cache  map[string][]byte
	mu     sync.RWMutex
}

const remoteObjectLimit = int64(1 << 20)

func newRemoteStore(mirror string) *remoteStore {
	return &remoteStore{
		mirror: strings.TrimSuffix(mirror, "/"),
		client: &http.Client{Timeout: 30 * time.Second},
		cache:  make(map[string][]byte),
	}
}

func (r *remoteStore) Get(ctx context.Context, path string) ([]byte, error) {
	r.mu.RLock()
	if data, ok := r.cache[path]; ok {
		r.mu.RUnlock()
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	}
	r.mu.RUnlock()

	url := r.mirror + "/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", appmeta.UserAgent())
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	data, err := readBoundedResponse(resp.Body, remoteObjectLimit)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	r.mu.Lock()
	if r.cache[path] == nil {
		r.cache[path] = make([]byte, len(data))
		copy(r.cache[path], data)
	}
	r.mu.Unlock()
	return data, nil
}

func readBoundedResponse(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

func (r *remoteStore) Put(ctx context.Context, obj storage.Object) error {
	return fmt.Errorf("remoteStore is read-only")
}

func (r *remoteStore) Delete(ctx context.Context, path string) error {
	return fmt.Errorf("remoteStore is read-only")
}

func (r *remoteStore) List(ctx context.Context, prefix string) ([]string, error) {
	return nil, fmt.Errorf("remoteStore does not support listing")
}

func (r *remoteStore) Publish(ctx context.Context, obj storage.Object) error {
	return r.Put(ctx, obj)
}

func (r *remoteStore) Close() error { return nil }

func loadPolicy(cfg config.Config) (tlogx.Policy, error) {
	if cfg.PolicyPath == "" {
		return tlogx.DefaultPolicy(), nil
	}
	return tlogx.LoadPolicy(cfg.PolicyPath)
}

func loadCheckpointState(cfg config.Config) (tlog.Tree, []byte, error) {
	if cfg.CheckpointPath == "" {
		return tlog.Tree{}, nil, nil
	}
	tree, signed, err := tlogx.LoadCheckpointState(cfg.CheckpointPath)
	if err != nil {
		if os.IsNotExist(err) {
			return tlog.Tree{}, nil, nil
		}
		return tlog.Tree{}, nil, err
	}
	return tree, signed, nil
}

func mirrorURL(cfg config.Config) string {
	if cfg.MirrorURL != "" {
		return cfg.MirrorURL
	}
	if len(cfg.ServerURLs) > 0 {
		return cfg.ServerURLs[0]
	}
	return ""
}

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout() || netErr.Temporary()
	}
	return false
}

func fetchMirrorBytes(ctx context.Context, mirror, path string) ([]byte, int, error) {
	url := strings.TrimSuffix(mirror, "/") + "/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", appmeta.UserAgent())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, resp.StatusCode, nil
	}
	data, err := readBoundedResponse(resp.Body, remoteObjectLimit)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("fetch %s: %w", url, err)
	}
	return data, resp.StatusCode, nil
}

func fetchAndVerifyBlob(ctx context.Context, mirror, recordID string) (*schema.Record, error) {
	data, status, err := fetchMirrorBytes(ctx, mirror, "v1/blob/"+recordID)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("blob %s: http %d", recordID, status)
	}
	rec, err := schema.DecodeRecordStrict(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decode blob %s: %w", recordID, err)
	}
	body, _, err := schema.Verify(rec)
	if err != nil {
		return nil, fmt.Errorf("verify blob %s: %w", recordID, err)
	}
	gotID, err := schema.RecordID(*body)
	if err != nil {
		return nil, fmt.Errorf("record id %s: %w", recordID, err)
	}
	if gotID != recordID {
		return nil, fmt.Errorf("record id mismatch: got %s, want %s", gotID, recordID)
	}
	return rec, nil
}

type communityLookup struct {
	Records      []score.VerifiedRecord
	PriorRecords []score.VerifiedRecord
}

type lookupRecord struct {
	entry     prefixdb.Entry
	record    *schema.Record
	isCurrent bool
}

// lookupCommunityRecords fetches community records for the target hash and
// verifies every authenticated step. Any corruption in authenticated material is
// returned as an error so the caller can exit with exitVerifyFail. A plain
// network error is treated as unknown (nil records, nil error) so the caller can
// fall back to local analysis.
func lookupCommunityRecords(ctx context.Context, targetHash string, cfg config.Config) (*communityLookup, error) {
	mirror := mirrorURL(cfg)
	if mirror == "" {
		return &communityLookup{}, nil
	}
	policy, err := loadPolicy(cfg)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	priorTree, _, err := loadCheckpointState(cfg)
	if err != nil {
		return nil, fmt.Errorf("checkpoint state: %w", err)
	}

	var collected []lookupRecord
	visitedTargets := map[string]bool{}
	seenRecords := map[string]bool{}
	var collect func(hash string, depth int, current bool) error
	collect = func(hash string, depth int, current bool) error {
		if depth > score.DeltaMaxDepth || visitedTargets[hash] {
			return nil
		}
		visitedTargets[hash] = true
		prefix := prefixdb.Prefix(hash)
		if prefix == "" {
			return fmt.Errorf("invalid target hash %q", hash)
		}
		shard, status, err := fetchMirrorBytes(ctx, mirror, "v1/prefix/"+prefix)
		if err != nil {
			if isNetworkError(err) && !current {
				return nil
			}
			return fmt.Errorf("lookup shard %s: %w", prefix, err)
		}
		if status == http.StatusNotFound {
			return nil
		}
		if status != http.StatusOK {
			return fmt.Errorf("lookup shard %s: http %d", prefix, status)
		}
		entries, err := prefixdb.MatchExact(shard, hash)
		if err != nil {
			return fmt.Errorf("lookup shard %s: %w", prefix, err)
		}
		for _, entry := range entries {
			if seenRecords[entry.RecordID] {
				continue
			}
			rec, err := fetchAndVerifyBlob(ctx, mirror, entry.RecordID)
			if err != nil {
				if isNetworkError(err) && !current {
					continue
				}
				return err
			}
			if rec.Body.Type != schema.SchemaAuditV1 || rec.Body.Target.SHA256 != hash {
				return fmt.Errorf("record %s target/type mismatch", entry.RecordID)
			}
			seenRecords[entry.RecordID] = true
			collected = append(collected, lookupRecord{entry: entry, record: rec, isCurrent: current})
			if rec.Body.PrevSHA256 != "" {
				if err := collect(rec.Body.PrevSHA256, depth+1, false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := collect(targetHash, 0, true); err != nil {
		if isNetworkError(err) {
			return &communityLookup{}, nil
		}
		return nil, err
	}
	if len(collected) == 0 {
		return &communityLookup{}, nil
	}

	// Fetch and verify the latest checkpoint once, then verify inclusion for each entry.
	store := newRemoteStore(mirror)
	cp, status, err := fetchMirrorBytes(ctx, mirror, storage.CheckpointPath())
	if err != nil {
		if isNetworkError(err) {
			return &communityLookup{}, nil
		}
		return nil, fmt.Errorf("checkpoint: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("checkpoint: http %d", status)
	}
	store.mu.Lock()
	store.cache[storage.CheckpointPath()] = cp
	store.mu.Unlock()
	tree, _, err := tlogx.VerifyCheckpointState(cp, priorTree, policy, store)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: %w", err)
	}

	result := &communityLookup{}
	for _, item := range collected {
		leaf, err := tlogx.RecordToLeaf(*item.record)
		if err != nil {
			return nil, fmt.Errorf("record %s leaf: %w", item.entry.RecordID, err)
		}
		lh, err := tlogx.LeafHash(leaf)
		if err != nil {
			return nil, fmt.Errorf("record %s leaf hash: %w", item.entry.RecordID, err)
		}
		if err := tlogx.VerifyInclusionAt(store, item.entry.LogIndex, lh, tree, policy); err != nil {
			return nil, fmt.Errorf("record %s inclusion: %w", item.entry.RecordID, err)
		}
		verified := verifiedRecordFrom(item.record, item.entry.RecordID)
		if item.isCurrent {
			result.Records = append(result.Records, verified)
		} else {
			result.PriorRecords = append(result.PriorRecords, verified)
		}
	}
	if cfg.CheckpointPath != "" {
		if err := tlogx.SaveCheckpointState(cfg.CheckpointPath, tree, cp); err != nil {
			return nil, fmt.Errorf("persist checkpoint: %w", err)
		}
	}

	return result, nil
}

func verifiedRecordFrom(rec *schema.Record, id string) score.VerifiedRecord {
	return score.VerifiedRecord{
		ID:        id,
		AuditorID: schema.AuditorHash(rec.PublicKey),
		Body:      rec.Body,
		PublicKey: rec.PublicKey,
		Signature: rec.Signature,
	}
}

// verifyRemoteRecordByID verifies a remote record given only its record ID. It
// fetches the blob, then derives the target hash to find the prefix entry and
// log index, then verifies the checkpoint and inclusion proof.
func verifyRemoteRecordByID(ctx context.Context, recordID string, cfg config.Config) error {
	mirror := mirrorURL(cfg)
	if mirror == "" {
		return fmt.Errorf("no mirror configured for remote verification")
	}
	policy, err := loadPolicy(cfg)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	priorTree, _, err := loadCheckpointState(cfg)
	if err != nil {
		return fmt.Errorf("checkpoint state: %w", err)
	}

	rec, err := fetchAndVerifyBlob(ctx, mirror, recordID)
	if err != nil {
		return err
	}
	store := newRemoteStore(mirror)
	cp, status, err := fetchMirrorBytes(ctx, mirror, storage.CheckpointPath())
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("checkpoint: http %d", status)
	}
	store.cache[storage.CheckpointPath()] = cp
	tree, _, err := tlogx.VerifyCheckpointState(cp, priorTree, policy, store)
	if err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}

	logIndex, err := findRemoteRecordIndex(ctx, mirror, tree.N, recordID, rec)
	if err != nil {
		return err
	}
	leaf, err := tlogx.RecordToLeaf(*rec)
	if err != nil {
		return fmt.Errorf("record %s leaf: %w", recordID, err)
	}
	leafHash, err := tlogx.LeafHash(leaf)
	if err != nil {
		return fmt.Errorf("record %s leaf hash: %w", recordID, err)
	}
	if err := tlogx.VerifyInclusionAt(store, logIndex, leafHash, tree, policy); err != nil {
		return fmt.Errorf("record %s inclusion: %w", recordID, err)
	}
	if cfg.CheckpointPath != "" {
		if err := tlogx.SaveCheckpointState(cfg.CheckpointPath, tree, cp); err != nil {
			return fmt.Errorf("persist checkpoint: %w", err)
		}
	}
	return nil
}

func findRemoteRecordIndex(ctx context.Context, mirror string, treeSize int64, recordID string, rec *schema.Record) (int64, error) {
	if rec.Body.Type == schema.SchemaAuditV1 && rec.Body.Target.SHA256 != "" {
		prefix := prefixdb.Prefix(rec.Body.Target.SHA256)
		if prefix == "" {
			return -1, fmt.Errorf("record %s has invalid target hash", recordID)
		}
		shard, status, err := fetchMirrorBytes(ctx, mirror, "v1/prefix/"+prefix)
		if err != nil {
			return -1, err
		}
		if status == http.StatusOK {
			entries, err := prefixdb.MatchExact(shard, rec.Body.Target.SHA256)
			if err != nil {
				return -1, fmt.Errorf("prefix lookup: %w", err)
			}
			for _, entry := range entries {
				if entry.RecordID == recordID {
					return entry.LogIndex, nil
				}
			}
		} else if status != http.StatusNotFound {
			return -1, fmt.Errorf("prefix lookup: http %d", status)
		}
	}

	// Retractions, moderation records, and audits removed from a mutable shard
	// do not have a target-prefix reverse index. Scan the authenticated
	// append-order index as the portable fallback.
	for index := int64(0); index < treeSize; index++ {
		path := fmt.Sprintf("v1/leaf/%d", index)
		data, status, err := fetchMirrorBytes(ctx, mirror, path)
		if err != nil {
			return -1, err
		}
		if status != http.StatusOK {
			return -1, fmt.Errorf("leaf index %d: http %d", index, status)
		}
		entry, _, err := tlogx.DecodeLeafIndex(path, data)
		if err != nil {
			return -1, fmt.Errorf("leaf index %d: %w", index, err)
		}
		if entry.RecordID == recordID {
			return index, nil
		}
	}
	return -1, fmt.Errorf("record %s not found in append-order index", recordID)
}
