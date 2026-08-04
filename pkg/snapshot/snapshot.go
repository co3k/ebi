// Package snapshot creates and verifies tar.zst snapshots of the log data.
package snapshot

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/co3k/ebi/pkg/prefixdb"
	"github.com/co3k/ebi/pkg/schema"
	"github.com/co3k/ebi/pkg/score"
	"github.com/co3k/ebi/pkg/storage"
	"github.com/co3k/ebi/pkg/tlogx"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/mod/sumdb/tlog"
)

// Default archive limits.
const (
	DefaultMaxTotalBytes = 1 << 30   // 1 GiB
	DefaultMaxFileBytes  = 100 << 20 // 100 MiB
	DefaultMaxFileCount  = 1_000_000

	metadataPath   = "snapshot.json"
	datasetPath    = "dataset/records.jsonl"
	scorePath      = "v1/score/params.json"
	checkpointPath = "v1/checkpoint"
	blobPrefix     = "v1/blob/"
	leafPrefix     = "v1/leaf/"
	tilePrefix     = "v1/tile/"
	prefixPrefix   = "v1/prefix/"
)

// ManifestEntry describes a single file in the snapshot archive.
type ManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Metadata describes a snapshot. SHA256 is the digest of the complete
// compressed archive; the JSON snapshot.json file uses the "sha256" field for
// the manifest digest to avoid self-reference.
type Metadata struct {
	SHA256         string          `json:"-"`
	CompressedSize int64           `json:"-"`
	Size           int64           `json:"size"`
	TreeSize       int64           `json:"tree_size"`
	Checkpoint     string          `json:"checkpoint"`
	Origin         string          `json:"origin"`
	CreatedAt      string          `json:"created_at"`
	Manifest       []ManifestEntry `json:"manifest"`
}

// Latest describes the public v1/snapshot/latest.json pointer. Size is the
// compressed archive size; Mirrors may contain equivalent archive URLs.
type Latest struct {
	URL        string   `json:"url"`
	Mirrors    []string `json:"mirrors,omitempty"`
	Size       int64    `json:"size"`
	TreeSize   int64    `json:"tree_size"`
	SHA256     string   `json:"sha256"`
	Checkpoint string   `json:"checkpoint"`
}

// Limits control the size of a snapshot archive.
type Limits struct {
	TotalBytes int64
	FileBytes  int64
	FileCount  int64
}

// DefaultLimits returns the built-in size limits.
func DefaultLimits() Limits {
	return Limits{
		TotalBytes: DefaultMaxTotalBytes,
		FileBytes:  DefaultMaxFileBytes,
		FileCount:  DefaultMaxFileCount,
	}
}

// Create writes a tar.zst snapshot of the storage root to w.
// The returned Metadata.SHA256 is the digest of the final compressed archive.
func Create(ctx context.Context, store storage.Store, treeSize int64, checkpoint string, w io.Writer) (*Metadata, error) {
	return CreateWithLimits(ctx, store, treeSize, checkpoint, w, DefaultLimits())
}

// CreateWithLimits writes a tar.zst snapshot with explicit size limits.
func CreateWithLimits(ctx context.Context, store storage.Store, treeSize int64, checkpoint string, w io.Writer, limits Limits) (*Metadata, error) {
	if limits.TotalBytes <= 0 {
		limits.TotalBytes = DefaultMaxTotalBytes
	}
	if limits.FileBytes <= 0 {
		limits.FileBytes = DefaultMaxFileBytes
	}
	if limits.FileCount <= 0 {
		limits.FileCount = DefaultMaxFileCount
	}

	records, err := loadRecords(ctx, store, treeSize)
	if err != nil {
		return nil, fmt.Errorf("load records: %w", err)
	}
	if err := validateTombstoneBindings(records); err != nil {
		return nil, fmt.Errorf("validate tombstones: %w", err)
	}
	if err := verifyCheckpointAgainstRecords(checkpoint, treeSize, records); err != nil {
		return nil, fmt.Errorf("checkpoint does not match records: %w", err)
	}

	leafFiles, err := buildLeafFiles(records)
	if err != nil {
		return nil, fmt.Errorf("build leaf files: %w", err)
	}
	recordsJSONL, err := buildRecordsJSONL(records)
	if err != nil {
		return nil, fmt.Errorf("build records dataset: %w", err)
	}
	scoreParams := buildScoreParams()
	prefixShards, err := buildPrefixShards(records)
	if err != nil {
		return nil, fmt.Errorf("build prefix shards: %w", err)
	}
	leafBlobIDs := make(map[string]struct{}, len(records))
	referencedArtifactIDs := make(map[string]struct{})
	for _, record := range records {
		leafBlobIDs[record.id] = struct{}{}
		if record.rec == nil || record.rec.Body.Type != schema.SchemaAuditV1 {
			continue
		}
		referencedArtifactIDs[record.rec.Body.Target.SHA256] = struct{}{}
		if record.rec.Body.Analyzer.Kind == schema.KindLLM {
			referencedArtifactIDs[record.rec.Body.Analyzer.PromptSHA256] = struct{}{}
		}
	}

	generated := map[string]struct{}{
		datasetPath: {},
		scorePath:   {},
	}
	for path := range leafFiles {
		generated[path] = struct{}{}
	}
	for path := range prefixShards {
		generated[path] = struct{}{}
	}

	var entries []archiveEntry
	keys, err := store.List(ctx, "v1")
	if err != nil {
		return nil, fmt.Errorf("list store: %w", err)
	}
	for _, key := range keys {
		// Derived indexes are regenerated from the authenticated append-order
		// leaves. Never carry stale prefix/leaf/score objects into a snapshot.
		if strings.HasPrefix(key, leafPrefix) ||
			strings.HasPrefix(key, prefixPrefix) ||
			key == scorePath {
			continue
		}
		// Snapshots contain the public log dataset only. Operational state and
		// mismatch reports (v1/lease, v1/pending, v1/reports, staged witness
		// files, nested snapshots) must never be distributed accidentally.
		if key != checkpointPath &&
			!strings.HasPrefix(key, tilePrefix) &&
			!strings.HasPrefix(key, blobPrefix) {
			continue
		}
		if _, ok := generated[key]; ok {
			continue
		}
		if strings.HasPrefix(key, blobPrefix) {
			id := strings.TrimPrefix(key, blobPrefix)
			if _, leafBlob := leafBlobIDs[id]; !leafBlob {
				if _, referenced := referencedArtifactIDs[id]; !referenced {
					// Orphan artifacts may exist transiently after a rejected
					// submission. Do not distribute archives the verifier
					// correctly rejects as containing unreferenced content.
					continue
				}
			}
		}
		data, err := store.Get(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", key, err)
		}
		if key == checkpointPath && string(data) != checkpoint {
			return nil, fmt.Errorf("stored checkpoint differs from requested checkpoint")
		}
		entries = append(entries, archiveEntry{path: key, data: data})
	}

	for path, data := range leafFiles {
		entries = append(entries, archiveEntry{path: path, data: data})
	}
	entries = append(entries, archiveEntry{path: datasetPath, data: recordsJSONL})
	entries = append(entries, archiveEntry{path: scorePath, data: scoreParams})
	for path, data := range prefixShards {
		entries = append(entries, archiveEntry{path: path, data: data})
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })

	origin := checkpointOrigin(checkpoint)
	createdAt := time.Now().UTC().Format(time.RFC3339)

	h := sha256.New()
	cw := &countedWriter{}
	zw, err := zstd.NewWriter(io.MultiWriter(w, h, cw), zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return nil, fmt.Errorf("zstd writer: %w", err)
	}
	defer zw.Close()
	tw := tar.NewWriter(zw)
	defer tw.Close()

	var manifest []ManifestEntry
	var fileCount int64
	var totalSize int64

	for _, e := range entries {
		if err := validatePath(e.path); err != nil {
			return nil, fmt.Errorf("invalid path %s: %w", e.path, err)
		}
		if int64(len(e.data)) > limits.FileBytes {
			return nil, fmt.Errorf("file %s exceeds max file size %d", e.path, limits.FileBytes)
		}
		fileCount++
		if fileCount > limits.FileCount {
			return nil, fmt.Errorf("file count exceeds max %d", limits.FileCount)
		}
		header := &tar.Header{
			Name:     e.path,
			Mode:     0644,
			Size:     int64(len(e.data)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(header); err != nil {
			return nil, fmt.Errorf("write header %s: %w", e.path, err)
		}
		if _, err := tw.Write(e.data); err != nil {
			return nil, fmt.Errorf("write %s: %w", e.path, err)
		}
		if err := tw.Flush(); err != nil {
			return nil, fmt.Errorf("flush tar: %w", err)
		}
		if err := zw.Flush(); err != nil {
			return nil, fmt.Errorf("flush zstd: %w", err)
		}
		if cw.n > limits.TotalBytes {
			return nil, fmt.Errorf("archive exceeds max total size %d", limits.TotalBytes)
		}
		manifest = append(manifest, ManifestEntry{
			Path:   e.path,
			SHA256: storage.ContentHash(e.data),
			Size:   int64(len(e.data)),
		})
		totalSize += int64(len(e.data))
	}

	manifestDigest := digestManifest(manifest)

	snapshotJSON := struct {
		SHA256     string          `json:"sha256"`
		Size       int64           `json:"size"`
		TreeSize   int64           `json:"tree_size"`
		Checkpoint string          `json:"checkpoint"`
		Origin     string          `json:"origin"`
		CreatedAt  string          `json:"created_at"`
		Manifest   []ManifestEntry `json:"manifest"`
	}{
		SHA256:     manifestDigest,
		TreeSize:   treeSize,
		Checkpoint: checkpoint,
		Origin:     origin,
		CreatedAt:  createdAt,
		Manifest:   append([]ManifestEntry(nil), manifest...),
	}
	// Size includes metadata bytes; iterate because the size value affects the JSON length.
	size := totalSize
	var metaBytes []byte
	for {
		snapshotJSON.Size = size
		b, err := json.MarshalIndent(snapshotJSON, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal metadata: %w", err)
		}
		b = append(b, '\n')
		newSize := totalSize + int64(len(b))
		if newSize == size {
			metaBytes = b
			break
		}
		size = newSize
	}

	if int64(len(metaBytes)) > limits.FileBytes {
		return nil, fmt.Errorf("metadata file exceeds max file size %d", limits.FileBytes)
	}
	fileCount++
	if fileCount > limits.FileCount {
		return nil, fmt.Errorf("file count exceeds max %d", limits.FileCount)
	}
	metaHeader := &tar.Header{
		Name:     metadataPath,
		Mode:     0644,
		Size:     int64(len(metaBytes)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(metaHeader); err != nil {
		return nil, fmt.Errorf("write metadata header: %w", err)
	}
	if _, err := tw.Write(metaBytes); err != nil {
		return nil, fmt.Errorf("write metadata: %w", err)
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close zstd: %w", err)
	}
	if cw.n > limits.TotalBytes {
		return nil, fmt.Errorf("archive exceeds max total size %d", limits.TotalBytes)
	}

	totalSize += int64(len(metaBytes))
	sort.Slice(manifest, func(i, j int) bool { return manifest[i].Path < manifest[j].Path })

	return &Metadata{
		SHA256:         hex.EncodeToString(h.Sum(nil)),
		CompressedSize: cw.n,
		Size:           size,
		TreeSize:       treeSize,
		Checkpoint:     checkpoint,
		Origin:         origin,
		CreatedAt:      createdAt,
		Manifest:       manifest,
	}, nil
}

// LatestJSON returns deterministic JSON for the public latest snapshot pointer.
func LatestJSON(meta *Metadata, archiveURL string, mirrors []string) ([]byte, error) {
	if meta == nil {
		return nil, fmt.Errorf("snapshot metadata is required")
	}
	if archiveURL == "" {
		return nil, fmt.Errorf("snapshot URL is required")
	}
	if !schema.IsHexHash(meta.SHA256) || meta.CompressedSize <= 0 || meta.TreeSize < 0 || meta.Checkpoint == "" {
		return nil, fmt.Errorf("snapshot metadata is incomplete")
	}
	cleanMirrors := make([]string, 0, len(mirrors))
	seen := map[string]bool{archiveURL: true}
	for _, mirror := range mirrors {
		mirror = strings.TrimSpace(mirror)
		if mirror == "" || seen[mirror] {
			continue
		}
		seen[mirror] = true
		cleanMirrors = append(cleanMirrors, mirror)
	}
	sort.Strings(cleanMirrors)
	data, err := json.Marshal(Latest{
		URL:        archiveURL,
		Mirrors:    cleanMirrors,
		Size:       meta.CompressedSize,
		TreeSize:   meta.TreeSize,
		SHA256:     meta.SHA256,
		Checkpoint: meta.Checkpoint,
	})
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// VerifyArchive performs safety checks and verifies the archive digest against want.
func VerifyArchive(r io.Reader, want *Metadata) error {
	info, err := readArchive(r, DefaultLimits())
	if err != nil {
		return err
	}
	return verifyArchiveDigest(info, want)
}

// Verify reads a tar.zst snapshot from r and verifies it.
// If want is non-nil, the archive digest is checked. If policy and checkpointPath
// are provided, the checkpoint signature and tree consistency are verified.
func Verify(r io.Reader, want *Metadata, policy *tlogx.Policy, checkpointPath string) error {
	limits := DefaultLimits()
	info, err := readArchive(r, limits)
	if err != nil {
		return err
	}
	if err := verifyArchiveDigest(info, want); err != nil {
		return err
	}
	if err := verifyMetadataDigest(info, want); err != nil {
		return err
	}
	if policy != nil {
		cp := checkpointPath
		if cp == "" {
			cp = checkpointPath
		}
		if err := verifyTree(info, *policy, cp); err != nil {
			return fmt.Errorf("tree verification: %w", err)
		}
		if err := verifyRecordsAndPrefix(info, limits); err != nil {
			return fmt.Errorf("record/prefix verification: %w", err)
		}
	}
	return nil
}

// ImportMirror copies all signed tree assets from the archive to store as-is.
// It returns the parsed metadata so the caller can verify the archive digest.
func ImportMirror(r io.Reader, store storage.Store) (*Metadata, error) {
	info, err := readArchive(r, DefaultLimits())
	if err != nil {
		return nil, err
	}
	if err := verifyMetadataDigest(info, nil); err != nil {
		return nil, err
	}
	if err := verifyRecordsAndPrefix(info, DefaultLimits()); err != nil {
		return nil, fmt.Errorf("record/prefix verification: %w", err)
	}
	return importMirrorInfo(info, store)
}

// ImportMirrorWithPolicy additionally authenticates the checkpoint, tiles, and
// every leaf against policy before copying the original signed log assets.
func ImportMirrorWithPolicy(r io.Reader, store storage.Store, policy tlogx.Policy) (*Metadata, error) {
	info, err := readArchive(r, DefaultLimits())
	if err != nil {
		return nil, err
	}
	if err := verifyMetadataDigest(info, nil); err != nil {
		return nil, err
	}
	if err := verifyTree(info, policy, checkpointPath); err != nil {
		return nil, fmt.Errorf("tree verification: %w", err)
	}
	if err := verifyRecordsAndPrefix(info, DefaultLimits()); err != nil {
		return nil, fmt.Errorf("record/prefix verification: %w", err)
	}
	return importMirrorInfo(info, store)
}

func importMirrorInfo(info *archiveInfo, store storage.Store) (*Metadata, error) {
	for path, e := range info.entries {
		if !strings.HasPrefix(path, "v1/") {
			continue
		}
		if err := store.Put(context.Background(), storage.Object{
			Path:        path,
			Data:        e.data,
			ContentType: "application/octet-stream",
		}); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
	}
	return metadataFromInfo(info)
}

// ImportFork verifies every record in the archive and then re-sequences them by
// appending to the provided store using callback. The callback is invoked once
// per record, in leaf-index order, with the 0-based index. The callback should
// write the record blob, leaf index, and any other derived assets (tiles,
// checkpoint) to store.
func ImportFork(r io.Reader, store storage.Store, policy *tlogx.Policy, callback func(rec schema.Record, index int64) error) (*Metadata, error) {
	_ = store // the callback is responsible for writing to the store
	if policy == nil {
		return nil, fmt.Errorf("fork import requires an authenticated trust policy")
	}
	if callback == nil {
		return nil, fmt.Errorf("fork import callback is required")
	}
	limits := DefaultLimits()
	info, err := readArchive(r, limits)
	if err != nil {
		return nil, err
	}
	if err := verifyMetadataDigest(info, nil); err != nil {
		return nil, err
	}
	if err := verifyTree(info, *policy, checkpointPath); err != nil {
		return nil, fmt.Errorf("tree verification: %w", err)
	}
	if err := verifyRecordsAndPrefix(info, limits); err != nil {
		return nil, fmt.Errorf("record/prefix verification: %w", err)
	}

	records, err := recordsFromInfo(info, limits)
	if err != nil {
		return nil, err
	}

	leafIDs, err := leafIndexFromInfo(info)
	if err != nil {
		return nil, err
	}
	recordByID := map[string]schema.Record{}
	for _, rec := range records {
		id, err := schema.RecordID(rec.Body)
		if err != nil {
			return nil, fmt.Errorf("record id: %w", err)
		}
		recordByID[id] = rec
	}
	for i, id := range leafIDs {
		rec, ok := recordByID[id]
		if !ok {
			return nil, fmt.Errorf("record %s not found", id)
		}
		if err := callback(rec, int64(i)); err != nil {
			return nil, fmt.Errorf("callback at index %d: %w", i, err)
		}
	}

	return metadataFromInfo(info)
}

// Extract extracts the archive to the local directory dest.
// It rejects symlinks, hard links, and traversal paths, and enforces maxBytes.
func Extract(r io.Reader, dest string, maxBytes int64) error {
	local, err := storage.NewLocal(dest)
	if err != nil {
		return fmt.Errorf("local store: %w", err)
	}
	info, err := readArchive(r, Limits{
		TotalBytes: maxBytes,
		FileBytes:  maxBytes,
		FileCount:  DefaultMaxFileCount,
	})
	if err != nil {
		return err
	}
	var written int64
	for _, e := range info.entries {
		if written+int64(len(e.data)) > maxBytes {
			return fmt.Errorf("extraction exceeds max bytes %d", maxBytes)
		}
		if err := local.Put(context.Background(), storage.Object{
			Path: e.path,
			Data: e.data,
		}); err != nil {
			return fmt.Errorf("extract %s: %w", e.path, err)
		}
		written += int64(len(e.data))
	}
	return nil
}

// archiveEntry is a single file read from an archive.
type archiveEntry struct {
	path string
	data []byte
	size int64
	hash string
}

// archiveInfo holds the result of reading an archive.
type archiveInfo struct {
	size    int64
	hash    string
	entries map[string]archiveEntry
}

// countedWriter counts bytes written to an underlying writer.
type countedWriter struct {
	w io.Writer
	n int64
}

func (cw *countedWriter) Write(p []byte) (int, error) {
	if cw.w != nil {
		n, err := cw.w.Write(p)
		cw.n += int64(n)
		return n, err
	}
	cw.n += int64(len(p))
	return len(p), nil
}

// loadRecords reads records in the authoritative append order from v1/leaf.
// Every malformed index/blob is an error; no log object is silently skipped.
func loadRecords(ctx context.Context, store storage.Store, treeSize int64) ([]indexedRecord, error) {
	idxs, err := tlogx.LoadLeafIndexes(ctx, store)
	if err != nil {
		return nil, err
	}
	if treeSize < 0 {
		return nil, fmt.Errorf("negative tree size %d", treeSize)
	}
	if int64(len(idxs)) != treeSize {
		return nil, fmt.Errorf("leaf index count %d does not match tree size %d", len(idxs), treeSize)
	}

	records := make([]indexedRecord, 0, len(idxs))
	for _, idx := range idxs {
		leafHash, err := tlogx.LeafIndexHash(idx)
		if err != nil {
			return nil, err
		}
		path := blobPrefix + idx.RecordID
		data, err := store.Get(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		if tombstone, ok, err := tlogx.DecodeTombstoneBlob(data, idx.RecordID); err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		} else if ok {
			records = append(records, indexedRecord{
				index:     idx.Index,
				id:        idx.RecordID,
				leafHash:  leafHash,
				tombstone: tombstone,
				blob:      append([]byte(nil), data...),
			})
			continue
		}

		rec, err := schema.DecodeRecordStrict(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		body, _, err := schema.Verify(rec)
		if err != nil {
			return nil, fmt.Errorf("verify %s: %w", path, err)
		}
		id, err := schema.RecordID(*body)
		if err != nil {
			return nil, fmt.Errorf("record id %s: %w", path, err)
		}
		if id != idx.RecordID {
			return nil, fmt.Errorf("blob %s contains record %s", idx.RecordID, id)
		}
		leaf, err := tlogx.RecordToLeaf(*rec)
		if err != nil {
			return nil, fmt.Errorf("record to leaf %s: %w", path, err)
		}
		lh, err := tlogx.LeafHash(leaf)
		if err != nil {
			return nil, fmt.Errorf("leaf hash %s: %w", path, err)
		}
		if lh != leafHash {
			return nil, fmt.Errorf("leaf index %d hash does not match record %s", idx.Index, idx.RecordID)
		}
		records = append(records, indexedRecord{
			index:    idx.Index,
			rec:      rec,
			id:       id,
			leafHash: lh,
			blob:     append([]byte(nil), data...),
		})
	}
	return records, nil
}

// indexedRecord is a verified record with its leaf hash.
type indexedRecord struct {
	index     int64
	rec       *schema.Record
	id        string
	leafHash  tlog.Hash
	tombstone *tlogx.Tombstone
	blob      []byte
}

// buildLeafFiles creates v1/leaf/<index> files matching tlogx leafIndex.
func buildLeafFiles(records []indexedRecord) (map[string][]byte, error) {
	out := make(map[string][]byte, len(records))
	for _, r := range records {
		path := fmt.Sprintf("%s%d", leafPrefix, r.index)
		data, err := leafIndexJSON(r.index, r.leafHash, r.id)
		if err != nil {
			return nil, err
		}
		out[path] = data
	}
	return out, nil
}

func leafIndexJSON(index int64, leafHash tlog.Hash, recordID string) ([]byte, error) {
	doc := tlogx.LeafIndex{
		Index:    index,
		Leaf:     tlogx.Base64Hash(leafHash),
		RecordID: recordID,
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// datasetLine preserves one line per Merkle leaf. A tombstone line explicitly
// identifies the deleted record and binds the exact marker hash; normal lines
// contain the signed record envelope.
type datasetLine struct {
	Index           int64          `json:"index"`
	RecordID        string         `json:"record_id"`
	Record          *schema.Record `json:"record,omitempty"`
	Tombstone       bool           `json:"tombstone,omitempty"`
	TombstoneSHA256 string         `json:"tombstone_sha256,omitempty"`
}

// buildRecordsJSONL builds a JSONL dataset ordered by the real leaf index.
func buildRecordsJSONL(records []indexedRecord) ([]byte, error) {
	var buf strings.Builder
	for _, r := range records {
		line := datasetLine{Index: r.index, RecordID: r.id, Record: r.rec}
		if r.tombstone != nil {
			line.Record = nil
			line.Tombstone = true
			line.TombstoneSHA256 = tlogx.TombstoneSHA256(r.blob)
		}
		b, err := json.Marshal(line)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return []byte(buf.String()), nil
}

func verifyCheckpointAgainstRecords(checkpoint string, treeSize int64, records []indexedRecord) error {
	tree := tlogx.NewTree()
	for _, record := range records {
		if err := tree.Append(record.leafHash); err != nil {
			return fmt.Errorf("append leaf %d: %w", record.index, err)
		}
	}
	if tree.Size() != treeSize {
		return fmt.Errorf("rebuilt tree size %d, want %d", tree.Size(), treeSize)
	}
	checkpointTree, _, err := tlogx.ParseCheckpoint([]byte(checkpoint))
	if err != nil {
		return err
	}
	if checkpointTree.N != treeSize || checkpointTree.Hash != tree.Root() {
		return fmt.Errorf("checkpoint tree %d/%s, rebuilt tree %d/%s",
			checkpointTree.N, checkpointTree.Hash, tree.Size(), tree.Root())
	}
	return nil
}

// buildScoreParams returns a JSON document with the current scoring parameters.
func buildScoreParams() []byte {
	params := struct {
		Version                      string             `json:"version"`
		TrustDefault                 float64            `json:"trust_default"`
		PositiveMultiplierBase       float64            `json:"positive_multiplier_base"`
		FamilyDiversityBonusPerExtra float64            `json:"family_diversity_bonus_per_extra"`
		FamilyDiversityBonusMax      float64            `json:"family_diversity_bonus_max"`
		NegativeMultiplier           float64            `json:"negative_multiplier"`
		TrustedPositiveThreshold     float64            `json:"trusted_positive_threshold"`
		DeltaInheritanceCoefficient  float64            `json:"delta_inheritance_coefficient"`
		DeltaMaxDepth                int                `json:"delta_max_depth"`
		Severity                     map[string]float64 `json:"severity"`
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
		Severity:                     score.Severity,
	}
	b, _ := json.MarshalIndent(params, "", "  ")
	b = append(b, '\n')
	return b
}

// buildPrefixShards builds prefix lookup shard files after applying valid retractions.
func buildPrefixShards(records []indexedRecord) (map[string][]byte, error) {
	recs, indices := indexedAuditRecords(records)
	recs, indices = applyRetractionsWithIndex(recs, indices, recordsToSchema(records))
	shards, err := prefixdb.BuildShardsWithIndex(recs, indices)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(shards))
	for prefix, data := range shards {
		out[prefixPrefix+prefix] = data
	}
	return out, nil
}

// recordsToSchema strips indexedRecord wrappers.
func recordsToSchema(records []indexedRecord) []schema.Record {
	out := make([]schema.Record, 0, len(records))
	for _, r := range records {
		if r.rec != nil {
			out = append(out, *r.rec)
		}
	}
	return out
}

func indexedAuditRecords(records []indexedRecord) ([]schema.Record, []int64) {
	recs := make([]schema.Record, 0, len(records))
	indices := make([]int64, 0, len(records))
	for _, r := range records {
		if r.rec == nil || r.rec.Body.Type != schema.SchemaAuditV1 {
			continue
		}
		recs = append(recs, *r.rec)
		indices = append(indices, r.index)
	}
	return recs, indices
}

func applyRetractionsWithIndex(audits []schema.Record, indices []int64, all []schema.Record) ([]schema.Record, []int64) {
	retractions := make([]schema.Record, 0)
	for _, rec := range all {
		if rec.Body.Type == schema.SchemaRetractV1 {
			retractions = append(retractions, rec)
		}
	}
	kept := make([]schema.Record, 0, len(audits))
	keptIndices := make([]int64, 0, len(indices))
	for i, audit := range audits {
		retracted := false
		for j := range retractions {
			if schema.RetractionMatchesTarget(&retractions[j], &audit) {
				retracted = true
				break
			}
		}
		if !retracted {
			kept = append(kept, audit)
			keptIndices = append(keptIndices, indices[i])
		}
	}
	return kept, keptIndices
}

func validateTombstoneBindings(records []indexedRecord) error {
	moderations := make([]indexedRecord, 0)
	for _, r := range records {
		if r.rec != nil && r.rec.Body.Type == schema.SchemaModerationV1 {
			moderations = append(moderations, r)
		}
	}
	for _, original := range records {
		if original.tombstone == nil {
			continue
		}
		hash := tlogx.TombstoneSHA256(original.blob)
		found := false
		for _, moderation := range moderations {
			body := moderation.rec.Body
			if moderation.index > original.index &&
				body.Reason == "tombstone" &&
				body.BlobSHA256 == original.id &&
				body.TombstoneSHA256 == hash {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("tombstoned record %s at index %d has no later matching moderation record", original.id, original.index)
		}
	}
	return nil
}

// applyRetractions removes audit records that have a valid retraction.
func applyRetractions(records []schema.Record) []schema.Record {
	retractions := make([]*schema.Record, 0)
	for i := range records {
		if records[i].Body.Type == schema.SchemaRetractV1 {
			retractions = append(retractions, &records[i])
		}
	}
	if len(retractions) == 0 {
		return records
	}
	out := make([]schema.Record, 0, len(records))
	for i := range records {
		if records[i].Body.Type == schema.SchemaRetractV1 {
			continue
		}
		retracted := false
		for _, retr := range retractions {
			if schema.RetractionMatchesTarget(retr, &records[i]) {
				retracted = true
				break
			}
		}
		if !retracted {
			out = append(out, records[i])
		}
	}
	return out
}

// filterWithTarget keeps records that have a target hash.
func filterWithTarget(records []schema.Record) []schema.Record {
	out := make([]schema.Record, 0, len(records))
	for _, rec := range records {
		if rec.Body.Target.SHA256 != "" && schema.IsHexHash(rec.Body.Target.SHA256) {
			out = append(out, rec)
		}
	}
	return out
}

// digestManifest returns the SHA-256 hex digest of the manifest entries,
// excluding the snapshot metadata file itself.
func digestManifest(entries []ManifestEntry) string {
	payload := make([]ManifestEntry, 0, len(entries))
	for _, e := range entries {
		if e.Path == metadataPath {
			continue
		}
		payload = append(payload, e)
	}
	b, _ := json.Marshal(payload)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// checkpointOrigin extracts the first line of the checkpoint text.
func checkpointOrigin(checkpoint string) string {
	checkpoint = strings.TrimSpace(checkpoint)
	if idx := strings.IndexByte(checkpoint, '\n'); idx >= 0 {
		return checkpoint[:idx]
	}
	return checkpoint
}

// validatePath rejects absolute paths, traversal, and empty paths.
func validatePath(path string) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	if filepath.IsAbs(path) {
		return fmt.Errorf("absolute path: %s", path)
	}
	cleaned := filepath.Clean(filepath.ToSlash(path))
	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, "../") {
		return fmt.Errorf("traversal path: %s", path)
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return fmt.Errorf("traversal path: %s", path)
		}
	}
	return nil
}

// isRegular reports whether a tar header is a regular file.
func isRegular(h *tar.Header) bool {
	return h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA
}

// readArchive reads and validates a tar.zst archive.
func readArchive(r io.Reader, limits Limits) (*archiveInfo, error) {
	if limits.TotalBytes <= 0 {
		limits.TotalBytes = DefaultMaxTotalBytes
	}
	if limits.FileBytes <= 0 {
		limits.FileBytes = DefaultMaxFileBytes
	}
	if limits.FileCount <= 0 {
		limits.FileCount = DefaultMaxFileCount
	}

	h := sha256.New()
	cw := &countedWriter{}
	zr, err := zstd.NewReader(io.TeeReader(r, io.MultiWriter(h, cw)))
	if err != nil {
		return nil, fmt.Errorf("zstd reader: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	entries := make(map[string]archiveEntry)
	var count int64
	var totalUncompressed int64

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar header: %w", err)
		}
		if err := validatePath(header.Name); err != nil {
			return nil, fmt.Errorf("unsafe path %s: %w", header.Name, err)
		}
		if !isRegular(header) {
			return nil, fmt.Errorf("non-regular entry %s (type=%d)", header.Name, header.Typeflag)
		}
		if _, ok := entries[header.Name]; ok {
			return nil, fmt.Errorf("duplicate path: %s", header.Name)
		}
		count++
		if count > limits.FileCount {
			return nil, fmt.Errorf("file count exceeds max %d", limits.FileCount)
		}
		if header.Size < 0 || header.Size > limits.FileBytes {
			return nil, fmt.Errorf("file %s size %d exceeds max %d", header.Name, header.Size, limits.FileBytes)
		}
		if header.Size > limits.TotalBytes-totalUncompressed {
			return nil, fmt.Errorf("archive uncompressed size exceeds max %d", limits.TotalBytes)
		}
		data := make([]byte, header.Size)
		if _, err := io.ReadFull(tr, data); err != nil {
			return nil, fmt.Errorf("read %s: %w", header.Name, err)
		}
		entries[header.Name] = archiveEntry{
			path: header.Name,
			data: data,
			size: int64(len(data)),
			hash: storage.ContentHash(data),
		}
		totalUncompressed += header.Size
	}
	// Drain the compressed stream so the archive digest and compressed-size
	// limit cover trailing bytes as well.
	if _, err := io.Copy(io.Discard, zr); err != nil {
		return nil, fmt.Errorf("drain zstd stream: %w", err)
	}
	if cw.n > limits.TotalBytes {
		return nil, fmt.Errorf("compressed archive exceeds max %d", limits.TotalBytes)
	}
	return &archiveInfo{
		size:    cw.n,
		hash:    hex.EncodeToString(h.Sum(nil)),
		entries: entries,
	}, nil
}

// verifyArchiveDigest compares the archive digest.
func verifyArchiveDigest(info *archiveInfo, want *Metadata) error {
	if want == nil {
		return nil
	}
	if want.SHA256 != "" && want.SHA256 != info.hash {
		return fmt.Errorf("archive digest mismatch: got %s, want %s", info.hash, want.SHA256)
	}
	return nil
}

// verifyMetadataDigest verifies the snapshot.json manifest digest.
func verifyMetadataDigest(info *archiveInfo, want *Metadata) error {
	meta, err := metadataFromInfo(info)
	if err != nil {
		return err
	}
	entries := make([]ManifestEntry, 0, len(info.entries))
	for path, e := range info.entries {
		if path == metadataPath {
			continue
		}
		entries = append(entries, ManifestEntry{Path: path, SHA256: e.hash, Size: e.size})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	if err := validateSnapshotLayout(info); err != nil {
		return err
	}
	wantManifestDigest := digestManifest(entries)
	if meta.SHA256 != "" && meta.SHA256 != wantManifestDigest {
		return fmt.Errorf("manifest digest mismatch: got %s, want %s", meta.SHA256, wantManifestDigest)
	}
	if !manifestEqual(meta.Manifest, entries) {
		return fmt.Errorf("metadata manifest does not match archive entries")
	}
	var actualSize int64
	for _, entry := range info.entries {
		actualSize += entry.size
	}
	if meta.Size != actualSize {
		return fmt.Errorf("metadata size mismatch: got %d, actual %d", meta.Size, actualSize)
	}
	checkpointEntry, ok := info.entries[checkpointPath]
	if !ok {
		return fmt.Errorf("missing checkpoint %s", checkpointPath)
	}
	if meta.Checkpoint != string(checkpointEntry.data) {
		return fmt.Errorf("metadata checkpoint does not match archive checkpoint")
	}
	checkpointTree, origin, err := tlogx.ParseCheckpoint(checkpointEntry.data)
	if err != nil {
		return fmt.Errorf("metadata checkpoint: %w", err)
	}
	if meta.TreeSize != checkpointTree.N {
		return fmt.Errorf("metadata tree size %d does not match checkpoint %d", meta.TreeSize, checkpointTree.N)
	}
	if meta.Origin != origin {
		return fmt.Errorf("metadata origin %q does not match checkpoint %q", meta.Origin, origin)
	}
	if want != nil {
		if want.Size > 0 && want.Size != meta.Size {
			return fmt.Errorf("metadata size mismatch: got %d, want %d", meta.Size, want.Size)
		}
		if want.TreeSize > 0 && want.TreeSize != meta.TreeSize {
			return fmt.Errorf("tree size mismatch: got %d, want %d", meta.TreeSize, want.TreeSize)
		}
		if want.Checkpoint != "" && want.Checkpoint != meta.Checkpoint {
			return fmt.Errorf("checkpoint mismatch")
		}
		if want.Origin != "" && want.Origin != meta.Origin {
			return fmt.Errorf("origin mismatch")
		}
		if want.CreatedAt != "" && want.CreatedAt != meta.CreatedAt {
			return fmt.Errorf("created_at mismatch")
		}
		if len(want.Manifest) > 0 {
			if !manifestEqual(want.Manifest, meta.Manifest) {
				return fmt.Errorf("manifest mismatch")
			}
		}
	}
	return nil
}

func validateSnapshotLayout(info *archiveInfo) error {
	required := []string{checkpointPath, datasetPath, scorePath}
	for _, path := range required {
		if _, ok := info.entries[path]; !ok {
			return fmt.Errorf("missing required snapshot entry %s", path)
		}
	}
	for path := range info.entries {
		switch {
		case path == metadataPath, path == checkpointPath, path == datasetPath, path == scorePath:
			continue
		case strings.HasPrefix(path, leafPrefix):
			if _, _, err := tlogx.DecodeLeafIndex(path, info.entries[path].data); err != nil {
				return err
			}
		case strings.HasPrefix(path, blobPrefix):
			id := strings.TrimPrefix(path, blobPrefix)
			if !schema.IsHexHash(id) || strings.Contains(id, "/") {
				return fmt.Errorf("invalid blob path %s", path)
			}
		case strings.HasPrefix(path, prefixPrefix):
			prefix := strings.TrimPrefix(path, prefixPrefix)
			if strings.Contains(prefix, "/") {
				return fmt.Errorf("invalid prefix path %s", path)
			}
			if err := prefixdb.ValidatePrefix(prefix); err != nil {
				return fmt.Errorf("invalid prefix path %s: %w", path, err)
			}
		case strings.HasPrefix(path, tilePrefix):
			if _, err := tlog.ParseTilePath(strings.TrimPrefix(path, "v1/")); err != nil {
				return fmt.Errorf("invalid tile path %s: %w", path, err)
			}
		default:
			return fmt.Errorf("unexpected snapshot entry %s", path)
		}
	}
	return nil
}

// metadataFromInfo parses snapshot.json from the archive.
func metadataFromInfo(info *archiveInfo) (*Metadata, error) {
	e, ok := info.entries[metadataPath]
	if !ok {
		return nil, fmt.Errorf("missing %s", metadataPath)
	}
	var raw struct {
		SHA256     string          `json:"sha256"`
		Size       int64           `json:"size"`
		TreeSize   int64           `json:"tree_size"`
		Checkpoint string          `json:"checkpoint"`
		Origin     string          `json:"origin"`
		CreatedAt  string          `json:"created_at"`
		Manifest   []ManifestEntry `json:"manifest"`
	}
	dec := json.NewDecoder(bytes.NewReader(e.data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode metadata: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode metadata: trailing data")
		}
		return nil, fmt.Errorf("decode metadata: trailing data: %w", err)
	}
	if raw.TreeSize < 0 || raw.Size < 0 {
		return nil, fmt.Errorf("decode metadata: negative size")
	}
	if raw.Origin == "" || raw.Checkpoint == "" || raw.CreatedAt == "" {
		return nil, fmt.Errorf("decode metadata: origin, checkpoint, and created_at are required")
	}
	if _, err := time.Parse(time.RFC3339, raw.CreatedAt); err != nil {
		return nil, fmt.Errorf("decode metadata: invalid created_at: %w", err)
	}
	return &Metadata{
		SHA256:     raw.SHA256,
		Size:       raw.Size,
		TreeSize:   raw.TreeSize,
		Checkpoint: raw.Checkpoint,
		Origin:     raw.Origin,
		CreatedAt:  raw.CreatedAt,
		Manifest:   raw.Manifest,
	}, nil
}

// manifestEqual reports whether two manifest lists are identical.
func manifestEqual(a, b []ManifestEntry) bool {
	if len(a) != len(b) {
		return false
	}
	a = append([]ManifestEntry(nil), a...)
	b = append([]ManifestEntry(nil), b...)
	sort.Slice(a, func(i, j int) bool { return a[i].Path < a[j].Path })
	sort.Slice(b, func(i, j int) bool { return b[i].Path < b[j].Path })
	for i := range a {
		if a[i].Path != b[i].Path || a[i].SHA256 != b[i].SHA256 || a[i].Size != b[i].Size {
			return false
		}
	}
	return true
}

// verifyTree verifies the checkpoint and tree consistency.
func verifyTree(info *archiveInfo, policy tlogx.Policy, cpPath string) error {
	if cpPath == "" {
		cpPath = checkpointPath
	}
	cp, ok := info.entries[cpPath]
	if !ok {
		return fmt.Errorf("missing checkpoint %s", cpPath)
	}
	tree, _, err := tlogx.VerifyCheckpoint(cp.data, policy)
	if err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}

	leafIndexes, err := leafIndexesFromInfo(info)
	if err != nil {
		return err
	}
	if int64(len(leafIndexes)) != tree.N {
		return fmt.Errorf("leaf count %d does not match tree size %d", len(leafIndexes), tree.N)
	}

	records := make([]indexedRecord, 0, len(leafIndexes))
	for _, idx := range leafIndexes {
		blobPath := blobPrefix + idx.RecordID
		blob, ok := info.entries[blobPath]
		if !ok {
			return fmt.Errorf("missing blob for leaf %d: %s", idx.Index, idx.RecordID)
		}
		leafHash, err := tlogx.LeafIndexHash(idx)
		if err != nil {
			return err
		}
		if tombstone, ok, err := tlogx.DecodeTombstoneBlob(blob.data, idx.RecordID); err != nil {
			return fmt.Errorf("leaf %d tombstone: %w", idx.Index, err)
		} else if ok {
			records = append(records, indexedRecord{
				index:     idx.Index,
				id:        idx.RecordID,
				leafHash:  leafHash,
				tombstone: tombstone,
				blob:      append([]byte(nil), blob.data...),
			})
			continue
		}
		rec, err := schema.DecodeRecordStrict(bytes.NewReader(blob.data))
		if err != nil {
			return fmt.Errorf("leaf %d decode: %w", idx.Index, err)
		}
		body, _, err := schema.Verify(rec)
		if err != nil {
			return fmt.Errorf("leaf %d signature: %w", idx.Index, err)
		}
		id, err := schema.RecordID(*body)
		if err != nil {
			return fmt.Errorf("leaf %d record id: %w", idx.Index, err)
		}
		if id != idx.RecordID {
			return fmt.Errorf("leaf %d record id %s does not match index %s", idx.Index, id, idx.RecordID)
		}
		leaf, err := tlogx.RecordToLeaf(*rec)
		if err != nil {
			return fmt.Errorf("leaf %d to leaf: %w", idx.Index, err)
		}
		gotHash, err := tlogx.LeafHash(leaf)
		if err != nil {
			return fmt.Errorf("leaf %d hash: %w", idx.Index, err)
		}
		if gotHash != leafHash {
			return fmt.Errorf("leaf %d hash does not match index", idx.Index)
		}
		records = append(records, indexedRecord{
			index:    idx.Index,
			rec:      rec,
			id:       id,
			leafHash: leafHash,
			blob:     append([]byte(nil), blob.data...),
		})
	}
	if err := validateTombstoneBindings(records); err != nil {
		return err
	}

	tr := tlogx.NewTileReader(&archiveStore{entries: info.entries}, tlogx.DefaultTileHeight)
	hr := tlog.TileHashReader(tree, tr)
	for _, record := range records {
		proof, err := tlog.ProveRecord(tree.N, record.index, hr)
		if err != nil {
			return fmt.Errorf("prove record %d: %w", record.index, err)
		}
		if err := tlog.CheckRecord(proof, tree.N, tree.Hash, record.index, record.leafHash); err != nil {
			return fmt.Errorf("check record %d: %w", record.index, err)
		}
	}
	return nil
}

// verifyRecordsAndPrefix verifies the records.jsonl dataset and prefix shards.
func verifyRecordsAndPrefix(info *archiveInfo, limits Limits) error {
	lines, err := datasetLinesFromInfo(info, limits)
	if err != nil {
		return err
	}
	leafIndexes, err := leafIndexesFromInfo(info)
	if err != nil {
		return err
	}
	if len(leafIndexes) != len(lines) {
		return fmt.Errorf("records.jsonl length %d does not match leaf count %d", len(lines), len(leafIndexes))
	}
	records := make([]indexedRecord, 0, len(lines))
	for i, line := range lines {
		idx := leafIndexes[i]
		if line.Index != idx.Index || line.RecordID != idx.RecordID {
			return fmt.Errorf("records.jsonl line %d does not match leaf index %d", i, idx.Index)
		}
		blob, ok := info.entries[blobPrefix+idx.RecordID]
		if !ok {
			return fmt.Errorf("missing blob for record %s", idx.RecordID)
		}
		leafHash, err := tlogx.LeafIndexHash(idx)
		if err != nil {
			return err
		}
		if line.Tombstone {
			if line.Record != nil || !schema.IsHexHash(line.TombstoneSHA256) {
				return fmt.Errorf("records.jsonl line %d has invalid tombstone representation", i)
			}
			tombstone, isTombstone, err := tlogx.DecodeTombstoneBlob(blob.data, idx.RecordID)
			if err != nil || !isTombstone {
				if err == nil {
					err = fmt.Errorf("blob is not a tombstone")
				}
				return fmt.Errorf("records.jsonl line %d tombstone: %w", i, err)
			}
			if line.TombstoneSHA256 != tlogx.TombstoneSHA256(blob.data) {
				return fmt.Errorf("records.jsonl line %d tombstone hash mismatch", i)
			}
			records = append(records, indexedRecord{
				index:     idx.Index,
				id:        idx.RecordID,
				leafHash:  leafHash,
				tombstone: tombstone,
				blob:      append([]byte(nil), blob.data...),
			})
			continue
		}
		if line.Record == nil || line.TombstoneSHA256 != "" {
			return fmt.Errorf("records.jsonl line %d is missing a signed record", i)
		}
		if _, isTombstone, err := tlogx.DecodeTombstoneBlob(blob.data, idx.RecordID); err != nil || isTombstone {
			if err == nil {
				err = fmt.Errorf("dataset says record but blob is tombstoned")
			}
			return fmt.Errorf("records.jsonl line %d: %w", i, err)
		}
		blobRecord, err := schema.DecodeRecordStrict(bytes.NewReader(blob.data))
		if err != nil {
			return fmt.Errorf("records.jsonl line %d blob: %w", i, err)
		}
		if !recordsEqual(line.Record, blobRecord) {
			return fmt.Errorf("records.jsonl line %d does not match record blob", i)
		}
		body, _, err := schema.Verify(line.Record)
		if err != nil {
			return fmt.Errorf("records.jsonl line %d: %w", i, err)
		}
		id, err := schema.RecordID(*body)
		if err != nil || id != idx.RecordID {
			return fmt.Errorf("records.jsonl line %d record id mismatch", i)
		}
		records = append(records, indexedRecord{
			index:    idx.Index,
			rec:      line.Record,
			id:       idx.RecordID,
			leafHash: leafHash,
			blob:     append([]byte(nil), blob.data...),
		})
	}

	if err := validateTombstoneBindings(records); err != nil {
		return err
	}
	leafIDs := make(map[string]bool, len(records))
	referencedArtifacts := make(map[string]bool)
	for _, record := range records {
		leafIDs[record.id] = true
		if record.rec != nil && record.rec.Body.Type == schema.SchemaAuditV1 {
			referencedArtifacts[record.rec.Body.Target.SHA256] = true
			if record.rec.Body.Analyzer.Kind == schema.KindLLM {
				referencedArtifacts[record.rec.Body.Analyzer.PromptSHA256] = true
			}
		}
	}
	for path, entry := range info.entries {
		if !strings.HasPrefix(path, blobPrefix) {
			continue
		}
		id := strings.TrimPrefix(path, blobPrefix)
		if leafIDs[id] {
			continue
		}
		if !referencedArtifacts[id] {
			return fmt.Errorf("unreferenced content-addressed artifact %s", id)
		}
		if storage.ContentHash(entry.data) != id {
			return fmt.Errorf("content-addressed artifact %s does not match its path", id)
		}
	}
	schemaRecords := recordsToSchema(records)
	if err := validateRetractions(schemaRecords); err != nil {
		return err
	}
	audits, auditIndices := indexedAuditRecords(records)
	audits, auditIndices = applyRetractionsWithIndex(audits, auditIndices, schemaRecords)
	wantShards, err := prefixdb.BuildShardsWithIndex(audits, auditIndices)
	if err != nil {
		return fmt.Errorf("build shards: %w", err)
	}
	gotShards := map[string][]byte{}
	for path, e := range info.entries {
		if !strings.HasPrefix(path, prefixPrefix) {
			continue
		}
		prefix := strings.TrimPrefix(path, prefixPrefix)
		if err := prefixdb.ValidatePrefix(prefix); err != nil {
			return err
		}
		gotShards[prefix] = e.data
	}
	for prefix, want := range wantShards {
		got, ok := gotShards[prefix]
		if !ok {
			return fmt.Errorf("missing prefix shard %s", prefix)
		}
		if string(got) != string(want) {
			return fmt.Errorf("prefix shard %s mismatch", prefix)
		}
	}
	for prefix := range gotShards {
		if _, ok := wantShards[prefix]; !ok {
			return fmt.Errorf("unexpected prefix shard %s", prefix)
		}
	}
	return nil
}

func recordsEqual(a, b *schema.Record) bool {
	aBytes, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bBytes, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(aBytes, bBytes)
}

// datasetLinesFromInfo parses the one-line-per-leaf dataset.
func datasetLinesFromInfo(info *archiveInfo, limits Limits) ([]datasetLine, error) {
	_ = limits
	e, ok := info.entries[datasetPath]
	if !ok {
		return nil, fmt.Errorf("missing %s", datasetPath)
	}
	if len(e.data) == 0 {
		return nil, nil
	}
	rawLines := strings.Split(strings.TrimSuffix(string(e.data), "\n"), "\n")
	lines := make([]datasetLine, 0, len(rawLines))
	for i, raw := range rawLines {
		if raw == "" {
			return nil, fmt.Errorf("records.jsonl line %d is empty", i)
		}
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		var line datasetLine
		if err := dec.Decode(&line); err != nil {
			return nil, fmt.Errorf("records.jsonl line %d: %w", i, err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return nil, fmt.Errorf("records.jsonl line %d has trailing data", i)
		}
		lines = append(lines, line)
	}
	return lines, nil
}

// recordsFromInfo returns the non-deleted signed records in leaf order. It is
// used by fork import; tombstoned leaves cannot be recreated in a fork.
func recordsFromInfo(info *archiveInfo, limits Limits) ([]schema.Record, error) {
	lines, err := datasetLinesFromInfo(info, limits)
	if err != nil {
		return nil, err
	}
	var records []schema.Record
	for _, line := range lines {
		if line.Record == nil {
			continue
		}
		records = append(records, *line.Record)
	}
	return records, nil
}

// leafIndexesFromInfo strictly reads v1/leaf entries in append order.
func leafIndexesFromInfo(info *archiveInfo) ([]tlogx.LeafIndex, error) {
	indices := map[int64]tlogx.LeafIndex{}
	for path, e := range info.entries {
		if !strings.HasPrefix(path, leafPrefix) {
			continue
		}
		idx, _, err := tlogx.DecodeLeafIndex(path, e.data)
		if err != nil {
			return nil, err
		}
		if _, exists := indices[idx.Index]; exists {
			return nil, fmt.Errorf("duplicate leaf index %d", idx.Index)
		}
		indices[idx.Index] = idx
	}
	if len(indices) == 0 {
		return nil, nil
	}
	out := make([]tlogx.LeafIndex, len(indices))
	for i := range out {
		idx, ok := indices[int64(i)]
		if !ok {
			return nil, fmt.Errorf("missing leaf index %d", i)
		}
		out[i] = idx
	}
	return out, nil
}

func leafIndexFromInfo(info *archiveInfo) ([]string, error) {
	idxs, err := leafIndexesFromInfo(info)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(idxs))
	for i, idx := range idxs {
		ids[i] = idx.RecordID
	}
	return ids, nil
}

// validateRetractions verifies that every retraction record matches a target.
func validateRetractions(records []schema.Record) error {
	for i, rec := range records {
		if rec.Body.Type != schema.SchemaRetractV1 {
			continue
		}
		matched := false
		for j, target := range records {
			if j >= i || target.Body.Type != schema.SchemaAuditV1 {
				continue
			}
			if schema.RetractionMatchesTarget(&rec, &target) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("retraction record %d has no matching target", i)
		}
	}
	return nil
}

// recordsToPrefixRecords converts dataset records to a schema slice for prefix building.
func recordsToPrefixRecords(records []schema.Record) []schema.Record {
	out := make([]schema.Record, len(records))
	copy(out, records)
	return out
}

// archiveStore exposes archive entries as a storage.Store for tile readers.
type archiveStore struct {
	entries map[string]archiveEntry
}

func (s *archiveStore) Get(ctx context.Context, path string) ([]byte, error) {
	e, ok := s.entries[path]
	if !ok {
		return nil, fmt.Errorf("not found: %s", path)
	}
	return e.data, nil
}

func (s *archiveStore) Put(ctx context.Context, obj storage.Object) error {
	return fmt.Errorf("archiveStore is read-only")
}

func (s *archiveStore) Delete(ctx context.Context, path string) error {
	return fmt.Errorf("archiveStore is read-only")
}

func (s *archiveStore) List(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	for path := range s.entries {
		if strings.HasPrefix(path, prefix) {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *archiveStore) Publish(ctx context.Context, obj storage.Object) error {
	return s.Put(ctx, obj)
}

func (s *archiveStore) Close() error { return nil }
