package snapshot

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/co3k/ebi/pkg/prefixdb"
	"github.com/co3k/ebi/pkg/schema"
	"github.com/co3k/ebi/pkg/storage"
	"github.com/co3k/ebi/pkg/tlogx"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/mod/sumdb/tlog"
)

func hash64(c byte) string {
	return string(c) + strings.Repeat("0", 63)
}

func auditorFromKey(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub[:])
	return hex.EncodeToString(h[:])
}

func makeRecord(t *testing.T, priv ed25519.PrivateKey, auditor string, targetHash string, recType string, recordID string) schema.Record {
	t.Helper()
	var body schema.RecordBody
	switch recType {
	case schema.SchemaRetractV1:
		body = schema.RecordBody{
			Type:      schema.SchemaRetractV1,
			CreatedAt: 1704067201,
			Auditor:   auditor,
			RecordID:  recordID,
			Reason:    "false-positive",
		}
	default:
		body = schema.RecordBody{
			Type:      schema.SchemaAuditV1,
			CreatedAt: 1704067200,
			Auditor:   auditor,
			Target:    schema.Target{URL: "https://example.com/" + targetHash[:8], SHA256: targetHash, Size: 1},
			Analyzer:  schema.Analyzer{Kind: schema.FamilyStatic},
			Verdict:   schema.VerdictOK,
		}
	}
	rec, err := schema.Sign(body, priv)
	if err != nil {
		t.Fatalf("sign record: %v", err)
	}
	return *rec
}

func buildTestStore(t *testing.T, records []schema.Record) (storage.Store, []schema.Record, string, tlogx.Policy) {
	t.Helper()
	ctx := context.Background()
	store := storage.NewMem()

	origin := "ebi.example.com"
	signer, _, _, verifierKey, err := tlogx.GenerateKeyPair(origin)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	policy := tlogx.Policy{LogName: origin, LogKeys: []string{verifierKey}}

	tree := tlogx.NewTree()
	for _, rec := range records {
		leaf, err := tlogx.RecordToLeaf(rec)
		if err != nil {
			t.Fatalf("record to leaf: %v", err)
		}
		index, err := tree.AppendLeaf(leaf)
		if err != nil {
			t.Fatalf("append leaf: %v", err)
		}
		if err := tlogx.WriteRecord(store, index, rec); err != nil {
			t.Fatalf("write record: %v", err)
		}
	}

	if err := tlogx.WriteTiles(tree, store, tlogx.DefaultTileHeight); err != nil {
		t.Fatalf("write tiles: %v", err)
	}
	if err := tlogx.WriteCheckpoint(tree.TlogTree(), origin, signer, store); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}

	cpBytes, err := store.Get(ctx, checkpointPath)
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	return store, records, string(cpBytes), policy
}

func sortRecordsByID(t *testing.T, records []schema.Record) {
	t.Helper()
	ids := make([]string, len(records))
	for i, rec := range records {
		id, err := schema.RecordID(rec.Body)
		if err != nil {
			t.Fatalf("record id: %v", err)
		}
		ids[i] = id
	}
	for i := 0; i < len(records); i++ {
		for j := i + 1; j < len(records); j++ {
			if ids[i] > ids[j] {
				ids[i], ids[j] = ids[j], ids[i]
				records[i], records[j] = records[j], records[i]
			}
		}
	}
}

func writeEmptyCheckpoint(t *testing.T, store storage.Store) string {
	t.Helper()
	signer, _, _, _, err := tlogx.GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := tlogx.CheckpointBytes(tlogx.NewTree().TlogTree(), "ebi.example.com", signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(t.Context(), storage.Object{
		Path: checkpointPath,
		Data: checkpoint,
	}); err != nil {
		t.Fatal(err)
	}
	return string(checkpoint)
}

func TestCreateVerify(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMem()
	if err := store.Put(ctx, storage.Object{Path: "v1/records/aa/aaaaaaaa", Data: []byte("record-a")}); err != nil {
		t.Fatal(err)
	}
	checkpoint := writeEmptyCheckpoint(t, store)

	var buf bytes.Buffer
	meta, err := Create(ctx, store, 0, checkpoint, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Size == 0 || meta.SHA256 == "" {
		t.Fatal("empty metadata")
	}

	if err := VerifyArchive(&buf, meta); err != nil {
		t.Fatal(err)
	}

	// Tamper with metadata.
	bad := *meta
	bad.Size = 0
	bad.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := VerifyArchive(&buf, &bad); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestVerifyTraversal(t *testing.T) {
	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "../etc/passwd", Size: 4})
	tw.Write([]byte("root"))
	tw.Close()
	zw.Close()

	if err := VerifyArchive(&buf, nil); err == nil {
		t.Fatal("expected traversal error")
	}
}

func TestArchiveDigest(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	auditor := auditorFromKey(pub)
	rec := makeRecord(t, priv, auditor, hash64('a'), schema.SchemaAuditV1, "")
	store, records, cp, policy := buildTestStore(t, []schema.Record{rec})

	var buf bytes.Buffer
	meta, err := Create(ctx, store, int64(len(records)), cp, &buf)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the full archive digest matches.
	h := sha256.New()
	if _, err := h.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if meta.SHA256 != hex.EncodeToString(h.Sum(nil)) {
		t.Fatal("archive SHA256 does not match compressed bytes")
	}

	// Verify full tree with policy.
	if err := Verify(bytes.NewReader(buf.Bytes()), meta, &policy, checkpointPath); err != nil {
		t.Fatal(err)
	}
}

func TestCreateOmitsUnreferencedContentBlob(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	auditor := auditorFromKey(pub)
	rec := makeRecord(t, priv, auditor, hash64('a'), schema.SchemaAuditV1, "")
	store, records, cp, policy := buildTestStore(t, []schema.Record{rec})

	orphanData := []byte("unreferenced artifact")
	orphanID := storage.ContentHash(orphanData)
	if err := store.Put(ctx, storage.Object{
		Path:      storage.BlobPath(orphanID),
		Data:      orphanData,
		Immutable: true,
	}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	meta, err := Create(ctx, store, int64(len(records)), cp, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(bytes.NewReader(buf.Bytes()), meta, &policy, checkpointPath); err != nil {
		t.Fatalf("snapshot with filtered orphan did not verify: %v", err)
	}
	info, err := readArchive(bytes.NewReader(buf.Bytes()), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := info.entries[storage.BlobPath(orphanID)]; ok {
		t.Fatal("snapshot included an unreferenced content blob")
	}
}

func TestLatestJSON(t *testing.T) {
	meta := &Metadata{
		SHA256:         strings.Repeat("a", 64),
		CompressedSize: 1234,
		TreeSize:       42,
		Checkpoint:     "signed checkpoint",
	}
	data, err := LatestJSON(meta, "https://log.example/v1/snapshot/42.tar.zst", []string{
		"https://mirror-b.example/42.tar.zst",
		"https://mirror-a.example/42.tar.zst",
		"https://mirror-a.example/42.tar.zst",
		"https://log.example/v1/snapshot/42.tar.zst",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got Latest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Size != meta.CompressedSize || got.TreeSize != meta.TreeSize ||
		got.SHA256 != meta.SHA256 || got.Checkpoint != meta.Checkpoint {
		t.Fatalf("latest metadata mismatch: %+v", got)
	}
	wantMirrors := []string{
		"https://mirror-a.example/42.tar.zst",
		"https://mirror-b.example/42.tar.zst",
	}
	if len(got.Mirrors) != len(wantMirrors) {
		t.Fatalf("mirrors: %v", got.Mirrors)
	}
	for i := range wantMirrors {
		if got.Mirrors[i] != wantMirrors[i] {
			t.Fatalf("mirrors: %v", got.Mirrors)
		}
	}
}

func TestManifestDigest(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	auditor := auditorFromKey(pub)
	rec := makeRecord(t, priv, auditor, hash64('a'), schema.SchemaAuditV1, "")
	store, records, cp, _ := buildTestStore(t, []schema.Record{rec})

	var buf bytes.Buffer
	meta, err := Create(ctx, store, int64(len(records)), cp, &buf)
	if err != nil {
		t.Fatal(err)
	}

	// Read the archive and inspect snapshot.json.
	zr, err := zstd.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	found := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == metadataPath {
			found = true
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			var raw struct {
				SHA256 string `json:"sha256"`
			}
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatal(err)
			}
			want := digestManifest(meta.Manifest)
			if raw.SHA256 != want {
				t.Fatalf("manifest digest mismatch: got %s, want %s", raw.SHA256, want)
			}
			break
		}
	}
	if !found {
		t.Fatal("snapshot.json not found in archive")
	}
}

func TestTamperArchiveBytes(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMem()
	checkpoint := writeEmptyCheckpoint(t, store)
	var buf bytes.Buffer
	meta, err := Create(ctx, store, 0, checkpoint, &buf)
	if err != nil {
		t.Fatal(err)
	}

	// Flip one byte in the compressed archive.
	bad := buf.Bytes()
	bad[0] ^= 0xff

	if err := VerifyArchive(bytes.NewReader(bad), meta); err == nil {
		t.Fatal("expected tamper error")
	}
}

func TestTamperManifest(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	auditor := auditorFromKey(pub)
	rec := makeRecord(t, priv, auditor, hash64('a'), schema.SchemaAuditV1, "")
	store, records, cp, policy := buildTestStore(t, []schema.Record{rec})

	var buf bytes.Buffer
	meta, err := Create(ctx, store, int64(len(records)), cp, &buf)
	if err != nil {
		t.Fatal(err)
	}

	// Rewrite archive with a modified snapshot.json size.
	zr, err := zstd.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	var out bytes.Buffer
	zw, err := zstd.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == metadataPath {
			var raw map[string]interface{}
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatal(err)
			}
			raw["size"] = raw["size"].(float64) + 1
			data, err = json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.WriteHeader(&tar.Header{Name: h.Name, Mode: 0644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	// Update want to the tampered archive hash so the archive digest passes.
	bad := *meta
	h := sha256.Sum256(out.Bytes())
	bad.SHA256 = hex.EncodeToString(h[:])
	if err := Verify(bytes.NewReader(out.Bytes()), &bad, &policy, checkpointPath); err == nil {
		t.Fatal("expected manifest tamper error")
	}
}

func TestDuplicatePath(t *testing.T) {
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for _, data := range []string{"one", "two"} {
		tw.WriteHeader(&tar.Header{Name: "same", Mode: 0644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		tw.Write([]byte(data))
	}
	tw.Close()
	zw.Close()

	if err := VerifyArchive(&buf, nil); err == nil {
		t.Fatal("expected duplicate path error")
	}
}

func TestSymlinkRejection(t *testing.T) {
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "link", Mode: 0777, Typeflag: tar.TypeSymlink, Linkname: "v1/checkpoint"})
	tw.WriteHeader(&tar.Header{Name: "v1/checkpoint", Mode: 0644, Size: 10, Typeflag: tar.TypeReg})
	tw.Write([]byte("checkpoint"))
	tw.Close()
	zw.Close()

	if err := VerifyArchive(&buf, nil); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestLargeFileLimit(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMem()
	if err := store.Put(ctx, storage.Object{Path: "v1/blob/" + strings.Repeat("a", 64), Data: bytes.Repeat([]byte("x"), 200)}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_, err := CreateWithLimits(ctx, store, 0, "checkpoint", &buf, Limits{FileBytes: 100, FileCount: 1000, TotalBytes: 1 << 20})
	if err == nil {
		t.Fatal("expected file size limit error")
	}
}

func TestFileCountLimit(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMem()
	for i := 0; i < 5; i++ {
		if err := store.Put(ctx, storage.Object{Path: fmt.Sprintf("v1/extra/%d", i), Data: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	_, err := CreateWithLimits(ctx, store, 0, "checkpoint", &buf, Limits{FileBytes: 1 << 20, FileCount: 2, TotalBytes: 1 << 20})
	if err == nil {
		t.Fatal("expected file count limit error")
	}
}

func TestMirrorImport(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	auditor := auditorFromKey(pub)
	rec := makeRecord(t, priv, auditor, hash64('a'), schema.SchemaAuditV1, "")
	store, records, cp, _ := buildTestStore(t, []schema.Record{rec})

	var buf bytes.Buffer
	meta, err := Create(ctx, store, int64(len(records)), cp, &buf)
	if err != nil {
		t.Fatal(err)
	}

	dst := storage.NewMem()
	gotMeta, err := ImportMirror(bytes.NewReader(buf.Bytes()), dst)
	if err != nil {
		t.Fatal(err)
	}
	if gotMeta.Size != meta.Size {
		t.Fatal("metadata size mismatch")
	}

	// Ensure signed tree assets are copied, not dataset or snapshot.json.
	if _, err := dst.Get(ctx, checkpointPath); err != nil {
		t.Fatal("checkpoint not copied")
	}
	recordID, _ := schema.RecordID(records[0].Body)
	if _, err := dst.Get(ctx, "v1/blob/"+recordID); err != nil {
		t.Fatal("blob not copied")
	}
	if _, err := dst.Get(ctx, datasetPath); err == nil {
		t.Fatal("dataset should not be copied")
	}
	if _, err := dst.Get(ctx, metadataPath); err == nil {
		t.Fatal("snapshot.json should not be copied")
	}
}

func TestForkImport(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	auditor := auditorFromKey(pub)
	r1 := makeRecord(t, priv, auditor, hash64('a'), schema.SchemaAuditV1, "")
	r2 := makeRecord(t, priv, auditor, hash64('b'), schema.SchemaAuditV1, "")
	store, records, cp, policy := buildTestStore(t, []schema.Record{r1, r2})

	var buf bytes.Buffer
	_, err = Create(ctx, store, int64(len(records)), cp, &buf)
	if err != nil {
		t.Fatal(err)
	}

	dst := storage.NewMem()
	var got []string
	cb := func(rec schema.Record, index int64) error {
		id, err := schema.RecordID(rec.Body)
		if err != nil {
			return err
		}
		got = append(got, fmt.Sprintf("%d:%s", index, id))
		if _, err := tlogx.WriteBlob(dst, rec); err != nil {
			return err
		}
		return nil
	}
	if _, err := ImportFork(bytes.NewReader(buf.Bytes()), dst, &policy, cb); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}
	// Ensure order matches sorted leaf order.
	want := []string{}
	for i, rec := range records {
		id, _ := schema.RecordID(rec.Body)
		want = append(want, fmt.Sprintf("%d:%s", i, id))
	}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("order mismatch: got %v, want %v", got, want)
	}

	// Verify records are in the destination store.
	for _, rec := range records {
		id, _ := schema.RecordID(rec.Body)
		if _, err := dst.Get(ctx, "v1/blob/"+id); err != nil {
			t.Fatalf("blob not written: %v", err)
		}
	}
}

func TestExtractSafety(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMem()
	checkpoint := writeEmptyCheckpoint(t, store)
	var buf bytes.Buffer
	if _, err := Create(ctx, store, 0, checkpoint, &buf); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := Extract(bytes.NewReader(buf.Bytes()), dir, 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, checkpointPath)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, metadataPath)); err != nil {
		t.Fatal(err)
	}

	// Extraction should fail when maxBytes is too small.
	if err := Extract(bytes.NewReader(buf.Bytes()), t.TempDir(), 10); err == nil {
		t.Fatal("expected maxBytes error")
	}
}

func TestRetractionInSnapshot(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	auditor := auditorFromKey(pub)
	audit := makeRecord(t, priv, auditor, hash64('a'), schema.SchemaAuditV1, "")
	id, _ := schema.RecordID(audit.Body)
	retract := makeRecord(t, priv, auditor, hash64('a'), schema.SchemaRetractV1, id)

	records := []schema.Record{audit, retract}
	store, records, cp, policy := buildTestStore(t, records)

	var buf bytes.Buffer
	meta, err := Create(ctx, store, int64(len(records)), cp, &buf)
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(bytes.NewReader(buf.Bytes()), meta, &policy, checkpointPath); err != nil {
		t.Fatal(err)
	}
}

func TestRetractionWithoutTarget(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	auditor := auditorFromKey(pub)
	retract := makeRecord(t, priv, auditor, hash64('a'), schema.SchemaRetractV1, hash64('b'))
	store, records, cp, policy := buildTestStore(t, []schema.Record{retract})

	var buf bytes.Buffer
	meta, err := Create(ctx, store, int64(len(records)), cp, &buf)
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(bytes.NewReader(buf.Bytes()), meta, &policy, checkpointPath); err == nil {
		t.Fatal("expected retraction without target to fail")
	}
}

func TestSnapshotPreservesAppendOrderAndLogIndex(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	auditor := auditorFromKey(priv.Public().(ed25519.PublicKey))
	r0 := makeRecord(t, priv, auditor, hash64('a'), schema.SchemaAuditV1, "")
	r1 := makeRecord(t, priv, auditor, hash64('b'), schema.SchemaAuditV1, "")
	id0, _ := schema.RecordID(r0.Body)
	id1, _ := schema.RecordID(r1.Body)
	// Deliberately append in descending record-ID order so an implementation
	// that sorts blobs cannot accidentally pass.
	records := []schema.Record{r0, r1}
	if id0 < id1 {
		records[0], records[1] = records[1], records[0]
		id0, id1 = id1, id0
	}
	store, records, cp, policy := buildTestStore(t, records)

	var buf bytes.Buffer
	meta, err := Create(ctx, store, int64(len(records)), cp, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(bytes.NewReader(buf.Bytes()), meta, &policy, checkpointPath); err != nil {
		t.Fatal(err)
	}

	info, err := readArchive(bytes.NewReader(buf.Bytes()), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	lines, err := datasetLinesFromInfo(info, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0].RecordID != id0 || lines[1].RecordID != id1 {
		t.Fatalf("dataset order changed: %+v", lines)
	}
	prefix := prefixdb.Prefix(records[1].Body.Target.SHA256)
	shard, err := prefixdb.DecodeShardStrict(info.entries[prefixPrefix+prefix].data)
	if err != nil {
		t.Fatal(err)
	}
	if len(shard.Entries) != 1 || shard.Entries[0].LogIndex != 1 {
		t.Fatalf("expected real log index 1, got %+v", shard.Entries)
	}
}

func TestSnapshotRejectsMalformedLeafIndex(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	auditor := auditorFromKey(priv.Public().(ed25519.PublicKey))
	rec := makeRecord(t, priv, auditor, hash64('a'), schema.SchemaAuditV1, "")

	for _, tc := range []struct {
		name string
		edit func(storage.Store)
	}{
		{
			name: "path-document mismatch",
			edit: func(store storage.Store) {
				data, _ := store.Get(ctx, leafPrefix+"0")
				var idx tlogx.LeafIndex
				_ = json.Unmarshal(data, &idx)
				idx.Index = 1
				b, _ := json.Marshal(idx)
				_ = store.Put(ctx, storage.Object{Path: leafPrefix + "0", Data: b})
			},
		},
		{
			name: "gap",
			edit: func(store storage.Store) {
				data, _ := store.Get(ctx, leafPrefix+"0")
				var idx tlogx.LeafIndex
				_ = json.Unmarshal(data, &idx)
				idx.Index = 1
				b, _ := json.Marshal(idx)
				_ = store.Delete(ctx, leafPrefix+"0")
				_ = store.Put(ctx, storage.Object{Path: leafPrefix + "1", Data: b})
			},
		},
		{
			name: "unknown field",
			edit: func(store storage.Store) {
				data, _ := store.Get(ctx, leafPrefix+"0")
				data = append(data[:len(data)-1], []byte(`,"unknown":true}`)...)
				_ = store.Put(ctx, storage.Object{Path: leafPrefix + "0", Data: data})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, records, cp, _ := buildTestStore(t, []schema.Record{rec})
			tc.edit(store)
			var buf bytes.Buffer
			if _, err := Create(ctx, store, int64(len(records)), cp, &buf); err == nil {
				t.Fatal("expected malformed leaf index to fail")
			}
		})
	}
}

func TestSnapshotTombstoneBinding(t *testing.T) {
	ctx := context.Background()
	operatorPub, operatorPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	operatorID := auditorFromKey(operatorPub)
	audit := makeRecord(t, operatorPriv, operatorID, hash64('a'), schema.SchemaAuditV1, "")
	auditID, _ := schema.RecordID(audit.Body)

	tombstoneBytes, err := json.Marshal(tlogx.Tombstone{
		Tombstone: true,
		RecordID:  auditID,
		Reason:    "privacy",
		Message:   "Deletion never substitutes for rotation.",
		DeletedAt: "2026-08-02T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	moderation, err := schema.Sign(schema.RecordBody{
		Type:            schema.SchemaModerationV1,
		CreatedAt:       1785628801,
		Auditor:         operatorID,
		BlobSHA256:      auditID,
		TombstoneSHA256: tlogx.TombstoneSHA256(tombstoneBytes),
		Reason:          "tombstone",
	}, operatorPriv)
	if err != nil {
		t.Fatal(err)
	}

	makeStore := func(t *testing.T, records []schema.Record, replace bool) (storage.Store, string, tlogx.Policy) {
		store, _, cp, policy := buildTestStore(t, records)
		if replace {
			if err := store.Put(ctx, storage.Object{
				Path: blobPrefix + auditID,
				Data: tombstoneBytes,
			}); err != nil {
				t.Fatal(err)
			}
		}
		return store, cp, policy
	}

	t.Run("valid", func(t *testing.T) {
		store, cp, policy := makeStore(t, []schema.Record{audit, *moderation}, true)
		var buf bytes.Buffer
		meta, err := Create(ctx, store, 2, cp, &buf)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(bytes.NewReader(buf.Bytes()), meta, &policy, checkpointPath); err != nil {
			t.Fatal(err)
		}
		info, err := readArchive(bytes.NewReader(buf.Bytes()), DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		lines, err := datasetLinesFromInfo(info, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) != 2 || !lines[0].Tombstone || lines[0].Record != nil ||
			lines[1].Record == nil || lines[1].Record.Body.Type != schema.SchemaModerationV1 {
			t.Fatalf("unexpected tombstone dataset: %+v", lines)
		}
	})

	t.Run("missing moderation", func(t *testing.T) {
		store, cp, _ := makeStore(t, []schema.Record{audit}, true)
		var buf bytes.Buffer
		if _, err := Create(ctx, store, 1, cp, &buf); err == nil {
			t.Fatal("expected missing moderation to fail")
		}
	})

	t.Run("moderation before target", func(t *testing.T) {
		store, cp, _ := makeStore(t, []schema.Record{*moderation, audit}, true)
		var buf bytes.Buffer
		if _, err := Create(ctx, store, 2, cp, &buf); err == nil {
			t.Fatal("expected earlier moderation to fail")
		}
	})

	t.Run("tampered tombstone", func(t *testing.T) {
		store, cp, _ := makeStore(t, []schema.Record{audit, *moderation}, true)
		var tomb map[string]any
		_ = json.Unmarshal(tombstoneBytes, &tomb)
		tomb["message"] = "changed"
		bad, _ := json.Marshal(tomb)
		_ = store.Put(ctx, storage.Object{Path: blobPrefix + auditID, Data: bad})
		var buf bytes.Buffer
		if _, err := Create(ctx, store, 2, cp, &buf); err == nil {
			t.Fatal("expected tombstone hash mismatch to fail")
		}
	})

	t.Run("wrong record id", func(t *testing.T) {
		store, cp, _ := makeStore(t, []schema.Record{audit, *moderation}, true)
		var tomb map[string]any
		_ = json.Unmarshal(tombstoneBytes, &tomb)
		tomb["record_id"] = hash64('b')
		bad, _ := json.Marshal(tomb)
		_ = store.Put(ctx, storage.Object{Path: blobPrefix + auditID, Data: bad})
		var buf bytes.Buffer
		if _, err := Create(ctx, store, 2, cp, &buf); err == nil {
			t.Fatal("expected tombstone record id mismatch to fail")
		}
	})
}

// Ensure tlog.Hash is used, satisfying the import.
var _ = tlog.Hash{}
