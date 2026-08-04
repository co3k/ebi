package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/co3k/ebi/pkg/appmeta"
	"github.com/co3k/ebi/pkg/prefixdb"
	"github.com/co3k/ebi/pkg/schema"
	"github.com/co3k/ebi/pkg/score"
	"github.com/co3k/ebi/pkg/storage"
	"github.com/co3k/ebi/pkg/tlogx"
	"golang.org/x/mod/sumdb/note"
)

func testKey(t *testing.T) (note.Signer, string) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, "test")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, vkey
}

func hex64(seed string) string {
	h := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(h[:])
}

func makeRecord(t *testing.T, store storage.Store, seed string) (schema.Record, tlogx.Leaf, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	targetData := []byte("target content for " + seed)
	targetSHA := storage.ContentHash(targetData)
	if store != nil {
		if err := store.Put(context.Background(), storage.Object{
			Path:        storage.BlobPath(targetSHA),
			Data:        targetData,
			ContentType: "application/octet-stream",
			Immutable:   true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: time.Now().Unix(),
		Auditor:   schema.AuditorHash(pub),
		Target: schema.Target{
			URL:    "https://example.com/" + seed,
			SHA256: targetSHA,
			Size:   int64(len(targetData)),
		},
		Analyzer: schema.Analyzer{Kind: schema.KindHuman},
		Verdict:  schema.VerdictOK,
		Claims: []schema.Claim{{
			Category:   schema.KnownCategories[0],
			Line:       1,
			LineSHA256: hex64(seed),
		}},
	}
	rec, err := schema.Sign(body, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := tlogx.RecordToLeaf(*rec)
	if err != nil {
		t.Fatal(err)
	}
	return *rec, leaf, priv
}

func makeLog(t *testing.T, store storage.Store, signer note.Signer, count int) (*tlogx.Tree, []schema.Record) {
	t.Helper()
	tr := tlogx.NewTree()
	var records []schema.Record
	for i := 0; i < count; i++ {
		rec, leaf, _ := makeRecord(t, store, fmt.Sprintf("r%d", i))
		idx, err := tr.AppendLeaf(leaf)
		if err != nil {
			t.Fatal(err)
		}
		if err := tlogx.WriteRecord(store, idx, rec); err != nil {
			t.Fatal(err)
		}
		records = append(records, rec)
	}
	if err := tlogx.WriteTiles(tr, store, tlogx.DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteCheckpoint(tr.TlogTree(), "test", signer, store); err != nil {
		t.Fatal(err)
	}
	writeShards(t, store, records)
	return tr, records
}

func writeShards(t *testing.T, store storage.Store, records []schema.Record) {
	t.Helper()
	indices := make([]int64, len(records))
	for i := range records {
		indices[i] = int64(i)
	}
	shards, err := prefixdb.BuildShardsWithIndex(records, indices)
	if err != nil {
		t.Fatal(err)
	}
	for prefix, data := range shards {
		if err := store.Put(context.Background(), storage.Object{
			Path:         storage.PrefixPath(prefix),
			Data:         data,
			ContentType:  "application/json",
			CacheSeconds: 300,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func writePolicy(t *testing.T, dir, vkey string) string {
	t.Helper()
	path := filepath.Join(dir, "policy.toml")
	policy := tlogx.Policy{LogName: "test", LogKeys: []string{vkey}}
	if err := tlogx.SavePolicy(path, policy); err != nil {
		t.Fatal(err)
	}
	return path
}

func makeLLMRecord(t *testing.T, store storage.Store, seed string, targetData, promptData []byte) (schema.Record, tlogx.Leaf, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	targetSHA := storage.ContentHash(targetData)
	promptSHA := storage.ContentHash(promptData)
	if store != nil {
		if err := store.Put(context.Background(), storage.Object{
			Path:        storage.BlobPath(targetSHA),
			Data:        targetData,
			ContentType: "application/octet-stream",
			Immutable:   true,
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.Put(context.Background(), storage.Object{
			Path:        storage.BlobPath(promptSHA),
			Data:        promptData,
			ContentType: "application/octet-stream",
			Immutable:   true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: time.Now().Unix(),
		Auditor:   schema.AuditorHash(pub),
		Target: schema.Target{
			URL:    "https://example.com/" + seed,
			SHA256: targetSHA,
			Size:   int64(len(targetData)),
		},
		Analyzer: schema.Analyzer{
			Kind:         schema.KindLLM,
			Model:        "model",
			ModelFamily:  "family",
			Quantization: "q4",
			Backend:      "ollama",
			PromptSHA256: promptSHA,
			Runs:         1,
			Agreement:    1.0,
		},
		Verdict: schema.VerdictOK,
		Claims: []schema.Claim{{
			Category:   schema.KnownCategories[0],
			Line:       1,
			LineSHA256: hex64(seed),
		}},
	}
	rec, err := schema.Sign(body, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := tlogx.RecordToLeaf(*rec)
	if err != nil {
		t.Fatal(err)
	}
	return *rec, leaf, priv
}

func makeRetraction(t *testing.T, target schema.Record, priv ed25519.PrivateKey) schema.Record {
	t.Helper()
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	id, err := schema.RecordID(target.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := schema.RecordBody{
		Type:      schema.SchemaRetractV1,
		CreatedAt: time.Now().Unix(),
		Auditor:   schema.AuditorHash(pub),
		RecordID:  id,
		Reason:    "false-positive",
	}
	rec, err := schema.Sign(body, priv)
	if err != nil {
		t.Fatal(err)
	}
	return *rec
}

func TestLocalStorage(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	makeLog(t, store, signer, 3)

	cfg := &config{
		storage:        filepath.Join(dir, "store"),
		policyPath:     writePolicy(t, dir, vkey),
		checkpointPath: filepath.Join(dir, "state.toml"),
		oneShot:        true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Verified || res.Corrupt {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.Size != 3 || res.Records != 3 || res.Retractions != 0 {
		t.Fatalf("counts: size=%d records=%d retractions=%d", res.Size, res.Records, res.Retractions)
	}
	if res.Shards <= 0 {
		t.Fatalf("expected shards: %d", res.Shards)
	}
	if res.ScoreParams == "" {
		t.Fatal("missing score_params")
	}
	if _, err := os.Stat(cfg.checkpointPath); err != nil {
		t.Fatalf("checkpoint state not written: %v", err)
	}
}

func TestCheckpointConsistency(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	tr0 := tlogx.NewTree()
	cp0, err := tlogx.CheckpointBytes(tr0.TlogTree(), "test", signer)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.toml")
	if err := tlogx.SaveCheckpointState(statePath, tr0.TlogTree(), cp0); err != nil {
		t.Fatal(err)
	}
	makeLog(t, store, signer, 3)

	cfg := &config{
		storage:        filepath.Join(dir, "store"),
		policyPath:     writePolicy(t, dir, vkey),
		checkpointPath: statePath,
		oneShot:        true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Verified || res.Size != 3 {
		t.Fatalf("result: %+v", res)
	}
}

func TestCorruptBlob(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	tr, records := makeLog(t, store, signer, 3)
	_ = records
	recordIDs := map[string]bool{}
	for i := int64(0); i < tr.Size(); i++ {
		data, err := store.Get(context.Background(), fmt.Sprintf("v1/leaf/%d", i))
		if err != nil {
			t.Fatal(err)
		}
		idx, _, err := tlogx.DecodeLeafIndex(fmt.Sprintf("v1/leaf/%d", i), data)
		if err != nil {
			t.Fatal(err)
		}
		recordIDs[idx.RecordID] = true
	}
	keys, err := store.List(context.Background(), "v1/blob")
	if err != nil {
		t.Fatal(err)
	}
	var recordBlob string
	for _, key := range keys {
		id := strings.TrimPrefix(key, "v1/blob/")
		if recordIDs[id] {
			recordBlob = key
			break
		}
	}
	if recordBlob == "" {
		t.Fatal("no record blob found")
	}
	orig, err := store.Get(context.Background(), recordBlob)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), storage.Object{Path: recordBlob, Data: append([]byte("corrupt"), orig...), ContentType: "application/json", Immutable: true}); err != nil {
		t.Fatal(err)
	}

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Corrupt {
		t.Fatalf("expected corrupt: %+v", res)
	}
	found := false
	for _, d := range res.Details {
		if strings.Contains(d, "signature verify") || strings.Contains(d, "unmarshal") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected signature detail, got %v", res.Details)
	}
}

func TestMissingLeaf(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	makeLog(t, store, signer, 3)
	keys, err := store.List(context.Background(), "v1/leaf")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), keys[0]); err != nil {
		t.Fatal(err)
	}

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Corrupt {
		t.Fatalf("expected corrupt: %+v", res)
	}
	found := false
	for _, d := range res.Details {
		if strings.Contains(d, "missing leaf index") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing leaf detail, got %v", res.Details)
	}
}

func TestDuplicateLeafIndex(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	makeLog(t, store, signer, 3)
	keys, err := store.List(context.Background(), "v1/leaf")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("keys=%v", keys)
	data, err := store.Get(context.Background(), keys[0])
	if err != nil {
		t.Fatal(err)
	}
	// Write a non-canonical duplicate path. Strict path validation must report
	// corruption even though it cannot be treated as a second canonical leaf.
	jsonPath := keys[0] + ".json"
	if err := store.Put(context.Background(), storage.Object{Path: jsonPath, Data: data, ContentType: "application/json", Immutable: true}); err != nil {
		t.Fatal(err)
	}

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Corrupt {
		t.Fatalf("expected corrupt: %+v", res)
	}
	found := false
	for _, d := range res.Details {
		if strings.Contains(d, "duplicate leaf index") || strings.Contains(d, "invalid leaf index path") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected duplicate leaf detail, got %v", res.Details)
	}
}

func TestMonitorAcceptsAuthenticatedTombstone(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}

	audit, _, operatorPriv := makeRecord(t, store, "tombstoned-audit")
	auditID, err := schema.RecordID(audit.Body)
	if err != nil {
		t.Fatal(err)
	}
	tombstone, err := json.Marshal(tlogx.Tombstone{
		Tombstone: true,
		RecordID:  auditID,
		Reason:    "privacy",
		Message:   "Deletion never substitutes for rotation.",
		DeletedAt: "2026-08-02T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	operatorPub := operatorPriv.Public().(ed25519.PublicKey)
	moderation, err := schema.Sign(schema.RecordBody{
		Type:            schema.SchemaModerationV1,
		CreatedAt:       time.Now().Unix() + 1,
		Auditor:         schema.AuditorHash(hex.EncodeToString(operatorPub)),
		BlobSHA256:      auditID,
		TombstoneSHA256: tlogx.TombstoneSHA256(tombstone),
		Reason:          "tombstone",
	}, operatorPriv)
	if err != nil {
		t.Fatal(err)
	}

	tr := tlogx.NewTree()
	for _, rec := range []schema.Record{audit, *moderation} {
		leaf, err := tlogx.RecordToLeaf(rec)
		if err != nil {
			t.Fatal(err)
		}
		index, err := tr.AppendLeaf(leaf)
		if err != nil {
			t.Fatal(err)
		}
		if err := tlogx.WriteRecord(store, index, rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Put(t.Context(), storage.Object{
		Path: "v1/blob/" + auditID,
		Data: tombstone,
	}); err != nil {
		t.Fatal(err)
	}
	// The tombstoned audit's target content is no longer referenced by an
	// authenticated audit record.
	if err := store.Delete(context.Background(), storage.BlobPath(audit.Body.Target.SHA256)); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteTiles(tr, store, tlogx.DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteCheckpoint(tr.TlogTree(), "test", signer, store); err != nil {
		t.Fatal(err)
	}
	// No target remains available for lookup after the only audit is
	// tombstoned, so the expected prefix shard set is empty.

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.Corrupt || !res.Verified {
		t.Fatalf("authenticated tombstone rejected: %+v", res)
	}
	if res.Records != 0 {
		t.Fatalf("tombstoned audit must not be scored, records=%d", res.Records)
	}
}

func TestMonitorRejectsUnauthenticatedTombstone(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	tr, records := makeLog(t, store, signer, 1)
	auditID, err := schema.RecordID(records[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	tombstone, err := json.Marshal(tlogx.Tombstone{
		Tombstone: true,
		RecordID:  auditID,
		Reason:    "privacy",
		Message:   "Deletion never substitutes for rotation.",
		DeletedAt: "2026-08-02T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(t.Context(), storage.Object{Path: "v1/blob/" + auditID, Data: tombstone}); err != nil {
		t.Fatal(err)
	}
	_ = tr

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || !res.Corrupt {
		t.Fatalf("expected unauthenticated tombstone corruption: %+v", res)
	}
	found := false
	for _, detail := range res.Details {
		if strings.Contains(detail, "no later matching moderation") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing tombstone binding detail: %v", res.Details)
	}
}

func TestCorruptTile(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	makeLog(t, store, signer, 3)
	keys, err := store.List(context.Background(), "v1/tile")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("expected tiles")
	}
	data, err := store.Get(context.Background(), keys[0])
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 0xff
	if err := store.Put(context.Background(), storage.Object{Path: keys[0], Data: data, ContentType: "application/octet-stream", Immutable: true}); err != nil {
		t.Fatal(err)
	}

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Corrupt {
		t.Fatalf("expected corrupt: %+v", res)
	}
	found := false
	for _, d := range res.Details {
		if strings.Contains(d, "inclusion proof") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected inclusion proof detail, got %v", res.Details)
	}
}

func TestCorruptShard(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	makeLog(t, store, signer, 3)
	keys, err := store.List(context.Background(), "v1/prefix")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("expected shards")
	}
	data, err := store.Get(context.Background(), keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), storage.Object{Path: keys[0], Data: append(data, []byte("\n")...), ContentType: "application/json", CacheSeconds: 300}); err != nil {
		t.Fatal(err)
	}

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Corrupt {
		t.Fatalf("expected corrupt: %+v", res)
	}
	found := false
	for _, d := range res.Details {
		if strings.Contains(d, "shard") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected shard detail, got %v", res.Details)
	}
}

func TestWebhook(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	makeLog(t, store, signer, 3)
	keys, err := store.List(context.Background(), "v1/tile")
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Get(context.Background(), keys[0])
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 0xff
	if err := store.Put(context.Background(), storage.Object{Path: keys[0], Data: data, ContentType: "application/octet-stream", Immutable: true}); err != nil {
		t.Fatal(err)
	}

	var received []byte
	var contentType string
	var userAgent string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		contentType = r.Header.Get("Content-Type")
		userAgent = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = false
	srv.Start()
	defer srv.Close()

	cfg := &config{
		storage:        filepath.Join(dir, "store"),
		policyPath:     writePolicy(t, dir, vkey),
		oneShot:        true,
		webhook:        srv.URL,
		webhookRetries: 1,
		webhookTimeout: 5 * time.Second,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Corrupt {
		t.Fatalf("expected corrupt: %+v", res)
	}
	if len(received) == 0 {
		t.Fatal("webhook did not receive body")
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("webhook payload: %v", err)
	}
	if payload["corrupt"] != true {
		t.Fatalf("expected corrupt in webhook payload: %v", payload)
	}
	if contentType != "application/json" {
		t.Fatalf("content type: %s", contentType)
	}
	if userAgent != appmeta.UserAgent() {
		t.Fatalf("user agent: %s", userAgent)
	}
}

func TestHTTPBaseURL(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	makeLog(t, store, signer, 3)

	srv := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(dir, "store"))))
	defer srv.Close()

	cfg := &config{
		baseURL:        srv.URL,
		policyPath:     writePolicy(t, dir, vkey),
		checkpointPath: filepath.Join(dir, "state.toml"),
		oneShot:        true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Verified || res.Corrupt || res.Size != 3 {
		t.Fatalf("result: %+v", res)
	}
}

func TestOneShot(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	makeLog(t, store, signer, 2)

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
		interval:   time.Hour,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Verified || res.Size != 2 {
		t.Fatalf("result: %+v", res)
	}
	if res.Time == "" || res.Agent == "" || res.ScoreParams == "" {
		t.Fatalf("missing fields: %+v", res)
	}
}

func TestRetraction(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	tr := tlogx.NewTree()
	rec, leaf, priv := makeRecord(t, store, "target")
	idx, err := tr.AppendLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteRecord(store, idx, rec); err != nil {
		t.Fatal(err)
	}
	retract := makeRetraction(t, rec, priv)
	retractLeaf, err := tlogx.RecordToLeaf(retract)
	if err != nil {
		t.Fatal(err)
	}
	idx2, err := tr.AppendLeaf(retractLeaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteRecord(store, idx2, retract); err != nil {
		t.Fatal(err)
	}
	records := []schema.Record{rec, retract}
	if err := tlogx.WriteTiles(tr, store, tlogx.DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteCheckpoint(tr.TlogTree(), "test", signer, store); err != nil {
		t.Fatal(err)
	}
	_, kept, _ := applyRetractions(records, []schema.Record{retract}, nil)
	writeShards(t, store, kept)

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Verified || res.Retractions != 1 || res.Records != 0 || res.Shards != 0 {
		t.Fatalf("retraction result: %+v", res)
	}
}

func TestEmptyLog(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	tr := tlogx.NewTree()
	if err := tlogx.WriteCheckpoint(tr.TlogTree(), "test", signer, store); err != nil {
		t.Fatal(err)
	}

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Verified || res.Size != 0 || res.Records != 0 || res.Shards != 0 {
		t.Fatalf("empty log result: %+v", res)
	}
}

func TestOrphanBlob(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	makeLog(t, store, signer, 2)
	rec, _, _ := makeRecord(t, nil, "orphan")
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	id, err := schema.RecordID(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), storage.Object{Path: "v1/blob/" + id, Data: data, ContentType: "application/json", Immutable: true}); err != nil {
		t.Fatal(err)
	}

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Corrupt {
		t.Fatalf("expected corrupt: %+v", res)
	}
	found := false
	for _, d := range res.Details {
		if strings.Contains(d, "orphan blob") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected orphan blob detail, got %v", res.Details)
	}
}

func TestReferencedBlobMissingTarget(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	tr := tlogx.NewTree()
	rec, leaf, _ := makeRecord(t, store, "missing-target")
	idx, err := tr.AppendLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteRecord(store, idx, rec); err != nil {
		t.Fatal(err)
	}
	// Remove the target content blob so the referenced hash cannot be verified.
	if err := store.Delete(context.Background(), storage.BlobPath(rec.Body.Target.SHA256)); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteTiles(tr, store, tlogx.DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteCheckpoint(tr.TlogTree(), "test", signer, store); err != nil {
		t.Fatal(err)
	}
	writeShards(t, store, []schema.Record{rec})

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Corrupt {
		t.Fatalf("expected corrupt: %+v", res)
	}
	found := false
	for _, d := range res.Details {
		if strings.Contains(d, "missing referenced content blob") && strings.Contains(d, rec.Body.Target.SHA256) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing referenced content blob detail, got %v", res.Details)
	}
}

func TestReferencedBlobTamperedTarget(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	tr := tlogx.NewTree()
	rec, leaf, _ := makeRecord(t, store, "tampered-target")
	idx, err := tr.AppendLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteRecord(store, idx, rec); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), storage.Object{
		Path:        storage.BlobPath(rec.Body.Target.SHA256),
		Data:        []byte("tampered"),
		ContentType: "application/octet-stream",
		Immutable:   true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteTiles(tr, store, tlogx.DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteCheckpoint(tr.TlogTree(), "test", signer, store); err != nil {
		t.Fatal(err)
	}
	writeShards(t, store, []schema.Record{rec})

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Corrupt {
		t.Fatalf("expected corrupt: %+v", res)
	}
	found := false
	for _, d := range res.Details {
		if strings.Contains(d, "referenced content blob hash mismatch") && strings.Contains(d, rec.Body.Target.SHA256) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected referenced content blob hash mismatch detail, got %v", res.Details)
	}
}

func TestReferencedBlobMissingPrompt(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	tr := tlogx.NewTree()
	targetData := []byte("target for missing prompt")
	promptData := []byte("prompt for missing prompt")
	rec, leaf, _ := makeLLMRecord(t, store, "missing-prompt", targetData, promptData)
	idx, err := tr.AppendLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteRecord(store, idx, rec); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), storage.BlobPath(rec.Body.Analyzer.PromptSHA256)); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteTiles(tr, store, tlogx.DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteCheckpoint(tr.TlogTree(), "test", signer, store); err != nil {
		t.Fatal(err)
	}
	writeShards(t, store, []schema.Record{rec})

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Corrupt {
		t.Fatalf("expected corrupt: %+v", res)
	}
	found := false
	for _, d := range res.Details {
		if strings.Contains(d, "missing referenced content blob") && strings.Contains(d, rec.Body.Analyzer.PromptSHA256) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing referenced content blob detail, got %v", res.Details)
	}
}

func TestReferencedBlobTamperedPrompt(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	tr := tlogx.NewTree()
	targetData := []byte("target for tampered prompt")
	promptData := []byte("prompt for tampered prompt")
	rec, leaf, _ := makeLLMRecord(t, store, "tampered-prompt", targetData, promptData)
	idx, err := tr.AppendLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteRecord(store, idx, rec); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), storage.Object{
		Path:        storage.BlobPath(rec.Body.Analyzer.PromptSHA256),
		Data:        []byte("tampered"),
		ContentType: "application/octet-stream",
		Immutable:   true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteTiles(tr, store, tlogx.DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteCheckpoint(tr.TlogTree(), "test", signer, store); err != nil {
		t.Fatal(err)
	}
	writeShards(t, store, []schema.Record{rec})

	cfg := &config{
		storage:    filepath.Join(dir, "store"),
		policyPath: writePolicy(t, dir, vkey),
		oneShot:    true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Corrupt {
		t.Fatalf("expected corrupt: %+v", res)
	}
	found := false
	for _, d := range res.Details {
		if strings.Contains(d, "referenced content blob hash mismatch") && strings.Contains(d, rec.Body.Analyzer.PromptSHA256) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected referenced content blob hash mismatch detail, got %v", res.Details)
	}
}

func TestHTTPReferencedBlobMissing(t *testing.T) {
	signer, vkey := testKey(t)
	dir := t.TempDir()
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	tr := tlogx.NewTree()
	targetData := []byte("target for http missing")
	promptData := []byte("prompt for http missing")
	rec, leaf, _ := makeLLMRecord(t, store, "http-missing", targetData, promptData)
	idx, err := tr.AppendLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteRecord(store, idx, rec); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteTiles(tr, store, tlogx.DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	if err := tlogx.WriteCheckpoint(tr.TlogTree(), "test", signer, store); err != nil {
		t.Fatal(err)
	}
	writeShards(t, store, []schema.Record{rec})
	// Remove the prompt blob after the log is published so the HTTP monitor
	// must detect the missing referenced content blob without a directory listing.
	if err := store.Delete(context.Background(), storage.BlobPath(rec.Body.Analyzer.PromptSHA256)); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(dir, "store"))))
	defer srv.Close()

	cfg := &config{
		baseURL:        srv.URL,
		policyPath:     writePolicy(t, dir, vkey),
		checkpointPath: filepath.Join(dir, "state.toml"),
		oneShot:        true,
	}
	res, err := runWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res == nil || !res.Corrupt {
		t.Fatalf("expected corrupt: %+v", res)
	}
	found := false
	for _, d := range res.Details {
		if strings.Contains(d, "missing referenced content blob") && strings.Contains(d, rec.Body.Analyzer.PromptSHA256) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected missing referenced content blob detail, got %v", res.Details)
	}
}

func TestConfigValidation(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig }()
	os.Args = []string{"ebi-monitor"}
	if _, err := parseConfig(); err == nil {
		t.Fatal("expected error")
	}
}

func TestScoreParams(t *testing.T) {
	if scoreParamsString() == "" {
		t.Fatal("empty score params")
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(scoreParamsString()), &m); err != nil {
		t.Fatal(err)
	}
	if m["version"] != score.ParamsVersion {
		t.Fatalf("version: %v", m["version"])
	}
}

func TestWriteResult(t *testing.T) {
	res := &monitorResult{
		Time:     time.Now().UTC().Format(time.RFC3339),
		Verified: true,
		Size:     5,
		Records:  5,
	}
	var buf bytes.Buffer
	if err := writeResult(res, &buf); err != nil {
		t.Fatal(err)
	}
	var got monitorResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Verified || got.Size != 5 || got.Records != 5 {
		t.Fatalf("got %+v", got)
	}
}

func TestHTTPStoreDirListing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "c.txt"), []byte("c"), 0644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()
	s := newHTTPStore(srv.URL)
	keys, err := s.List(context.Background(), "")
	if err != nil {
		t.Fatalf("list root: %v", err)
	}
	got := map[string]bool{}
	for _, k := range keys {
		got[k] = true
	}
	if !got["a.txt"] || !got["b.txt"] {
		t.Fatalf("missing files in %v", keys)
	}
	if got["sub/c.txt"] {
		t.Fatal("unexpected recursive entry")
	}
}

func TestHTTPStoreListSubdir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "v1"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "v1", "a.txt"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()
	s := newHTTPStore(srv.URL)
	keys, err := s.List(context.Background(), "v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "v1/a.txt" {
		t.Fatalf("got %v", keys)
	}
}

func TestHTTPStoreReadWrite(t *testing.T) {
	s := newHTTPStore("http://example.com")
	if err := s.Put(context.Background(), storage.Object{Path: "x"}); err == nil {
		t.Fatal("expected Put error")
	}
	if err := s.Delete(context.Background(), "x"); err == nil {
		t.Fatal("expected Delete error")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookRetries(t *testing.T) {
	posts := 0
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	srv.EnableHTTP2 = false
	srv.Start()
	defer srv.Close()
	res := &monitorResult{Corrupt: true, Error: "x"}
	if err := sendWebhook(t.Context(), srv.URL, res, 2, time.Second); err == nil {
		t.Fatal("expected error")
	}
	if posts != 3 {
		t.Fatalf("POSTs: %d", posts)
	}
}

func TestWebhookTimeout(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = false
	srv.Start()
	defer srv.Close()
	res := &monitorResult{Corrupt: true, Error: "x"}
	if err := sendWebhook(t.Context(), srv.URL, res, 0, 5*time.Millisecond); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseDirList(t *testing.T) {
	html := `<html><body><a href="a.txt">a</a><a href="../">parent</a><a href="sub/">sub</a></body></html>`
	out, err := parseDirList("http://example.com/p/", html, "p")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0] != "p/a.txt" {
		t.Fatalf("got %v", out)
	}
}

func TestParseDirListAbsolute(t *testing.T) {
	html := `<a href="http://example.com/p/file.txt">f</a>`
	out, err := parseDirList("http://example.com/p/", html, "p")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0] != "p/file.txt" {
		t.Fatalf("got %v", out)
	}
}

func TestParseDirListDifferentHost(t *testing.T) {
	html := `<a href="http://other.com/p/file.txt">f</a>`
	out, err := parseDirList("http://example.com/p/", html, "p")
	if err != nil || len(out) != 0 {
		t.Fatal(err, out)
	}
}

func TestParseDirListNestedSkip(t *testing.T) {
	html := `<a href="sub/">sub</a>`
	out, err := parseDirList("http://example.com/p/", html, "p")
	if err != nil || len(out) != 0 {
		t.Fatal(err, out)
	}
}

func TestParseDirListFragmentQuery(t *testing.T) {
	html := `<a href="file.txt?x=1#frag">f</a>`
	out, err := parseDirList("http://example.com/p/", html, "p")
	if err != nil || len(out) != 1 || out[0] != "p/file.txt" {
		t.Fatal(err, out)
	}
}
