package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/co3k/ebi/pkg/fetch"
	"github.com/co3k/ebi/pkg/llm"
	"github.com/co3k/ebi/pkg/prefixdb"
	"github.com/co3k/ebi/pkg/schema"
	"github.com/co3k/ebi/pkg/secrets"
	"github.com/co3k/ebi/pkg/storage"
	"github.com/co3k/ebi/pkg/tlogx"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func newTestServer(t *testing.T) (*Server, func()) {
	t.Helper()
	ctx := context.Background()
	cfg := DefaultServerConfig()
	cfg.DataDir = t.TempDir()
	cfg.LogKeyFile = filepath.Join(cfg.DataDir, "log-key")
	cfg.CheckpointState = filepath.Join(cfg.DataDir, "checkpoint-state")

	s, err := NewServer(ctx, cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := s.StartSequencer(ctx); err != nil {
		t.Fatalf("start sequencer: %v", err)
	}
	return s, func() {
		_ = s.Shutdown(ctx)
	}
}

type testC2SPWitnessSigner struct {
	name      string
	hash      uint32
	private   ed25519.PrivateKey
	timestamp uint64
}

func (s *testC2SPWitnessSigner) Name() string    { return s.name }
func (s *testC2SPWitnessSigner) KeyHash() uint32 { return s.hash }
func (s *testC2SPWitnessSigner) Sign(checkpoint []byte) ([]byte, error) {
	message := []byte(fmt.Sprintf("cosignature/v1\ntime %d\n%s", s.timestamp, checkpoint))
	out := make([]byte, 8+ed25519.SignatureSize)
	binary.BigEndian.PutUint64(out[:8], s.timestamp)
	copy(out[8:], ed25519.Sign(s.private, message))
	return out, nil
}

func testC2SPWitnessKey(t *testing.T, name string) (note.Signer, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := append([]byte{0x04}, pub...)
	h := sha256.New()
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte("\n"))
	_, _ = h.Write(encoded)
	hash := binary.BigEndian.Uint32(h.Sum(nil)[:4])
	key := fmt.Sprintf("%s+%08x+%s", name, hash, base64.StdEncoding.EncodeToString(encoded))
	return &testC2SPWitnessSigner{name: name, hash: hash, private: priv, timestamp: 1_785_715_200}, key
}

func TestAutomaticC2SPWitnessCollection(t *testing.T) {
	witnessSigner, witnessKey := testC2SPWitnessKey(t, "witness.example/w1")
	witness := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		split := bytes.Index(body, []byte("\n\n"))
		if split < 0 {
			t.Errorf("malformed witness request: %q", body)
			http.Error(w, "malformed", http.StatusBadRequest)
			return
		}
		checkpoint := body[split+2:]
		textEnd := bytes.Index(checkpoint, []byte("\n\n— "))
		if textEnd < 0 {
			t.Errorf("missing checkpoint signature block: %q", checkpoint)
			http.Error(w, "malformed", http.StatusBadRequest)
			return
		}
		cosigned, err := note.Sign(&note.Note{Text: string(checkpoint[:textEnd+1])}, witnessSigner)
		if err != nil {
			t.Error(err)
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		signatureBlock := cosigned[bytes.Index(cosigned, []byte("\n\n"))+2:]
		w.Header().Set("Content-Type", "text/x.tlog.cosignature")
		_, _ = w.Write(signatureBlock)
	}))
	defer witness.Close()

	ctx := t.Context()
	cfg := DefaultServerConfig()
	cfg.DataDir = t.TempDir()
	cfg.LogKeyFile = filepath.Join(cfg.DataDir, "log-key")
	cfg.CheckpointState = filepath.Join(cfg.DataDir, "checkpoint-state")
	cfg.WitnessKeys = []string{witnessKey}
	cfg.WitnessURLs = []string{witness.URL}
	cfg.RequiredWitnesses = 1
	s, err := NewServer(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StartSequencer(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)

	deadline := time.Now().Add(2 * time.Second)
	var checkpoint tlog.Tree
	for {
		checkpoint, _, err = tlogx.ReadCheckpoint(s.Store(), s.Policy())
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("published checkpoint did not meet witness quorum: %v", err)
	}
	if checkpoint.N != 0 {
		t.Fatalf("unexpected initial tree size %d", checkpoint.N)
	}
	if _, err := s.Store().Get(ctx, pendingCheckpointPath); !storage.IsNotFound(err) {
		t.Fatalf("pending checkpoint was not cleaned: %v", err)
	}
}

func TestSlowWitnessDoesNotBlockHealthOrSubmission(t *testing.T) {
	witnessSigner, witnessKey := testC2SPWitnessKey(t, "witness.example/slow")
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	witness := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		select {
		case <-r.Context().Done():
			return
		case <-release:
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		split := bytes.Index(body, []byte("\n\n"))
		if split < 0 {
			http.Error(w, "malformed", http.StatusBadRequest)
			return
		}
		checkpoint := body[split+2:]
		textEnd := bytes.Index(checkpoint, []byte("\n\n— "))
		if textEnd < 0 {
			http.Error(w, "malformed", http.StatusBadRequest)
			return
		}
		cosigned, err := note.Sign(&note.Note{Text: string(checkpoint[:textEnd+1])}, witnessSigner)
		if err != nil {
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(cosigned[bytes.Index(cosigned, []byte("\n\n"))+2:])
	}))
	defer witness.Close()

	ctx := t.Context()
	cfg := DefaultServerConfig()
	cfg.Port = "0"
	cfg.DataDir = t.TempDir()
	cfg.LogKeyFile = filepath.Join(cfg.DataDir, "log-key")
	cfg.CheckpointState = filepath.Join(cfg.DataDir, "checkpoint-state")
	cfg.WitnessKeys = []string{witnessKey}
	cfg.WitnessURLs = []string{witness.URL}
	cfg.RequiredWitnesses = 1
	cfg.RequestTimeout = time.Second
	s, err := NewServer(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(release)
		_ = s.Shutdown(ctx)
	}()

	start := time.Now()
	if err := s.StartSequencer(ctx); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("sequencer startup waited for witness: %v", elapsed)
	}
	<-started
	if err := s.StartHTTP(ctx); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 200 * time.Millisecond}
	resp, err := client.Get("http://" + s.Addr() + "/healthz")
	if err != nil {
		t.Fatalf("health blocked by witness: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status %d", resp.StatusCode)
	}

	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)
	key := newAuditorKey(t)
	targetURL := "https://example.com/pending-witness.sh"
	content := []byte("echo pending\n")
	fetcher.set(targetURL, content)
	rec := makeAuditRecord(t, key, targetURL, content, nil)
	payload, _ := marshalSubmit(rec)
	requestStart := time.Now()
	w := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w, http.StatusAccepted)
	if elapsed := time.Since(requestStart); elapsed > 200*time.Millisecond {
		t.Fatalf("submission waited for witness: %v", elapsed)
	}
	if body := decodeMap(t, w.Body.Bytes()); body["pending"] != true {
		t.Fatalf("expected pending witness response: %v", body)
	}
}

func newTestFetcher() *testFetcher {
	return &testFetcher{data: make(map[string][]byte)}
}

type testFetcher struct {
	data map[string][]byte
	err  error
}

func (f *testFetcher) set(url string, content []byte) {
	f.data[url] = content
}

func (f *testFetcher) Fetch(ctx context.Context, rawURL string, opts fetch.Options) (*fetch.Fetched, error) {
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.data[rawURL]
	if !ok {
		return nil, fmt.Errorf("test fetch: not found: %s", rawURL)
	}
	tmp, err := os.CreateTemp("", "ebi-test-fetch-*")
	if err != nil {
		return nil, err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}
	_ = os.Chmod(tmp.Name(), 0600)
	sum := sha256.Sum256(b)
	return &fetch.Fetched{
		Path: tmp.Name(),
		Size: int64(len(b)),
		Hash: hex.EncodeToString(sum[:]),
		URL:  rawURL,
	}, nil
}

type blockingGetStore struct {
	storage.Store
	path    string
	blockAt int
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	count   int
	once    sync.Once
}

func (s *blockingGetStore) Get(ctx context.Context, path string) ([]byte, error) {
	if path != s.path {
		return s.Store.Get(ctx, path)
	}
	s.mu.Lock()
	s.count++
	count := s.count
	s.mu.Unlock()
	if count != s.blockAt {
		return s.Store.Get(ctx, path)
	}
	s.once.Do(func() { close(s.started) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.release:
	}
	return s.Store.Get(ctx, path)
}

func (s *blockingGetStore) CompareAndSwap(ctx context.Context, path string, old []byte, obj storage.Object) (bool, error) {
	return s.Store.(storage.AtomicStore).CompareAndSwap(ctx, path, old, obj)
}

func (s *blockingGetStore) CompareAndDelete(ctx context.Context, path string, old []byte) (bool, error) {
	return s.Store.(storage.AtomicStore).CompareAndDelete(ctx, path, old)
}

type getErrorStore struct {
	storage.Store
	path string
	err  error
}

func (s *getErrorStore) Get(ctx context.Context, path string) ([]byte, error) {
	if path == s.path {
		return nil, s.err
	}
	return s.Store.Get(ctx, path)
}

func (s *getErrorStore) CompareAndSwap(ctx context.Context, path string, old []byte, obj storage.Object) (bool, error) {
	return s.Store.(storage.AtomicStore).CompareAndSwap(ctx, path, old, obj)
}

func (s *getErrorStore) CompareAndDelete(ctx context.Context, path string, old []byte) (bool, error) {
	return s.Store.(storage.AtomicStore).CompareAndDelete(ctx, path, old)
}

type putErrorStore struct {
	storage.Store
	path string
	err  error
}

func (s *putErrorStore) Put(ctx context.Context, obj storage.Object) error {
	if obj.Path == s.path {
		return s.err
	}
	return s.Store.Put(ctx, obj)
}

func (s *putErrorStore) CompareAndSwap(ctx context.Context, path string, old []byte, obj storage.Object) (bool, error) {
	return s.Store.(storage.AtomicStore).CompareAndSwap(ctx, path, old, obj)
}

func (s *putErrorStore) CompareAndDelete(ctx context.Context, path string, old []byte) (bool, error) {
	return s.Store.(storage.AtomicStore).CompareAndDelete(ctx, path, old)
}

func TestFetchFailureDoesNotCreatePendingMismatch(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	fetcher.err = fmt.Errorf("temporary network failure")
	s.SetFetcher(fetcher)

	key := newAuditorKey(t)
	url := "https://example.com/script.sh"
	content := []byte("echo hello\n")
	rec := makeAuditRecord(t, key, url, content, nil)
	payload, _ := marshalSubmit(rec)
	w := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w, http.StatusBadGateway)

	id, err := schema.RecordID(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store().Get(t.Context(), "v1/pending/"+id); !storage.IsNotFound(err) {
		t.Fatalf("transient fetch failure must not create pending mismatch: %v", err)
	}
	if s.Tree().Size() != 0 {
		t.Fatalf("fetch failure unexpectedly appended a leaf: %d", s.Tree().Size())
	}
}

func TestClaimLineMismatchIsRejectedNotPending(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)

	key := newAuditorKey(t)
	url := "https://example.com/script.sh"
	content := []byte("echo hello\n")
	fetcher.set(url, content)
	rec := makeAuditRecord(t, key, url, content, []schema.Claim{{
		Category:   "net.fetch",
		Line:       1,
		LineSHA256: strings.Repeat("a", 64),
	}})
	payload, _ := marshalSubmit(rec)
	w := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w, http.StatusBadRequest)

	id, err := schema.RecordID(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store().Get(t.Context(), "v1/pending/"+id); !storage.IsNotFound(err) {
		t.Fatalf("bad claims must not create pending mismatch: %v", err)
	}
	if s.Tree().Size() != 0 {
		t.Fatalf("bad claims unexpectedly appended a leaf: %d", s.Tree().Size())
	}
}

type auditorKey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   string
}

func newAuditorKey(t *testing.T) auditorKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	return auditorKey{priv: priv, pub: pub, id: schema.AuditorHash(hex.EncodeToString(pub))}
}

func makeAuditRecord(t *testing.T, key auditorKey, url string, content []byte, claims []schema.Claim) schema.Record {
	t.Helper()
	sum := sha256.Sum256(content)
	h := hex.EncodeToString(sum[:])
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: time.Now().UTC().Unix(),
		Auditor:   key.id,
		Target:    schema.Target{URL: url, SHA256: h, Size: int64(len(content))},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictOK,
		Claims:    claims,
	}
	if len(claims) > 0 {
		body.Verdict = schema.VerdictDanger
	}
	rec, err := schema.Sign(body, key.priv)
	if err != nil {
		t.Fatalf("sign record: %v", err)
	}
	return *rec
}

func makeRetractionRecord(t *testing.T, key auditorKey, target schema.Record) schema.Record {
	t.Helper()
	targetID, err := schema.RecordID(target.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := schema.RecordBody{
		Type:      schema.SchemaRetractV1,
		CreatedAt: time.Now().UTC().Unix(),
		Auditor:   key.id,
		RecordID:  targetID,
		Reason:    "false-positive",
	}
	rec, err := schema.Sign(body, key.priv)
	if err != nil {
		t.Fatalf("sign retraction: %v", err)
	}
	return *rec
}

func linesFromContent(content string) []string {
	return strings.Split(strings.TrimSuffix(content, "\n"), "\n")
}

func claimsForLines(content string) []schema.Claim {
	lines := linesFromContent(content)
	claims := make([]schema.Claim, len(lines))
	for i, line := range lines {
		claims[i] = schema.Claim{
			Category:   "net.fetch",
			Line:       i + 1,
			LineSHA256: schema.LineHash(line),
		}
	}
	return claims
}

func marshalSubmit(value any) ([]byte, error) {
	var rec schema.Record
	switch v := value.(type) {
	case schema.Record:
		rec = v
	case *schema.Record:
		if v == nil {
			return nil, fmt.Errorf("nil record")
		}
		rec = *v
	default:
		return nil, fmt.Errorf("unsupported record type %T", value)
	}
	return json.Marshal(submitRecordRequest{
		Record: rec.Body, PublicKey: rec.PublicKey, Signature: rec.Signature,
	})
}

func postJSON(t *testing.T, handler http.Handler, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(w, req)
	return w
}

func get(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	handler.ServeHTTP(w, req)
	return w
}

func mustStatus(t *testing.T, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("expected status %d, got %d: %s", code, w.Code, w.Body.String())
	}
}

func decodeMap(t *testing.T, data []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

func TestE2EAppendAndVerify(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)

	key := newAuditorKey(t)
	url := "https://example.com/script.sh"
	content1 := "echo hello\n"
	content2 := "echo world\n"
	fetcher.set(url, []byte(content1))

	rec1 := makeAuditRecord(t, key, url, []byte(content1), claimsForLines(content1))
	payload1, _ := marshalSubmit(rec1)
	w1 := postJSON(t, s.Handler(), "/v1/records", payload1)
	mustStatus(t, w1, http.StatusAccepted)

	// Reconfigure the fetcher to return the second record's content.
	fetcher.set(url, []byte(content2))
	time.Sleep(2 * time.Second)
	rec2 := makeAuditRecord(t, key, url, []byte(content2), claimsForLines(content2))
	rec2ptr, err := schema.Sign(rec2.Body, key.priv)
	if err != nil {
		t.Fatal(err)
	}
	rec2 = *rec2ptr
	payload2, _ := marshalSubmit(rec2)
	w2 := postJSON(t, s.Handler(), "/v1/records", payload2)
	mustStatus(t, w2, http.StatusAccepted)

	if s.Tree().Size() != 2 {
		t.Fatalf("expected tree size 2, got %d", s.Tree().Size())
	}

	ctx := context.Background()
	cp, _, err := tlogx.ReadCheckpoint(s.Store(), s.Policy())
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	if cp.N != 2 {
		t.Fatalf("expected checkpoint size 2, got %d", cp.N)
	}

	leaves, err := tlogx.LoadLeavesFromIndex(s.Store())
	if err != nil {
		t.Fatalf("load leaves: %v", err)
	}
	for i, leaf := range leaves {
		lh, err := tlogx.LeafHash(leaf)
		if err != nil {
			t.Fatal(err)
		}
		if err := tlogx.VerifyInclusionAt(s.Store(), int64(i), lh, cp, s.Policy()); err != nil {
			t.Fatalf("inclusion proof for leaf %d: %v", i, err)
		}
	}

	// Prefix shard.
	prefix := prefixdb.Prefix(rec1.Body.Target.SHA256)
	shardData, err := s.Store().Get(ctx, storage.PrefixPath(prefix))
	if err != nil {
		t.Fatalf("read shard: %v", err)
	}
	entries, err := prefixdb.MatchExact(shardData, rec1.Body.Target.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 shard entry for first target, got %d", len(entries))
	}
	targetBlob, err := s.Store().Get(ctx, storage.BlobPath(rec1.Body.Target.SHA256))
	if err != nil {
		t.Fatalf("read server-fetched target blob: %v", err)
	}
	if string(targetBlob) != content1 {
		t.Fatalf("target blob mismatch: %q", targetBlob)
	}
}

func TestLLMPromptBlobIsReproducible(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)

	key := newAuditorKey(t)
	targetURL := "https://example.com/llm.sh"
	content := []byte("sudo true\n")
	fetcher.set(targetURL, content)
	prompt := llm.BuildPrompt(string(content))
	promptHash := llm.PromptHash(prompt)
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: time.Now().Unix(),
		Auditor:   key.id,
		Target: schema.Target{
			URL:    targetURL,
			SHA256: storage.ContentHash(content),
			Size:   int64(len(content)),
		},
		Analyzer: schema.Analyzer{
			Kind:         schema.KindLLM,
			Model:        "qwen2.5-coder",
			ModelFamily:  "qwen",
			Quantization: "q4_k_m",
			Backend:      "ollama",
			PromptSHA256: promptHash,
			Runs:         5,
			Agreement:    1,
		},
		Verdict: schema.VerdictDanger,
		Claims: []schema.Claim{{
			Category:   "priv.sudo",
			Line:       1,
			LineSHA256: schema.LineHash("sudo true"),
		}},
	}
	rec, err := schema.Sign(body, key.priv)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := marshalSubmit(rec)
	w := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w, http.StatusAccepted)

	promptBlob, err := s.Store().Get(t.Context(), storage.BlobPath(promptHash))
	if err != nil {
		t.Fatalf("read prompt blob: %v", err)
	}
	if !bytes.Equal(promptBlob, llm.PromptBytes(prompt)) {
		t.Fatal("published prompt blob is not the hashed reproducibility artifact")
	}
}

func TestRestartPreservesState(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultServerConfig()
	cfg.DataDir = t.TempDir()
	cfg.LogKeyFile = filepath.Join(cfg.DataDir, "log-key")
	cfg.CheckpointState = filepath.Join(cfg.DataDir, "checkpoint-state")

	s1, err := NewServer(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.StartSequencer(ctx); err != nil {
		t.Fatal(err)
	}
	fetcher := newTestFetcher()
	s1.SetFetcher(fetcher)

	key := newAuditorKey(t)
	url := "https://example.com/script.sh"
	content := "echo hello\n"
	fetcher.set(url, []byte(content))
	rec1 := makeAuditRecord(t, key, url, []byte(content), claimsForLines(content))
	payload1, _ := marshalSubmit(rec1)
	w1 := postJSON(t, s1.Handler(), "/v1/records", payload1)
	mustStatus(t, w1, http.StatusAccepted)

	oldCP, _, err := tlogx.ReadCheckpoint(s1.Store(), s1.Policy())
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	s2, err := NewServer(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.StartSequencer(ctx); err != nil {
		t.Fatal(err)
	}
	defer s2.Shutdown(ctx)
	s2.SetFetcher(fetcher)

	if s2.Tree().Size() != 1 {
		t.Fatalf("expected tree size 1 after restart, got %d", s2.Tree().Size())
	}

	time.Sleep(2 * time.Second)
	rec2 := makeAuditRecord(t, key, url, []byte(content), claimsForLines(content))
	rec2.Body.CreatedAt = time.Now().UTC().Unix()
	rec2ptr, err := schema.Sign(rec2.Body, key.priv)
	if err != nil {
		t.Fatal(err)
	}
	rec2 = *rec2ptr
	payload2, _ := marshalSubmit(rec2)
	w2 := postJSON(t, s2.Handler(), "/v1/records", payload2)
	mustStatus(t, w2, http.StatusAccepted)

	newCP, _, err := tlogx.ReadCheckpoint(s2.Store(), s2.Policy())
	if err != nil {
		t.Fatal(err)
	}
	if newCP.N != 2 {
		t.Fatalf("expected checkpoint size 2, got %d", newCP.N)
	}
	proof, err := s2.Tree().TreeProof(oldCP.N)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlogx.VerifyConsistency(newCP, oldCP, proof); err != nil {
		t.Fatalf("consistency proof: %v", err)
	}
}

func TestStartSequencerInitializesMissingCheckpointState(t *testing.T) {
	ctx := t.Context()
	cfg := DefaultServerConfig()
	cfg.DataDir = t.TempDir()
	cfg.LogKeyFile = filepath.Join(cfg.DataDir, "log-key")
	cfg.CheckpointState = filepath.Join(cfg.DataDir, "checkpoint-state")

	first, err := NewServer(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.StartSequencer(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.CheckpointState); err != nil {
		t.Fatal(err)
	}

	second, err := NewServer(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Shutdown(ctx)
	if err := second.StartSequencer(ctx); err != nil {
		t.Fatal(err)
	}
	tree, signed, err := tlogx.LoadCheckpointState(cfg.CheckpointState)
	if err != nil {
		t.Fatalf("checkpoint state was not initialized: %v", err)
	}
	published, _, err := tlogx.ReadCheckpoint(second.Store(), second.Policy())
	if err != nil {
		t.Fatal(err)
	}
	if tree != published || len(signed) == 0 {
		t.Fatalf("initialized state does not match published checkpoint: state=%v published=%v", tree, published)
	}
}

func TestDuplicateRecord(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)

	key := newAuditorKey(t)
	url := "https://example.com/script.sh"
	content := "echo hello\n"
	fetcher.set(url, []byte(content))
	rec := makeAuditRecord(t, key, url, []byte(content), claimsForLines(content))
	payload, _ := marshalSubmit(rec)

	w1 := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w1, http.StatusAccepted)

	w2 := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w2, http.StatusAccepted)
	if body := decodeMap(t, w2.Body.Bytes()); body["warning"] != "duplicate record" {
		t.Fatalf("expected duplicate warning, got %v", body["warning"])
	}
	if s.Tree().Size() != 1 {
		t.Fatalf("expected tree size 1, got %d", s.Tree().Size())
	}
}

func TestTamperedRequests(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	// Wrong content-type.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/records", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "text/plain")
	s.Handler().ServeHTTP(w, req)
	mustStatus(t, w, http.StatusUnsupportedMediaType)

	// Unknown field.
	w2 := postJSON(t, s.Handler(), "/v1/records", []byte(`{"record":{},"signature":"","public_key":"","extra":1}`))
	mustStatus(t, w2, http.StatusBadRequest)

	// Trailing data.
	w3 := postJSON(t, s.Handler(), "/v1/records", []byte(`{}`))
	mustStatus(t, w3, http.StatusBadRequest)

	// Wrong method.
	w4 := httptest.NewRecorder()
	req4 := httptest.NewRequest(http.MethodGet, "/v1/records", nil)
	s.Handler().ServeHTTP(w4, req4)
	mustStatus(t, w4, http.StatusMethodNotAllowed)

	// Unknown path.
	w5 := httptest.NewRecorder()
	req5 := httptest.NewRequest(http.MethodGet, "/v1/blob/foo", nil)
	s.Handler().ServeHTTP(w5, req5)
	mustStatus(t, w5, http.StatusNotFound)
}

func TestMismatchPendingAndReport(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)

	key := newAuditorKey(t)
	url := "https://example.com/script.sh"
	originalContent := "echo hello\n"
	fetchedContent := "echo world\n"
	fetcher.set(url, []byte(fetchedContent))
	rec := makeAuditRecord(t, key, url, []byte(originalContent), claimsForLines(originalContent))
	recptr, err := schema.Sign(rec.Body, key.priv)
	if err != nil {
		t.Fatal(err)
	}
	rec = *recptr
	payload, _ := marshalSubmit(rec)

	w := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w, http.StatusAccepted)
	body := decodeMap(t, w.Body.Bytes())
	if body["pending"] != true {
		t.Fatalf("expected pending true, got %v", body["pending"])
	}
	recordID := body["record_id"].(string)

	ctx := context.Background()
	if _, err := s.Store().Get(ctx, "v1/pending/"+recordID); err != nil {
		t.Fatalf("pending state not stored: %v", err)
	}
	if s.Tree().Size() != 1 {
		t.Fatalf("expected moderation leaf appended, got size %d", s.Tree().Size())
	}

	// Missing acknowledgement.
	badAck := map[string]interface{}{
		"record_id":            recordID,
		"acknowledgement":      "no",
		"masked_report":        "redacted",
		"secret_scan_metadata": map[string]interface{}{},
	}
	b, _ := json.Marshal(badAck)
	w2 := postJSON(t, s.Handler(), "/v1/reports", b)
	mustStatus(t, w2, http.StatusBadRequest)

	// Missing pending record.
	noPending := map[string]interface{}{
		"record_id":            "0000000000000000000000000000000000000000000000000000000000000000",
		"acknowledgement":      "yes-i-reviewed-this",
		"masked_report":        "redacted",
		"secret_scan_metadata": map[string]interface{}{},
	}
	b2, _ := json.Marshal(noPending)
	w3 := postJSON(t, s.Handler(), "/v1/reports", b2)
	mustStatus(t, w3, http.StatusBadRequest)

	// Masked report hashes to the claimed original target.
	maskedSame := map[string]interface{}{
		"record_id":            recordID,
		"acknowledgement":      "yes-i-reviewed-this",
		"masked_report":        string(originalContent),
		"secret_scan_metadata": map[string]interface{}{},
	}
	b3, _ := json.Marshal(maskedSame)
	w4 := postJSON(t, s.Handler(), "/v1/reports", b3)
	mustStatus(t, w4, http.StatusBadRequest)

	// Secret detected in masked report.
	withSecret := map[string]interface{}{
		"record_id":            recordID,
		"acknowledgement":      "yes-i-reviewed-this",
		"masked_report":        "ghp_1234567890123456789012345678901234567890",
		"secret_scan_metadata": map[string]interface{}{},
	}
	b4, _ := json.Marshal(withSecret)
	w5 := postJSON(t, s.Handler(), "/v1/reports", b4)
	mustStatus(t, w5, http.StatusBadRequest)
	if _, err := s.Store().Get(ctx, "v1/reports/"+recordID+".json"); !storage.IsNotFound(err) {
		t.Fatalf("secret report should not be stored: %v", err)
	}

	// Valid report.
	valid := map[string]interface{}{
		"record_id":            recordID,
		"acknowledgement":      "yes-i-reviewed-this",
		"masked_report":        "[REDACTED]",
		"secret_scan_metadata": map[string]interface{}{"tool": "gitleaks", "confidence": 1.0},
	}
	b5, _ := json.Marshal(valid)
	w6 := postJSON(t, s.Handler(), "/v1/reports", b5)
	mustStatus(t, w6, http.StatusAccepted)
	if _, err := s.Store().Get(ctx, "v1/reports/"+recordID+".json"); err != nil {
		t.Fatalf("report not stored: %v", err)
	}
	if _, err := s.Store().Get(ctx, "v1/pending/"+recordID); !storage.IsNotFound(err) {
		t.Fatalf("resolved pending record was not cleared: %v", err)
	}
	w7 := postJSON(t, s.Handler(), "/v1/reports", b5)
	mustStatus(t, w7, http.StatusBadRequest)
}

func TestTombstone(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)

	key := newAuditorKey(t)
	url := "https://example.com/script.sh"
	content := "echo hello\n"
	fetcher.set(url, []byte(content))
	rec := makeAuditRecord(t, key, url, []byte(content), claimsForLines(content))
	payload, _ := marshalSubmit(rec)

	w1 := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w1, http.StatusAccepted)
	recordID := decodeMap(t, w1.Body.Bytes())["record_id"].(string)

	ctx := context.Background()
	blob, err := s.Store().Get(ctx, "v1/blob/"+recordID)
	if err != nil {
		t.Fatal(err)
	}
	var before schema.Record
	if err := json.Unmarshal(blob, &before); err != nil {
		t.Fatal(err)
	}
	if before.Body.Type != schema.SchemaAuditV1 {
		t.Fatal("expected audit record")
	}

	res, err := s.Tombstone(ctx, recordID)
	if err != nil || res.err != nil {
		t.Fatalf("tombstone: %v / %v", err, res.err)
	}
	if s.Tree().Size() != 2 {
		t.Fatalf("expected tombstone leaf appended, got size %d", s.Tree().Size())
	}

	blob2, err := s.Store().Get(ctx, "v1/blob/"+recordID)
	if err != nil {
		t.Fatal(err)
	}
	var tomb map[string]interface{}
	if err := json.Unmarshal(blob2, &tomb); err != nil {
		t.Fatal(err)
	}
	if tomb["tombstone"] != true {
		t.Fatalf("expected tombstone blob, got %v", tomb)
	}
	prefix := prefixdb.Prefix(rec.Body.Target.SHA256)
	if _, err := s.Store().Get(ctx, storage.PrefixPath(prefix)); !storage.IsNotFound(err) {
		t.Fatalf("expected empty shard to be deleted after tombstone, got %v", err)
	}
}

func TestTombstoneRejectsRetractedAudit(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)

	key := newAuditorKey(t)
	url := "https://example.com/retracted.sh"
	content := []byte("echo hello\n")
	fetcher.set(url, content)
	audit := makeAuditRecord(t, key, url, content, claimsForLines(string(content)))
	payload, _ := marshalSubmit(audit)
	w := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w, http.StatusAccepted)
	auditID := decodeMap(t, w.Body.Bytes())["record_id"].(string)

	retraction := makeRetractionRecord(t, key, audit)
	retractPayload, _ := marshalSubmit(retraction)
	w2 := postJSON(t, s.Handler(), "/v1/records", retractPayload)
	mustStatus(t, w2, http.StatusAccepted)
	if s.Tree().Size() != 2 {
		t.Fatalf("expected audit and retraction leaves, got %d", s.Tree().Size())
	}

	before, err := s.Store().Get(t.Context(), storage.BlobPath(auditID))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Tombstone(t.Context(), auditID)
	if err == nil || res.err == nil || !strings.Contains(err.Error(), "live retraction") {
		t.Fatalf("expected live-retraction rejection, got res=%+v err=%v", res, err)
	}
	if s.Tree().Size() != 2 {
		t.Fatalf("rejected tombstone appended a leaf: %d", s.Tree().Size())
	}
	after, err := s.Store().Get(t.Context(), storage.BlobPath(auditID))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected tombstone changed the audit blob")
	}
}

func TestRetractAfterTombstoneIsRejected(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)

	key := newAuditorKey(t)
	url := "https://example.com/tombstoned.sh"
	content := []byte("echo hello\n")
	fetcher.set(url, content)
	audit := makeAuditRecord(t, key, url, content, claimsForLines(string(content)))
	payload, _ := marshalSubmit(audit)
	w := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w, http.StatusAccepted)
	auditID := decodeMap(t, w.Body.Bytes())["record_id"].(string)

	if _, err := s.Tombstone(t.Context(), auditID); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	if s.Tree().Size() != 2 {
		t.Fatalf("expected audit and moderation leaves, got %d", s.Tree().Size())
	}

	retraction := makeRetractionRecord(t, key, audit)
	retractPayload, _ := marshalSubmit(retraction)
	w2 := postJSON(t, s.Handler(), "/v1/records", retractPayload)
	mustStatus(t, w2, http.StatusBadRequest)
	if !strings.Contains(w2.Body.String(), "unavailable") {
		t.Fatalf("expected unavailable target response, got %s", w2.Body.String())
	}
	if s.Tree().Size() != 2 {
		t.Fatalf("rejected retraction appended a leaf: %d", s.Tree().Size())
	}
}

func TestConcurrentRetractionAndTombstoneRemainConsistent(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)

	key := newAuditorKey(t)
	url := "https://example.com/concurrent.sh"
	content := []byte("echo hello\n")
	fetcher.set(url, content)
	audit := makeAuditRecord(t, key, url, content, claimsForLines(string(content)))
	payload, _ := marshalSubmit(audit)
	w := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w, http.StatusAccepted)
	auditID := decodeMap(t, w.Body.Bytes())["record_id"].(string)

	retraction := makeRetractionRecord(t, key, audit)
	retractPayload, _ := marshalSubmit(retraction)
	blocking := &blockingGetStore{
		Store:   s.store,
		path:    storage.BlobPath(auditID),
		blockAt: 2, // Block the sequencer's revalidation, after the HTTP precheck.
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	s.store = blocking

	response := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response <- postJSON(t, s.Handler(), "/v1/records", retractPayload)
	}()
	<-blocking.started

	tombstoneResult := make(chan error, 1)
	go func() {
		_, err := s.Tombstone(t.Context(), auditID)
		tombstoneResult <- err
	}()
	close(blocking.release)

	w2 := <-response
	tombstoneErr := <-tombstoneResult
	mustStatus(t, w2, http.StatusAccepted)
	if tombstoneErr == nil || !strings.Contains(tombstoneErr.Error(), "live retraction") {
		t.Fatalf("accepted retraction must force tombstone rejection: response=%s err=%v", w2.Body.String(), tombstoneErr)
	}
	if s.Tree().Size() != 2 {
		t.Fatalf("expected audit and retraction leaves, got %d", s.Tree().Size())
	}
}

func TestInvalidLLMPromptHashLeavesNoOrphanTargetBlob(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)

	key := newAuditorKey(t)
	url := "https://example.com/bad-prompt.sh"
	content := []byte("sudo true\n")
	fetcher.set(url, content)
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: time.Now().UTC().Unix(),
		Auditor:   key.id,
		Target: schema.Target{
			URL:    url,
			SHA256: storage.ContentHash(content),
			Size:   int64(len(content)),
		},
		Analyzer: schema.Analyzer{
			Kind:         schema.KindLLM,
			Model:        "qwen2.5-coder",
			ModelFamily:  "qwen",
			Quantization: "q4_k_m",
			Backend:      "ollama",
			PromptSHA256: strings.Repeat("a", 64),
			Runs:         5,
			Agreement:    1,
		},
		Verdict: schema.VerdictDanger,
		Claims: []schema.Claim{{
			Category:   "priv.sudo",
			Line:       1,
			LineSHA256: schema.LineHash("sudo true"),
		}},
	}
	rec, err := schema.Sign(body, key.priv)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := marshalSubmit(rec)
	w := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w, http.StatusBadRequest)
	if _, err := s.Store().Get(t.Context(), storage.BlobPath(body.Target.SHA256)); !storage.IsNotFound(err) {
		t.Fatalf("rejected LLM audit left target artifact: %v", err)
	}
	if s.Tree().Size() != 0 {
		t.Fatalf("rejected LLM audit appended a leaf: %d", s.Tree().Size())
	}
}

func TestAuditArtifactPreparationFailureCleansTargetBlob(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)

	key := newAuditorKey(t)
	url := "https://example.com/prompt-store-failure.sh"
	content := []byte("sudo true\n")
	fetcher.set(url, content)
	prompt := llm.BuildPrompt(string(content))
	promptHash := llm.PromptHash(prompt)
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: time.Now().UTC().Unix(),
		Auditor:   key.id,
		Target: schema.Target{
			URL:    url,
			SHA256: storage.ContentHash(content),
			Size:   int64(len(content)),
		},
		Analyzer: schema.Analyzer{
			Kind:         schema.KindLLM,
			Model:        "qwen2.5-coder",
			ModelFamily:  "qwen",
			Quantization: "q4_k_m",
			Backend:      "ollama",
			PromptSHA256: promptHash,
			Runs:         5,
			Agreement:    1,
		},
		Verdict: schema.VerdictDanger,
		Claims: []schema.Claim{{
			Category:   "priv.sudo",
			Line:       1,
			LineSHA256: schema.LineHash("sudo true"),
		}},
	}
	rec, err := schema.Sign(body, key.priv)
	if err != nil {
		t.Fatal(err)
	}
	s.store = &putErrorStore{
		Store: s.store,
		path:  storage.BlobPath(promptHash),
		err:   fmt.Errorf("injected prompt write failure"),
	}

	payload, _ := marshalSubmit(rec)
	w := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w, http.StatusInternalServerError)
	if _, err := s.Store().Get(t.Context(), storage.BlobPath(body.Target.SHA256)); !storage.IsNotFound(err) {
		t.Fatalf("failed artifact preparation left target blob: %v", err)
	}
	if s.Tree().Size() != 0 {
		t.Fatalf("failed artifact preparation appended a leaf: %d", s.Tree().Size())
	}
}

func TestPendingLookupErrorFailsClosed(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)

	key := newAuditorKey(t)
	url := "https://example.com/pending-error.sh"
	content := []byte("echo hello\n")
	fetcher.set(url, content)
	rec := makeAuditRecord(t, key, url, content, nil)
	id, err := schema.RecordID(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	s.store = &getErrorStore{
		Store: s.store,
		path:  "v1/pending/" + id,
		err:   fmt.Errorf("injected pending read failure"),
	}

	payload, _ := marshalSubmit(rec)
	w := postJSON(t, s.Handler(), "/v1/records", payload)
	mustStatus(t, w, http.StatusServiceUnavailable)
	if s.Tree().Size() != 0 {
		t.Fatalf("pending lookup failure appended a leaf: %d", s.Tree().Size())
	}
}

func TestSubmissionRateLimit(t *testing.T) {
	ctx := t.Context()
	cfg := DefaultServerConfig()
	cfg.DataDir = t.TempDir()
	cfg.LogKeyFile = filepath.Join(cfg.DataDir, "log-key")
	cfg.CheckpointState = filepath.Join(cfg.DataDir, "checkpoint-state")
	cfg.SubmissionLimit = 1
	cfg.SubmissionWindow = time.Minute
	s, err := NewServer(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StartSequencer(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)

	badBody := []byte(`{}`)
	first := postJSON(t, s.Handler(), "/v1/records", badBody)
	mustStatus(t, first, http.StatusBadRequest)
	second := postJSON(t, s.Handler(), "/v1/records", badBody)
	mustStatus(t, second, http.StatusTooManyRequests)
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("rate-limited response omitted Retry-After")
	}

	// Health checks are never subject to the submission limiter.
	health := get(t, s.Handler(), "/healthz")
	mustStatus(t, health, http.StatusOK)
}

func TestStaleWitnessedCheckpointRemainsPending(t *testing.T) {
	witnessSigner, witnessKey := testC2SPWitnessKey(t, "witness.example/stale")
	ctx := t.Context()
	cfg := DefaultServerConfig()
	cfg.DataDir = t.TempDir()
	cfg.LogKeyFile = filepath.Join(cfg.DataDir, "log-key")
	cfg.CheckpointState = filepath.Join(cfg.DataDir, "checkpoint-state")
	cfg.WitnessKeys = []string{witnessKey}
	cfg.RequiredWitnesses = 1
	s, err := NewServer(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)

	oldTree := s.tree.TlogTree()
	oldCandidate, err := note.Sign(
		&note.Note{Text: string(tlogx.FormatCheckpoint(oldTree, s.origin))},
		s.key.signer,
		witnessSigner,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.Put(ctx, storage.Object{
		Path: witnessedCheckpointPath,
		Data: oldCandidate,
	}); err != nil {
		t.Fatal(err)
	}

	key := newAuditorKey(t)
	rec := makeAuditRecord(t, key, "https://example.com/new.sh", []byte("echo new\n"), nil)
	leaf, err := tlogx.RecordToLeaf(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.tree.AppendLeaf(leaf); err != nil {
		t.Fatal(err)
	}
	published, err := s.publishCheckpoint(ctx)
	if err != nil {
		t.Fatalf("stale witnessed checkpoint must be pending, not corrupt: %v", err)
	}
	if published {
		t.Fatal("stale witnessed checkpoint unexpectedly published the current tree")
	}
	if _, err := s.store.Get(ctx, storage.CheckpointPath()); !storage.IsNotFound(err) {
		t.Fatalf("stale candidate published a checkpoint: %v", err)
	}
}

func TestMismatchedWitnessedCheckpointStillFails(t *testing.T) {
	witnessSigner, witnessKey := testC2SPWitnessKey(t, "witness.example/mismatch")
	ctx := t.Context()
	cfg := DefaultServerConfig()
	cfg.DataDir = t.TempDir()
	cfg.LogKeyFile = filepath.Join(cfg.DataDir, "log-key")
	cfg.CheckpointState = filepath.Join(cfg.DataDir, "checkpoint-state")
	cfg.WitnessKeys = []string{witnessKey}
	cfg.RequiredWitnesses = 1
	s, err := NewServer(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)

	key := newAuditorKey(t)
	rec := makeAuditRecord(t, key, "https://example.com/current.sh", []byte("echo current\n"), nil)
	leaf, err := tlogx.RecordToLeaf(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.tree.AppendLeaf(leaf); err != nil {
		t.Fatal(err)
	}
	badTree := s.tree.TlogTree()
	badTree.Hash[0] ^= 0xff
	candidate, err := note.Sign(
		&note.Note{Text: string(tlogx.FormatCheckpoint(badTree, s.origin))},
		s.key.signer,
		witnessSigner,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.Put(ctx, storage.Object{
		Path: witnessedCheckpointPath,
		Data: candidate,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.publishCheckpoint(ctx); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected same-size mismatched root error, got %v", err)
	}
}

func TestAcquireLeaseIsAtomicAcrossServers(t *testing.T) {
	ctx := t.Context()
	cfg := DefaultServerConfig()
	cfg.DataDir = t.TempDir()
	cfg.LogKeyFile = filepath.Join(cfg.DataDir, "log-key")
	cfg.CheckpointState = filepath.Join(cfg.DataDir, "checkpoint-state")
	first, err := NewServer(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewServer(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Shutdown(ctx)
	defer second.Shutdown(ctx)

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, server := range []*Server{first, second} {
		go func(server *Server) {
			<-start
			results <- server.acquireLease(ctx)
		}(server)
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one atomic lease winner, got %d", successes)
	}
}

func TestCorruptLeaseFailsClosed(t *testing.T) {
	ctx := t.Context()
	cfg := DefaultServerConfig()
	cfg.DataDir = t.TempDir()
	cfg.LogKeyFile = filepath.Join(cfg.DataDir, "log-key")
	cfg.CheckpointState = filepath.Join(cfg.DataDir, "checkpoint-state")
	s, err := NewServer(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(ctx)
	if err := s.store.Put(ctx, storage.Object{
		Path: s.leasePath,
		Data: []byte("{not-json"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.acquireLease(ctx); err == nil || !strings.Contains(err.Error(), "decode lease") {
		t.Fatalf("corrupt lease was treated as free: %v", err)
	}
}

func TestMirrorImportTakesServerLock(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	s.mu.Lock()
	done := make(chan error, 1)
	go func() {
		done <- s.ImportSnapshot(t.Context(), bytes.NewReader(nil), "mirror")
	}()
	select {
	case err := <-done:
		s.mu.Unlock()
		t.Fatalf("mirror import returned without the server lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	s.mu.Unlock()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("invalid archive unexpectedly imported")
		}
	case <-time.After(time.Second):
		t.Fatal("mirror import did not resume after server lock release")
	}
}

func TestMirrorImportRefreshesInMemoryTree(t *testing.T) {
	source, sourceCleanup := newTestServer(t)
	defer sourceCleanup()
	fetcher := newTestFetcher()
	source.SetFetcher(fetcher)

	key := newAuditorKey(t)
	targetURL := "https://example.com/mirror-import.sh"
	content := []byte("echo mirror\n")
	fetcher.set(targetURL, content)
	rec := makeAuditRecord(t, key, targetURL, content, nil)
	payload, _ := marshalSubmit(rec)
	mustStatus(t, postJSON(t, source.Handler(), "/v1/records", payload), http.StatusAccepted)

	var archive bytes.Buffer
	if _, err := source.CreateSnapshot(t.Context(), &archive); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultServerConfig()
	cfg.DataDir = t.TempDir()
	cfg.LogKeyFile = filepath.Join(cfg.DataDir, "log-key")
	cfg.CheckpointState = filepath.Join(cfg.DataDir, "checkpoint-state")
	cfg.PolicyPath = filepath.Join(cfg.DataDir, "policy.toml")
	if err := tlogx.SavePolicy(cfg.PolicyPath, source.Policy()); err != nil {
		t.Fatal(err)
	}
	target, err := NewServer(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Shutdown(t.Context())
	if err := target.StartSequencer(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := target.ImportSnapshot(t.Context(), bytes.NewReader(archive.Bytes()), "mirror"); err != nil {
		t.Fatal(err)
	}
	if target.Tree().Size() != source.Tree().Size() || target.treeSize.Load() != source.Tree().Size() {
		t.Fatalf("mirror import did not refresh tree: in-memory=%d atomic=%d source=%d",
			target.Tree().Size(), target.treeSize.Load(), source.Tree().Size())
	}
	stateTree, _, err := tlogx.LoadCheckpointState(cfg.CheckpointState)
	if err != nil {
		t.Fatal(err)
	}
	if stateTree != target.Tree().TlogTree() {
		t.Fatalf("mirror checkpoint state mismatch: state=%v tree=%v", stateTree, target.Tree().TlogTree())
	}
}

func TestRestoreCheckpointStateFromEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.toml")
	data := []byte("trusted checkpoint state")
	t.Setenv(checkpointStateDataEnv, base64.StdEncoding.EncodeToString(data))
	if err := restoreCheckpointStateFromEnv(path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("restored checkpoint state mismatch: %q", got)
	}
	if os.Getenv(checkpointStateDataEnv) != "" {
		t.Fatal("checkpoint state environment value was not cleared")
	}
}

func TestRestoreCheckpointStateRejectsInvalidBase64(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.toml")
	t.Setenv(checkpointStateDataEnv, "not-base64!")
	if err := restoreCheckpointStateFromEnv(path); err == nil {
		t.Fatal("expected invalid checkpoint state to fail")
	}
}

func TestSecretDetectorFindsKnownSecret(t *testing.T) {
	detector, err := secrets.NewDetector()
	if err != nil {
		t.Fatalf("detector: %v", err)
	}
	findings, err := detector.ScanString("ghp_1234567890123456789012345678901234567890")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected secret detection")
	}
}

var _ = io.Discard
