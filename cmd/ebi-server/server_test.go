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

	checkpoint, _, err := tlogx.ReadCheckpoint(s.Store(), s.Policy())
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
