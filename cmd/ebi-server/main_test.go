package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/co3k/ebi/pkg/schema"
)

func TestEnvIntRequiresWholeInteger(t *testing.T) {
	t.Setenv("EBI_TEST_INT", "2x")
	if got := envInt("EBI_TEST_INT", 7); got != 7 {
		t.Fatalf("partial integer was accepted: %d", got)
	}
	t.Setenv("EBI_TEST_INT", "2")
	if got := envInt("EBI_TEST_INT", 7); got != 2 {
		t.Fatalf("valid integer was rejected: %d", got)
	}
	if err := os.Unsetenv("EBI_TEST_INT"); err != nil {
		t.Fatal(err)
	}
	if got := envInt("EBI_TEST_INT", 7); got != 7 {
		t.Fatalf("unset integer did not use default: %d", got)
	}
}

func TestExportCheckpointState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint-state")
	want := []byte("checkpoint-state-data")
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := exportCheckpointState(path, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("exported %q, want %q", out.Bytes(), want)
	}
}

func TestExportCheckpointStateRejectsOversizeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint-state")
	if err := os.WriteFile(path, make([]byte, (1<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := exportCheckpointState(path, &out); err == nil {
		t.Fatal("expected oversized checkpoint state to be rejected")
	}
	if out.Len() != 0 {
		t.Fatal("oversized checkpoint state was partially exported")
	}
}

func TestHealth(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("bad status: %v", body["status"])
	}
}

func TestSubmitAndVerify(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()
	fetcher := newTestFetcher()
	s.SetFetcher(fetcher)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	auditor := schema.AuditorHash(hex.EncodeToString(pub))

	url := "https://example.com/script.sh"
	content := []byte("echo hello\n")
	fetcher.set(url, content)
	sum := sha256.Sum256(content)
	h := hex.EncodeToString(sum[:])
	size := int64(len(content))

	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: time.Now().UTC().Unix(),
		Auditor:   auditor,
		Target:    schema.Target{URL: url, SHA256: h, Size: size},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictOK,
	}
	rec, err := schema.Sign(body, priv)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := marshalSubmit(rec)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/records", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated && w.Code != http.StatusAccepted {
		t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
	}
}
