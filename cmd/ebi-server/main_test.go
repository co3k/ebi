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
	"testing"
	"time"

	"github.com/co3k/ebi/pkg/schema"
)

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
