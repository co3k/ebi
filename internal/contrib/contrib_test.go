package contrib

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/co3k/ebi/pkg/schema"
)

func TestQueue(t *testing.T) {
	os.Setenv("HOME", t.TempDir())
	os.Unsetenv("EBI_HOME")
	os.Unsetenv("XDG_CONFIG_HOME")
	defer os.Unsetenv("HOME")
	q, err := NewQueue()
	if err != nil {
		t.Fatal(err)
	}
	rec := queueTestRecord(t)
	if err := q.Enqueue(rec, false); err != nil {
		t.Fatal(err)
	}
	status, err := q.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status != 1 {
		t.Fatalf("expected 1, got %d", status)
	}
	records, err := q.Flush(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	// Records must remain until ack.
	status, err = q.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status != 1 {
		t.Fatalf("expected 1 record before ack, got %d", status)
	}
	if err := q.Ack(records[0]); err != nil {
		t.Fatal(err)
	}
	status, err = q.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status != 0 {
		t.Fatalf("expected 0, got %d", status)
	}
}

func TestQueueDelayedFlush(t *testing.T) {
	os.Setenv("HOME", t.TempDir())
	os.Unsetenv("EBI_HOME")
	os.Unsetenv("XDG_CONFIG_HOME")
	defer os.Unsetenv("HOME")
	q, err := NewQueue()
	if err != nil {
		t.Fatal(err)
	}
	rec := queueTestRecord(t)
	if err := q.Enqueue(rec, true); err != nil {
		t.Fatal(err)
	}
	// Before the scheduled time, flush should be empty.
	records, err := q.Flush(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0 records before delay, got %d", len(records))
	}
	// After the future, flush should include it.
	records, err = q.Flush(time.Now().UTC().Add(25 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record after delay, got %d", len(records))
	}
}

func TestLicenseNotice(t *testing.T) {
	if LicenseNotice() == "" {
		t.Fatal("empty notice")
	}
	if !strings.Contains(SubmissionNotice(), "CC0") {
		t.Fatal("submission notice missing CC0")
	}
}

func TestQueueRejectsCorruptEntry(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("EBI_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	q, err := NewQueue()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(q.dir, "corrupt.json"), []byte(`{"record":`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := q.List(); err == nil {
		t.Fatal("expected corrupt queue entry to fail closed")
	}
	if _, err := q.Flush(time.Time{}); err == nil {
		t.Fatal("expected corrupt queue entry to block flush")
	}
	if _, err := q.Status(); err == nil {
		t.Fatal("expected corrupt queue entry to block status")
	}
}

func TestQueueRemoveRejectsPrefixSibling(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("EBI_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	q, err := NewQueue()
	if err != nil {
		t.Fatal(err)
	}
	outside := q.dir + "-outside.json"
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := q.Remove(outside); err == nil {
		t.Fatal("expected prefix-sibling path to be rejected")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside file was touched: %v", err)
	}
}

func queueTestRecord(t *testing.T) *schema.Record {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   schema.AuditorHash(hex.EncodeToString(pub)),
		Target: schema.Target{
			URL:    "https://example.com/install.sh",
			SHA256: strings.Repeat("a", 64),
			Size:   1,
		},
		Analyzer: schema.Analyzer{Kind: schema.KindStatic},
		Verdict:  schema.VerdictOK,
	}
	rec, err := schema.Sign(body, priv)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}
