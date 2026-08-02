package prefixdb

import (
	"crypto/ed25519"
	"testing"

	"github.com/co3k/ebi/pkg/schema"
)

func makeRecord(t *testing.T, hash string) schema.Record {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := schema.RecordBody{
		Schema:    schema.SchemaAuditV1,
		Version:   schema.SchemaVersion,
		CreatedAt: "2024-01-01T00:00:00Z",
		Target:    "https://example.com/" + hash,
		Hash:      hash,
		Size:      1,
		Analyzer:  "static",
		AnalyzerFamily: "static",
		Verdict:   schema.VerdictOK,
	}
	rec, err := schema.Sign(body, priv)
	if err != nil {
		t.Fatal(err)
	}
	return *rec
}

func TestPrefix(t *testing.T) {
	if Prefix("deadbeef1234") != "deadb" {
		t.Fatal("prefix wrong")
	}
	if Prefix("ABCD") != "abcd" {
		t.Fatal("prefix not lowercased")
	}
}

func TestBuildShards(t *testing.T) {
	rec := makeRecord(t, "a"+repeat("0", 63))
	shards, err := BuildShards([]schema.Record{rec})
	if err != nil {
		t.Fatal(err)
	}
	if len(shards) != 1 {
		t.Fatalf("expected 1 shard, got %d", len(shards))
	}
	id, _ := schema.RecordID(rec.Body)
	entries, err := MatchExact(shards[Prefix(rec.Body.Hash)], id)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 match, got %d", len(entries))
	}
	if entries[0].Size != 1 {
		t.Fatal("size mismatch")
	}
}

func TestVerifyShards(t *testing.T) {
	recs := []schema.Record{
		makeRecord(t, "a"+repeat("0", 63)),
		makeRecord(t, "b"+repeat("0", 63)),
	}
	shards, err := BuildShards(recs)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyShards(recs, shards); err != nil {
		t.Fatal(err)
	}
	shards["00000"] = []byte("invalid")
	if err := VerifyShards(recs, shards); err == nil {
		t.Fatal("expected verify to fail")
	}
}

func TestBuildShardForPrefixDedup(t *testing.T) {
	entries := []Entry{
		{RecordID: "x", Target: "a"},
		{RecordID: "x", Target: "b"},
		{RecordID: "y", Target: "c"},
	}
	b, err := BuildShardForPrefix("abc12", entries)
	if err != nil {
		t.Fatal(err)
	}
	got, err := MatchExact(b, "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected dedup, got %d", len(got))
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func TestShardPath(t *testing.T) {
	if ShardPath("abc12") != "v1/prefix/abc12" {
		t.Fatal("shard path wrong")
	}
}
