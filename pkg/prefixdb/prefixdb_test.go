package prefixdb

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/co3k/ebi/pkg/schema"
)

func hash64(c byte) string {
	return string(c) + repeat("0", 63)
}

func makeRecord(t *testing.T, hash string) schema.Record {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	aud := sha256.Sum256(pub)
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: 1704067200,
		Auditor:   hex.EncodeToString(aud[:]),
		Target:    schema.Target{URL: "https://example.com/" + hash, SHA256: hash, Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictOK,
	}
	rec, err := schema.Sign(body, priv)
	if err != nil {
		t.Fatal(err)
	}
	return *rec
}

func TestPrefix(t *testing.T) {
	if Prefix("deadbeef1234") != "" {
		t.Fatal("invalid hash should return empty")
	}
	full64 := "deadbeef" + strings.Repeat("0", 56)
	if Prefix(full64) != "deadb" {
		t.Fatalf("prefix wrong: got %q", Prefix(full64))
	}
	if Prefix("ABCD00000000000000000000000000000000000000000000000000000000000000") != "" {
		t.Fatal("uppercase not lowercase hex should return empty")
	}
	if ValidatePrefix("abc12") != nil {
		t.Fatal("valid prefix rejected")
	}
	if ValidatePrefix("ABC12") == nil {
		t.Fatal("uppercase prefix accepted")
	}
	if ValidatePrefix("abc1") == nil {
		t.Fatal("short prefix accepted")
	}
}

func TestBuildShards(t *testing.T) {
	rec := makeRecord(t, hash64('a'))
	shards, err := BuildShards([]schema.Record{rec})
	if err != nil {
		t.Fatal(err)
	}
	if len(shards) != 1 {
		t.Fatalf("expected 1 shard, got %d", len(shards))
	}
	entries, err := MatchExact(shards[Prefix(rec.Body.Target.SHA256)], rec.Body.Target.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 match, got %d", len(entries))
	}
	if entries[0].Size != 1 {
		t.Fatal("size mismatch")
	}
	if entries[0].TargetHash != rec.Body.Target.SHA256 {
		t.Fatal("target hash mismatch")
	}
	if entries[0].LogIndex != 0 {
		t.Fatalf("expected default LogIndex 0, got %d", entries[0].LogIndex)
	}
}

func TestBuildShardsWithIndex(t *testing.T) {
	recs := []schema.Record{
		makeRecord(t, hash64('a')),
		makeRecord(t, hash64('b')),
	}
	indices := []int64{10, 20}
	shards, err := BuildShardsWithIndex(recs, indices)
	if err != nil {
		t.Fatal(err)
	}
	if len(shards) != 2 {
		t.Fatalf("expected 2 shards, got %d", len(shards))
	}
	for i, rec := range recs {
		entries, err := MatchExact(shards[Prefix(rec.Body.Target.SHA256)], rec.Body.Target.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("expected 1 match for record %d, got %d", i, len(entries))
		}
		if entries[0].LogIndex != indices[i] {
			t.Fatalf("record %d LogIndex: want %d, got %d", i, indices[i], entries[0].LogIndex)
		}
	}
}

func TestBuildShardsWithIndexLengthMismatch(t *testing.T) {
	recs := []schema.Record{makeRecord(t, hash64('a'))}
	indices := []int64{1, 2}
	if _, err := BuildShardsWithIndex(recs, indices); err == nil {
		t.Fatal("expected length mismatch error")
	}
}

func TestVerifyShards(t *testing.T) {
	recs := []schema.Record{
		makeRecord(t, hash64('a')),
		makeRecord(t, hash64('b')),
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

func TestVerifyShardsWithIndex(t *testing.T) {
	recs := []schema.Record{
		makeRecord(t, hash64('a')),
		makeRecord(t, hash64('b')),
	}
	indices := []int64{5, 7}
	shards, err := BuildShardsWithIndex(recs, indices)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyShardsWithIndex(recs, indices, shards); err != nil {
		t.Fatal(err)
	}
	// Wrong indices should fail.
	wrongIndices := []int64{5, 8}
	if err := VerifyShardsWithIndex(recs, wrongIndices, shards); err == nil {
		t.Fatal("expected verify to fail with mismatched indices")
	}
}

func TestBuildShardForPrefixDedup(t *testing.T) {
	targetA := "abc12" + strings.Repeat("0", 59)
	targetB := "abc12" + strings.Repeat("1", 59)
	entries := []Entry{
		{RecordID: strings.Repeat("a", 64), TargetHash: targetA, AuditorID: strings.Repeat("c", 64), LogIndex: 1},
		{RecordID: strings.Repeat("a", 64), TargetHash: targetB, AuditorID: strings.Repeat("c", 64), LogIndex: 2},
		{RecordID: strings.Repeat("b", 64), TargetHash: targetB, AuditorID: strings.Repeat("d", 64), LogIndex: 3},
	}
	b, err := BuildShardForPrefix("abc12", entries)
	if err != nil {
		t.Fatal(err)
	}
	got, err := MatchExact(b, targetA)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected dedup, got %d", len(got))
	}
	if got[0].RecordID != strings.Repeat("a", 64) {
		t.Fatalf("unexpected record id %s", got[0].RecordID)
	}
	if got[0].TargetHash != targetA {
		t.Fatalf("expected target hash %s, got %s", targetA, got[0].TargetHash)
	}
}

func TestLogIndexInEntry(t *testing.T) {
	rec := makeRecord(t, hash64('c'))
	indices := []int64{42}
	shards, err := BuildShardsWithIndex([]schema.Record{rec}, indices)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := MatchExact(shards[Prefix(rec.Body.Target.SHA256)], rec.Body.Target.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 match, got %d", len(entries))
	}
	if entries[0].LogIndex != 42 {
		t.Fatalf("expected LogIndex 42, got %d", entries[0].LogIndex)
	}
}

func TestVerifyShardsIndexMismatch(t *testing.T) {
	rec := makeRecord(t, hash64('d'))
	shards, err := BuildShardsWithIndex([]schema.Record{rec}, []int64{100})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyShardsWithIndex([]schema.Record{rec}, []int64{101}, shards); err == nil {
		t.Fatal("expected mismatch error for different index")
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
