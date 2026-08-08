// Package prefixdb builds and verifies prefix lookup shards for ebi.
// The prefix is the first 5 lowercase hex characters of the target hash.
// Shards never contain the full hash or URL in a query; the client exact-matches
// locally after fetching the shard.
package prefixdb

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/co3k/ebi/pkg/schema"
	"github.com/gowebpki/jcs"
)

// PrefixLength is the number of hex characters used as a prefix.
const PrefixLength = 5

// hexPrefix is the set of valid lowercase hex characters.
const hexPrefix = "0123456789abcdef"

// Entry is a single target/record pair in a shard.
// LogIndex is the deterministic position of the record in the transparency
// log and can be used by clients to verify inclusion.
type Entry struct {
	TargetHash string `json:"target_hash"`
	RecordID   string `json:"record_id"`
	AuditorID  string `json:"auditor_id"`
	Size       int64  `json:"size"`
	LogIndex   int64  `json:"log_index"`
}

// Shard is a prefix lookup shard.
type Shard struct {
	Prefix  string  `json:"prefix"`
	Entries []Entry `json:"entries"`
}

// ValidatePrefix reports whether p is exactly PrefixLength lowercase hex chars.
func ValidatePrefix(p string) error {
	if len(p) != PrefixLength {
		return fmt.Errorf("prefix must be %d characters", PrefixLength)
	}
	for i := 0; i < len(p); i++ {
		if !strings.ContainsRune(hexPrefix, rune(p[i])) {
			return fmt.Errorf("prefix must be lowercase hex")
		}
	}
	return nil
}

// Prefix returns the first PrefixLength lowercase hex characters of s.
// It returns an empty string if s is not a valid 64-character hex hash.
func Prefix(s string) string {
	if len(s) < PrefixLength {
		return ""
	}
	if !schema.IsHexHash(s) {
		return ""
	}
	return s[:PrefixLength]
}

// BuildShards groups records by target hash prefix and returns a map of prefix
// to canonical JSON shard bytes. Log indices default to the record position
// (0..N-1).
func BuildShards(records []schema.Record) (map[string][]byte, error) {
	indices := make([]int64, len(records))
	for i := range records {
		indices[i] = int64(i)
	}
	return BuildShardsWithIndex(records, indices)
}

// BuildShardsWithIndex groups records by target hash prefix and returns a map of
// prefix to canonical JSON shard bytes. The indices slice maps each record
// position to its log index and must have the same length as records.
func BuildShardsWithIndex(records []schema.Record, indices []int64) (map[string][]byte, error) {
	if len(records) != len(indices) {
		return nil, fmt.Errorf("records and indices length mismatch: %d vs %d", len(records), len(indices))
	}
	groups := map[string][]Entry{}
	for i, rec := range records {
		id, err := schema.RecordID(rec.Body)
		if err != nil {
			return nil, fmt.Errorf("record id: %w", err)
		}
		auditorID, err := schema.AuditorIDFromKey(rec.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("auditor id: %w", err)
		}
		prefix := Prefix(rec.Body.Target.SHA256)
		if prefix == "" {
			return nil, fmt.Errorf("invalid target hash in record %s", id)
		}
		groups[prefix] = append(groups[prefix], Entry{
			TargetHash: rec.Body.Target.SHA256,
			RecordID:   id,
			AuditorID:  auditorID,
			Size:       rec.Body.Target.Size,
			LogIndex:   indices[i],
		})
	}
	out := map[string][]byte{}
	for prefix, entries := range groups {
		b, err := BuildShardForPrefix(prefix, entries)
		if err != nil {
			return nil, err
		}
		out[prefix] = b
	}
	return out, nil
}

// BuildShardForPrefix builds a single shard deterministically.
func BuildShardForPrefix(prefix string, entries []Entry) ([]byte, error) {
	if err := ValidatePrefix(prefix); err != nil {
		return nil, err
	}
	// Deduplicate by record id.
	seen := map[string]struct{}{}
	uniq := []Entry{}
	for _, e := range entries {
		if err := validateEntry(prefix, e); err != nil {
			return nil, err
		}
		if _, ok := seen[e.RecordID]; ok {
			continue
		}
		seen[e.RecordID] = struct{}{}
		uniq = append(uniq, e)
	}
	// Deterministic order: record id, then target hash.
	sort.Slice(uniq, func(i, j int) bool {
		if uniq[i].RecordID != uniq[j].RecordID {
			return uniq[i].RecordID < uniq[j].RecordID
		}
		if uniq[i].TargetHash != uniq[j].TargetHash {
			return uniq[i].TargetHash < uniq[j].TargetHash
		}
		return uniq[i].AuditorID < uniq[j].AuditorID
	})
	shard := Shard{Prefix: prefix, Entries: uniq}
	return canonicalJSON(shard)
}

// canonicalJSON returns a deterministic RFC 8785 JCS canonical JSON encoding.
func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(b)
}

// MatchExact returns the entries whose TargetHash matches fullHash.
func MatchExact(shard []byte, fullHash string) ([]Entry, error) {
	s, err := DecodeShardStrict(shard)
	if err != nil {
		return nil, err
	}
	if s.Prefix != Prefix(fullHash) {
		return nil, fmt.Errorf("shard prefix %q does not match target hash", s.Prefix)
	}
	var out []Entry
	for _, e := range s.Entries {
		if e.TargetHash == fullHash {
			out = append(out, e)
		}
	}
	return out, nil
}

// DecodeShardStrict rejects unknown fields, malformed entries, wrong prefix
// membership, duplicates, and non-deterministic ordering.
func DecodeShardStrict(data []byte) (*Shard, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var shard Shard
	if err := dec.Decode(&shard); err != nil {
		return nil, fmt.Errorf("decode shard: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing data after shard")
		}
		return nil, fmt.Errorf("trailing data after shard: %w", err)
	}
	if err := ValidatePrefix(shard.Prefix); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(shard.Entries))
	for i, entry := range shard.Entries {
		if err := validateEntry(shard.Prefix, entry); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		if _, ok := seen[entry.RecordID]; ok {
			return nil, fmt.Errorf("entry %d: duplicate record_id", i)
		}
		seen[entry.RecordID] = struct{}{}
		if i > 0 && entryLess(entry, shard.Entries[i-1]) {
			return nil, fmt.Errorf("entries are not deterministically sorted")
		}
	}
	canonical, err := BuildShardForPrefix(shard.Prefix, shard.Entries)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("shard is not canonical JSON")
	}
	return &shard, nil
}

func validateEntry(prefix string, e Entry) error {
	if !schema.IsHexHash(e.TargetHash) || Prefix(e.TargetHash) != prefix {
		return fmt.Errorf("target_hash is invalid or outside prefix %s", prefix)
	}
	if !schema.IsHexHash(e.RecordID) {
		return fmt.Errorf("record_id must be lowercase sha256")
	}
	if !schema.IsHexHash(e.AuditorID) {
		return fmt.Errorf("auditor_id must be lowercase sha256")
	}
	if e.Size < 0 {
		return fmt.Errorf("size must be non-negative")
	}
	if e.LogIndex < 0 {
		return fmt.Errorf("log_index must be non-negative")
	}
	return nil
}

func entryLess(a, b Entry) bool {
	if a.RecordID != b.RecordID {
		return a.RecordID < b.RecordID
	}
	if a.TargetHash != b.TargetHash {
		return a.TargetHash < b.TargetHash
	}
	if a.AuditorID != b.AuditorID {
		return a.AuditorID < b.AuditorID
	}
	return a.LogIndex < b.LogIndex
}

// VerifyShards rebuilds shards from records and checks each byte slice.
func VerifyShards(records []schema.Record, shards map[string][]byte) error {
	indices := make([]int64, len(records))
	for i := range records {
		indices[i] = int64(i)
	}
	return VerifyShardsWithIndex(records, indices, shards)
}

// VerifyShardsWithIndex rebuilds shards using the same log index mapping and
// checks each byte slice.
func VerifyShardsWithIndex(records []schema.Record, indices []int64, shards map[string][]byte) error {
	want, err := BuildShardsWithIndex(records, indices)
	if err != nil {
		return err
	}
	for prefix, got := range shards {
		if err := ValidatePrefix(prefix); err != nil {
			return err
		}
		w, ok := want[prefix]
		if !ok {
			return fmt.Errorf("unexpected prefix %s", prefix)
		}
		if string(w) != string(got) {
			return fmt.Errorf("prefix %s shard mismatch", prefix)
		}
	}
	for prefix := range want {
		if _, ok := shards[prefix]; !ok {
			return fmt.Errorf("missing prefix %s", prefix)
		}
	}
	return nil
}

// ShardPath returns the storage path for a prefix shard.
func ShardPath(prefix string) string {
	return "v1/prefix/" + prefix
}

// TargetHashFromRecordID is a helper for tests/migration that decodes the
// target hash from a record blob reference when needed.
func TargetHashFromRecordID(recordID string) (string, error) {
	b, err := hex.DecodeString(recordID)
	if err != nil {
		return "", err
	}
	if len(b) != 32 {
		return "", fmt.Errorf("invalid record id length")
	}
	return hex.EncodeToString(b), nil
}
