// Package prefixdb builds and verifies prefix lookup shards for ebi.
// The prefix is the first 5 lowercase hex characters of the target hash.
// Shards never contain the full hash or URL in a query; the client exact-matches
// locally after fetching the shard.
package prefixdb

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/co3k/ebi/pkg/schema"
	"github.com/gowebpki/jcs"
)

// PrefixLength is the number of hex characters used as a prefix.
const PrefixLength = 5

// Entry is a single target/record pair in a shard.
type Entry struct {
	Target    string `json:"target"`
	RecordID  string `json:"record_id"`
	AuditorID string `json:"auditor_id"`
	Size      int64  `json:"size"`
}

// Shard is a prefix lookup shard.
type Shard struct {
	Prefix  string  `json:"prefix"`
	Entries []Entry `json:"entries"`
}

// Prefix returns the first PrefixLength lowercase hex characters of s.
func Prefix(s string) string {
	if len(s) < PrefixLength {
		return strings.ToLower(s)
	}
	return strings.ToLower(s[:PrefixLength])
}

// BuildShards groups records by target hash prefix and returns a map of prefix
// to canonical JSON shard bytes.
func BuildShards(records []schema.Record) (map[string][]byte, error) {
	groups := map[string][]Entry{}
	for _, rec := range records {
		id, err := schema.RecordID(rec.Body)
		if err != nil {
			return nil, fmt.Errorf("record id: %w", err)
		}
		auditorID, err := schema.AuditorID(rec.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("auditor id: %w", err)
		}
		prefix := Prefix(rec.Body.Hash)
		groups[prefix] = append(groups[prefix], Entry{
			Target:    rec.Body.Target,
			RecordID:  id,
			AuditorID: auditorID,
			Size:      rec.Body.Size,
		})
	}
	out := map[string][]byte{}
	for prefix, entries := range groups {
		shard := Shard{Prefix: prefix, Entries: entries}
		b, err := canonicalJSON(shard)
		if err != nil {
			return nil, err
		}
		out[prefix] = b
	}
	return out, nil
}

// BuildShardForPrefix builds a single shard deterministically.
func BuildShardForPrefix(prefix string, entries []Entry) ([]byte, error) {
	// Deduplicate by record id.
	seen := map[string]struct{}{}
	uniq := []Entry{}
	for _, e := range entries {
		if _, ok := seen[e.RecordID]; ok {
			continue
		}
		seen[e.RecordID] = struct{}{}
		uniq = append(uniq, e)
	}
	sort.Slice(uniq, func(i, j int) bool {
		if uniq[i].RecordID != uniq[j].RecordID {
			return uniq[i].RecordID < uniq[j].RecordID
		}
		return uniq[i].Target < uniq[j].Target
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

// MatchExact returns the entries whose RecordID matches fullHash.
func MatchExact(shard []byte, fullHash string) ([]Entry, error) {
	var s Shard
	if err := json.Unmarshal(shard, &s); err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range s.Entries {
		if e.RecordID == fullHash {
			out = append(out, e)
		}
	}
	return out, nil
}

// VerifyShards rebuilds shards from records and checks each byte slice.
func VerifyShards(records []schema.Record, shards map[string][]byte) error {
	want, err := BuildShards(records)
	if err != nil {
		return err
	}
	for prefix, got := range shards {
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
