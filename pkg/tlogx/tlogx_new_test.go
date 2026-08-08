package tlogx

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/co3k/ebi/pkg/schema"
	"github.com/co3k/ebi/pkg/storage"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func TestLeafHashFixedVector(t *testing.T) {
	// Fixed leaf hash test vector. The leaf payload is 32 bytes of 0x00
	// (record ID), 32 bytes of 0x01 (auditor key hash), and 64 bytes of 0x02
	// (Ed25519 record signature).
	l := Leaf{
		RecordID:  strings.Repeat("00", 32),
		AuditorID: strings.Repeat("01", 32),
		Signature: strings.Repeat("02", 64),
	}
	got, err := LeafHash(l)
	if err != nil {
		t.Fatal(err)
	}
	want := "7fc75e67c0f6d6f892861645402e65d0d2878a4b9d86df88194363a4eb210029"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("leaf hash mismatch: got %s, want %s", hex.EncodeToString(got[:]), want)
	}
}

func TestLeafHashLengthValidation(t *testing.T) {
	base := makeLeaf("x")
	if _, err := LeafHash(base); err != nil {
		t.Fatal(err)
	}
	bad := base
	bad.RecordID = bad.RecordID[:62]
	if _, err := LeafHash(bad); err == nil {
		t.Fatal("expected error for short record id")
	}
	bad = base
	bad.AuditorID = bad.AuditorID + "00"
	if _, err := LeafHash(bad); err == nil {
		t.Fatal("expected error for long auditor id")
	}
	bad = base
	bad.Signature = bad.Signature[:126]
	if _, err := LeafHash(bad); err == nil {
		t.Fatal("expected error for short signature")
	}
}

func leafHashReader(leaves []tlog.Hash) tlog.HashReader {
	return tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			if idx < 0 || idx >= int64(len(leaves)) {
				return nil, fmt.Errorf("leaf index %d out of range", idx)
			}
			out[i] = leaves[idx]
		}
		return out, nil
	})
}

func TestTreeManyLeaves(t *testing.T) {
	var leaves []Leaf
	for i := 0; i < 100; i++ {
		leaves = append(leaves, makeLeaf(fmt.Sprintf("leaf%d", i)))
	}
	// Build each prefix size and compare the root against tlog.TreeHash on the
	// tree's stored hash reader, and verify every inclusion/consistency proof.
	for n := int64(1); n <= int64(len(leaves)); n++ {
		tr, err := NewTreeFromLeaves(leaves[:n])
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		leafHashes := make([]tlog.Hash, n)
		for i := int64(0); i < n; i++ {
			leafHashes[i], _ = LeafHash(leaves[i])
		}
		want, err := tlog.TreeHash(n, tr.HashReader())
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if tr.Root() != want {
			t.Fatalf("n=%d: root mismatch", n)
		}
		// Inclusion proofs for every leaf in this tree.
		for i := int64(0); i < n; i++ {
			proof, err := tr.RecordProof(i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if err := VerifyRecord(tr.TlogTree(), i, leafHashes[i], proof); err != nil {
				t.Fatalf("n=%d i=%d: verify inclusion: %v", n, i, err)
			}
		}
		// Consistency proof against the previous size.
		if n > 1 {
			proof, err := tr.TreeProof(n - 1)
			if err != nil {
				t.Fatalf("n=%d: prove consistency: %v", n, err)
			}
			prev, _ := NewTreeFromLeaves(leaves[:n-1])
			if err := VerifyConsistency(tr.TlogTree(), prev.TlogTree(), proof); err != nil {
				t.Fatalf("n=%d: verify consistency: %v", n, err)
			}
		}
	}
}

func TestTreeTamper(t *testing.T) {
	leaves := []Leaf{makeLeaf("a"), makeLeaf("b"), makeLeaf("c")}
	tr, err := NewTreeFromLeaves(leaves)
	if err != nil {
		t.Fatal(err)
	}
	lh, _ := LeafHash(leaves[1])
	proof, err := tr.RecordProof(1)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the claimed leaf hash.
	badLeaf := lh
	badLeaf[0] ^= 0xff
	if VerifyRecord(tr.TlogTree(), 1, badLeaf, proof) == nil {
		t.Fatal("expected corrupt leaf to fail")
	}
	// Wrong index.
	if VerifyRecord(tr.TlogTree(), 0, lh, proof) == nil {
		t.Fatal("expected wrong index to fail")
	}
	// Corrupt proof.
	badProof := make(tlog.RecordProof, len(proof))
	copy(badProof, proof)
	if len(badProof) > 0 {
		badProof[0][0] ^= 0xff
		if VerifyRecord(tr.TlogTree(), 1, lh, badProof) == nil {
			t.Fatal("expected corrupt proof to fail")
		}
	}
}

func TestNewTreeFromLeavesAndLoad(t *testing.T) {
	leaves := []Leaf{makeLeaf("a"), makeLeaf("b"), makeLeaf("c")}
	tr1, err := NewTreeFromLeaves(leaves)
	if err != nil {
		t.Fatal(err)
	}
	tr2, err := LoadTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if tr1.Size() != tr2.Size() || tr1.Root() != tr2.Root() {
		t.Fatal("NewTreeFromLeaves and LoadTree produced different trees")
	}
	// Sequential appends should produce the same root.
	tr3 := NewTree()
	for _, l := range leaves {
		if _, err := tr3.AppendLeaf(l); err != nil {
			t.Fatal(err)
		}
	}
	if tr3.Root() != tr1.Root() {
		t.Fatal("sequential append produced different root")
	}
}

func TestTilePathRoundtrip(t *testing.T) {
	tile := tlog.Tile{H: 8, L: 0, N: 0, W: 3}
	path := TilePath(tile)
	want := "v1/" + tile.Path()
	if path != want {
		t.Fatalf("tile path: got %q, want %q", path, want)
	}
	parsed, err := tlog.ParseTilePath(strings.TrimPrefix(path, "v1/"))
	if err != nil {
		t.Fatal(err)
	}
	if parsed != tile {
		t.Fatalf("tile roundtrip: got %+v, want %+v", parsed, tile)
	}
}

func TestCorruptTileFails(t *testing.T) {
	// Use three records so that the inclusion proof must read sibling hashes from
	// the level-0 tile.
	store, err := storage.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTree()
	var leaves []Leaf
	var leafHashes []tlog.Hash
	for i := 0; i < 3; i++ {
		rec, leaf := makeRecord(t, fmt.Sprintf("corrupt%d", i))
		idx, err := tr.AppendLeaf(leaf)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteRecord(store, idx, rec); err != nil {
			t.Fatal(err)
		}
		lh, _ := LeafHash(leaf)
		leaves = append(leaves, leaf)
		leafHashes = append(leafHashes, lh)
	}
	if err := WriteTiles(tr, store, DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	signer, _, _, vkey, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteCheckpoint(tr.TlogTree(), "ebi.example.com", signer, store); err != nil {
		t.Fatal(err)
	}
	policy := Policy{LogName: "ebi.example.com", LogKeys: []string{vkey}}
	if err := VerifyInclusionAt(store, 0, leafHashes[0], tr.TlogTree(), policy); err != nil {
		t.Fatalf("inclusion before tamper: %v", err)
	}
	// Corrupt the first tile.
	keys, err := store.List(context.Background(), "v1/tile")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("expected tiles")
	}
	sort.Strings(keys)
	data, err := store.Get(context.Background(), keys[0])
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 0xff
	if err := store.Put(context.Background(), storage.Object{Path: keys[0], Data: data, ContentType: "application/octet-stream", Immutable: true}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInclusionAt(store, 0, leafHashes[0], tr.TlogTree(), policy); err == nil {
		t.Fatal("expected corrupt tile to fail inclusion")
	}
}

func TestCheckpointFormatExactBytes(t *testing.T) {
	tr := tlog.Tree{N: 5, Hash: tlog.Hash{1, 2, 3}}
	text := FormatCheckpoint(tr, "ebi.example.com")
	lines := strings.Split(string(text), "\n")
	if len(lines) != 4 || lines[3] != "" {
		t.Fatalf("expected exactly 3 non-empty lines and trailing newline, got %q", lines)
	}
	if lines[0] != "ebi.example.com" {
		t.Fatalf("origin line: %q", lines[0])
	}
	if lines[1] != "5" {
		t.Fatalf("size line: %q", lines[1])
	}
	if lines[2] != base64.StdEncoding.EncodeToString(tr.Hash[:]) {
		t.Fatalf("root not base64: %q", lines[2])
	}
	if !bytes.HasSuffix(text, []byte("\n")) {
		t.Fatal("missing trailing newline")
	}
}

func TestWitnessQuorumMetAndUnmet(t *testing.T) {
	logSigner, _, _, logKey, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	witSigner, _, _, witKey, err := GenerateKeyPair("wit.example.com")
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTree()
	tr.AppendLeaf(makeLeaf("a"))
	origin := "ebi.example.com"
	cp, err := CheckpointBytes(tr.TlogTree(), origin, logSigner)
	if err != nil {
		t.Fatal(err)
	}
	logVer, err := note.NewVerifier(logKey)
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Open(cp, note.VerifierList(logVer))
	if err != nil {
		t.Fatal(err)
	}
	cosigned, err := note.Sign(n, witSigner)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{LogName: origin, LogKeys: []string{logKey}, WitnessKeys: []string{witKey}, RequiredWitnesses: 1}
	_, witnesses, err := VerifyCheckpoint(cosigned, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(witnesses) != 1 {
		t.Fatalf("expected 1 witness, got %d", len(witnesses))
	}
	// Unmet quorum.
	policy2 := policy
	policy2.RequiredWitnesses = 2
	if _, _, err := VerifyCheckpoint(cosigned, policy2); err == nil {
		t.Fatal("expected unmet quorum error")
	}
	// Missing log signature should fail.
	policy3 := Policy{LogName: origin, WitnessKeys: []string{witKey}, RequiredWitnesses: 0}
	if _, _, err := VerifyCheckpoint(cosigned, policy3); err == nil {
		t.Fatal("expected missing log signature error")
	}
}

func TestC2SPTimestampedWitnessQuorum(t *testing.T) {
	logSigner, _, _, logKey, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	witnessPub, witnessPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	witnessName := "witness.example.com"
	encodedPublic := append([]byte{cosignatureEd25519}, witnessPub...)
	witnessHash := namedKeyHash(witnessName, encodedPublic)
	witnessKey := fmt.Sprintf("%s+%08x+%s", witnessName, witnessHash, base64.StdEncoding.EncodeToString(encodedPublic))

	tree := NewTree()
	if _, err := tree.AppendLeaf(makeLeaf("c2sp")); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := CheckpointBytes(tree.TlogTree(), "ebi.example.com", logSigner)
	if err != nil {
		t.Fatal(err)
	}
	logVerifier, err := note.NewVerifier(logKey)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := note.Open(checkpoint, note.VerifierList(logVerifier))
	if err != nil {
		t.Fatal(err)
	}
	timestamp := uint64(1_785_715_200)
	message := []byte(fmt.Sprintf("cosignature/v1\ntime %d\n%s", timestamp, opened.Text))
	rawSignature := make([]byte, 8+ed25519.SignatureSize)
	binary.BigEndian.PutUint64(rawSignature[:8], timestamp)
	copy(rawSignature[8:], ed25519.Sign(witnessPriv, message))
	envelope := make([]byte, 4+len(rawSignature))
	binary.BigEndian.PutUint32(envelope[:4], witnessHash)
	copy(envelope[4:], rawSignature)
	signatureLine := []byte(fmt.Sprintf("— %s %s\n", witnessName, base64.StdEncoding.EncodeToString(envelope)))
	cosigned := append(append([]byte(nil), checkpoint...), signatureLine...)

	policy := Policy{
		LogName:           "ebi.example.com",
		LogKeys:           []string{logKey},
		WitnessKeys:       []string{witnessKey},
		RequiredWitnesses: 1,
	}
	if _, witnesses, err := VerifyCheckpoint(cosigned, policy); err != nil || len(witnesses) != 1 {
		t.Fatalf("C2SP witness verification failed: witnesses=%v err=%v", witnesses, err)
	}
	merged, err := MergeWitnessSignature(checkpoint, signatureLine, []string{witnessKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, witnesses, err := VerifyCheckpoint(merged, policy); err != nil || len(witnesses) != 1 {
		t.Fatalf("merged C2SP witness verification failed: witnesses=%v err=%v", witnesses, err)
	}

	tampered := append([]byte(nil), signatureLine...)
	tampered[len(tampered)-3] ^= 1
	if _, err := MergeWitnessSignature(checkpoint, tampered, []string{witnessKey}); err == nil {
		t.Fatal("expected tampered C2SP cosignature to fail")
	}
}

func TestPolicyLoadSaveAndValidation(t *testing.T) {
	_, _, _, logKey, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, witKey, err := GenerateKeyPair("wit.example.com")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	p := Policy{
		LogName:           "ebi.example.com",
		LogKeys:           []string{logKey},
		WitnessKeys:       []string{witKey},
		RequiredWitnesses: 1,
	}
	if err := SavePolicy(path, p); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.LogName != p.LogName || got.RequiredWitnesses != p.RequiredWitnesses || len(got.LogKeys) != 1 || len(got.WitnessKeys) != 1 {
		t.Fatalf("policy roundtrip mismatch: %+v", got)
	}

	// Validation errors.
	if err := SavePolicy(path, Policy{LogName: "x", RequiredWitnesses: -1}); err == nil {
		t.Fatal("expected negative quorum error")
	}
	if err := SavePolicy(path, Policy{LogName: "x", LogKeys: []string{logKey}, WitnessKeys: []string{witKey}, RequiredWitnesses: 2}); err == nil {
		t.Fatal("expected quorum too large error")
	}
	if err := SavePolicy(path, Policy{LogName: "x", LogKeys: []string{logKey, logKey}}); err == nil {
		t.Fatal("expected duplicate log key error")
	}
	if err := SavePolicy(path, Policy{LogName: "x", LogKeys: []string{logKey}, WitnessKeys: []string{logKey}}); err == nil {
		t.Fatal("expected overlapping keys error")
	}
}

func TestDefaultPolicyFile(t *testing.T) {
	path := "testdata/default-policy.toml"
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.LogName != "ebi.example.com" {
		t.Fatalf("origin: %q", p.LogName)
	}
	if len(p.LogKeys) != 0 || len(p.WitnessKeys) != 0 || p.RequiredWitnesses != 0 {
		t.Fatal("default policy should be empty and require configuration")
	}
}

func TestCheckpointState(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "checkpoint-state.toml")

	logSigner, _, _, logKey, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{LogName: "ebi.example.com", LogKeys: []string{logKey}}
	store, err := storage.NewLocal(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}

	// Initial state with an empty tree.
	tr0 := NewTree()
	cp0, err := CheckpointBytes(tr0.TlogTree(), "ebi.example.com", logSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveCheckpointState(statePath, tr0.TlogTree(), cp0); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatalf("state file mode too permissive: %o", info.Mode().Perm())
	}
	loadedTree, loadedRaw, err := LoadCheckpointState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if loadedTree != tr0.TlogTree() {
		t.Fatal("loaded tree mismatch")
	}
	if !bytes.Equal(loadedRaw, cp0) {
		t.Fatal("loaded checkpoint mismatch")
	}

	// Grow the log and verify the new checkpoint against the prior state.
	leaves := []Leaf{makeLeaf("a"), makeLeaf("b"), makeLeaf("c")}
	tr1, err := NewTreeFromLeaves(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteTiles(tr1, store, DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	cp1, err := CheckpointBytes(tr1.TlogTree(), "ebi.example.com", logSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveCheckpointState(statePath, tr1.TlogTree(), cp1); err != nil {
		t.Fatal(err)
	}
	_, _, err = VerifyCheckpointState(cp1, loadedTree, policy, store)
	if err != nil {
		t.Fatal(err)
	}

	// Equal same root is accepted.
	_, _, err = VerifyCheckpointState(cp1, tr1.TlogTree(), policy, store)
	if err != nil {
		t.Fatal(err)
	}

	// Grow further to exercise consistency proof against a non-empty prior tree.
	leaves2 := []Leaf{makeLeaf("d"), makeLeaf("e"), makeLeaf("f")}
	tr2, err := NewTreeFromLeaves(append(leaves, leaves2...))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteTiles(tr2, store, DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	cp2, err := CheckpointBytes(tr2.TlogTree(), "ebi.example.com", logSigner)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = VerifyCheckpointState(cp2, tr1.TlogTree(), policy, store)
	if err != nil {
		t.Fatal(err)
	}

	// Rollback must fail.
	_, _, err = VerifyCheckpointState(cp0, tr1.TlogTree(), policy, store)
	if err == nil {
		t.Fatal("expected rollback error")
	}
	// Equivocation must fail: same size but different root.
	fake := tr1.TlogTree()
	fake.Hash[0] ^= 0xff
	cpFake, err := CheckpointBytes(fake, "ebi.example.com", logSigner)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = VerifyCheckpointState(cpFake, tr1.TlogTree(), policy, store)
	if err == nil {
		t.Fatal("expected equivocation error")
	}
}

func TestVerifyInclusionAtAgainstSuppliedTree(t *testing.T) {
	logSigner, _, _, logKey, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{LogName: "ebi.example.com", LogKeys: []string{logKey}}
	store, err := storage.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTree()
	var leaves []Leaf
	var leafHashes []tlog.Hash
	for i := 0; i < 10; i++ {
		rec, leaf := makeRecord(t, fmt.Sprintf("r%d", i))
		idx, err := tr.AppendLeaf(leaf)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteRecord(store, idx, rec); err != nil {
			t.Fatal(err)
		}
		lh, _ := LeafHash(leaf)
		leaves = append(leaves, leaf)
		leafHashes = append(leafHashes, lh)
	}
	if err := WriteTiles(tr, store, DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	treeN := tr.TlogTree()
	if err := WriteCheckpoint(treeN, "ebi.example.com", logSigner, store); err != nil {
		t.Fatal(err)
	}

	// Advance to N+1 and overwrite the checkpoint and tiles. The old tiles
	// needed to prove inclusion in tree N must remain readable.
	rec, leaf := makeRecord(t, "extra")
	idx, err := tr.AppendLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRecord(store, idx, rec); err != nil {
		t.Fatal(err)
	}
	if err := WriteTiles(tr, store, DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	if err := WriteCheckpoint(tr.TlogTree(), "ebi.example.com", logSigner, store); err != nil {
		t.Fatal(err)
	}

	// Verification against the retained immutable tree N must succeed even
	// though the mutable checkpoint now points at N+1.
	for i := int64(0); i < treeN.N; i++ {
		if err := VerifyInclusionAt(store, i, leafHashes[i], treeN, policy); err != nil {
			t.Fatalf("index %d against retained tree N: %v", i, err)
		}
	}

	// Bounds checks are preserved.
	if err := VerifyInclusionAt(store, -1, leafHashes[0], treeN, policy); err == nil {
		t.Fatal("expected negative index error")
	}
	if err := VerifyInclusionAt(store, treeN.N, leafHashes[0], treeN, policy); err == nil {
		t.Fatal("expected out-of-range index error")
	}

	// Tampered leaf must still fail.
	badLeaf := leafHashes[0]
	badLeaf[0] ^= 0xff
	if err := VerifyInclusionAt(store, 0, badLeaf, treeN, policy); err == nil {
		t.Fatal("expected tampered leaf to fail")
	}
}

func TestVerifyInclusionAt(t *testing.T) {
	logSigner, _, _, logKey, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{LogName: "ebi.example.com", LogKeys: []string{logKey}}
	store, err := storage.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTree()
	var leaves []Leaf
	var leafHashes []tlog.Hash
	for i := 0; i < 10; i++ {
		rec, leaf := makeRecord(t, fmt.Sprintf("r%d", i))
		idx, err := tr.AppendLeaf(leaf)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteRecord(store, idx, rec); err != nil {
			t.Fatal(err)
		}
		lh, _ := LeafHash(leaf)
		leaves = append(leaves, leaf)
		leafHashes = append(leafHashes, lh)
	}
	if err := WriteTiles(tr, store, DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	if err := WriteCheckpoint(tr.TlogTree(), "ebi.example.com", logSigner, store); err != nil {
		t.Fatal(err)
	}
	for i := int64(0); i < tr.Size(); i++ {
		if err := VerifyInclusionAt(store, i, leafHashes[i], tr.TlogTree(), policy); err != nil {
			t.Fatalf("index %d: %v", i, err)
		}
	}
	if err := VerifyInclusionAt(store, -1, leafHashes[0], tr.TlogTree(), policy); err == nil {
		t.Fatal("expected negative index error")
	}
	if err := VerifyInclusionAt(store, tr.Size(), leafHashes[0], tr.TlogTree(), policy); err == nil {
		t.Fatal("expected out-of-range index error")
	}
}

func TestLoadLeavesFromIndex(t *testing.T) {
	store, err := storage.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var want []Leaf
	for i := 0; i < 5; i++ {
		rec, leaf := makeRecord(t, fmt.Sprintf("leaf%d", i))
		if err := WriteRecord(store, int64(i), rec); err != nil {
			t.Fatal(err)
		}
		want = append(want, leaf)
	}
	got, err := LoadLeavesFromIndex(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d leaves, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("leaf %d mismatch: got %+v, want %+v", i, got[i], want[i])
		}
	}
	// Loading leaves and rebuilding the tree should match the original order.
	tr1, err := NewTreeFromLeaves(want)
	if err != nil {
		t.Fatal(err)
	}
	tr2, err := LoadTree(got)
	if err != nil {
		t.Fatal(err)
	}
	if tr1.Root() != tr2.Root() {
		t.Fatal("rebuilt tree root mismatch")
	}
}

func TestDecodeLeafIndexStrict(t *testing.T) {
	rec, leaf := makeRecord(t, "strict-leaf")
	hash, err := LeafHash(leaf)
	if err != nil {
		t.Fatal(err)
	}
	id, err := schema.RecordID(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := json.Marshal(LeafIndex{Index: 0, Leaf: Base64Hash(hash), RecordID: id})
	if err != nil {
		t.Fatal(err)
	}
	if _, gotHash, err := DecodeLeafIndex("v1/leaf/0", valid); err != nil || gotHash != hash {
		t.Fatalf("valid leaf index rejected: %v", err)
	}

	cases := []struct {
		name string
		path string
		data []byte
	}{
		{"noncanonical path", "v1/leaf/00", valid},
		{"path mismatch", "v1/leaf/1", valid},
		{"unknown field", "v1/leaf/0", append(valid[:len(valid)-1], []byte(`,"extra":true}`)...)},
		{"trailing data", "v1/leaf/0", append(valid, []byte(`{}`)...)},
		{"bad record id", "v1/leaf/0", []byte(`{"index":0,"leaf":"` + Base64Hash(hash) + `","record_id":"bad"}`)},
		{"bad leaf hash", "v1/leaf/0", []byte(`{"index":0,"leaf":"bad","record_id":"` + id + `"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := DecodeLeafIndex(tc.path, tc.data); err == nil {
				t.Fatal("expected strict decode failure")
			}
		})
	}
}

func TestLoadLeafIndexesRejectsGapAndDuplicateRecord(t *testing.T) {
	rec0, leaf0 := makeRecord(t, "index-zero")
	rec1, leaf1 := makeRecord(t, "index-one")
	h0, _ := LeafHash(leaf0)
	h1, _ := LeafHash(leaf1)
	id0, _ := schema.RecordID(rec0.Body)
	id1, _ := schema.RecordID(rec1.Body)

	t.Run("gap", func(t *testing.T) {
		store := storage.NewMem()
		if err := WriteLeafIndex(store, 0, h0, id0); err != nil {
			t.Fatal(err)
		}
		if err := WriteLeafIndex(store, 2, h1, id1); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadLeafIndexes(context.Background(), store); err == nil {
			t.Fatal("expected missing leaf index error")
		}
	})

	t.Run("duplicate record", func(t *testing.T) {
		store := storage.NewMem()
		if err := WriteLeafIndex(store, 0, h0, id0); err != nil {
			t.Fatal(err)
		}
		if err := WriteLeafIndex(store, 1, h0, id0); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadLeafIndexes(context.Background(), store); err == nil {
			t.Fatal("expected duplicate record error")
		}
	})
}

func TestDecodeTombstoneBlobStrict(t *testing.T) {
	id := strings.Repeat("a", 64)
	valid, err := json.Marshal(Tombstone{
		Tombstone: true,
		RecordID:  id,
		Reason:    "privacy",
		Message:   "rotate credentials",
		DeletedAt: "2026-08-02T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := DecodeTombstoneBlob(valid, id); err != nil || !ok {
		t.Fatalf("valid tombstone rejected: ok=%v err=%v", ok, err)
	}
	if _, ok, err := DecodeTombstoneBlob([]byte(`{"body":{}}`), id); err != nil || ok {
		t.Fatalf("ordinary JSON must not be a tombstone: ok=%v err=%v", ok, err)
	}
	for _, data := range [][]byte{
		[]byte(`{"tombstone":true}`),
		[]byte(`{"tombstone":false,"record_id":"` + id + `","reason":"privacy","message":"rotate","deleted_at":"2026-08-02T00:00:00Z"}`),
		[]byte(`{"tombstone":true,"record_id":"` + strings.Repeat("b", 64) + `","reason":"privacy","message":"rotate","deleted_at":"2026-08-02T00:00:00Z"}`),
		[]byte(`{"tombstone":true,"record_id":"` + id + `","reason":"privacy","message":"rotate","deleted_at":"bad"}`),
		[]byte(`{"tombstone":true,"record_id":"` + id + `","reason":"privacy","message":"rotate","deleted_at":"2026-08-02T00:00:00Z","unknown":true}`),
	} {
		if _, ok, err := DecodeTombstoneBlob(data, id); err == nil || !ok {
			t.Fatalf("expected strict tombstone failure: ok=%v err=%v data=%s", ok, err, data)
		}
	}
}

func TestAddCheckpointRequest(t *testing.T) {
	leaves := []Leaf{makeLeaf("a"), makeLeaf("b"), makeLeaf("c")}
	tr, err := NewTreeFromLeaves(leaves)
	if err != nil {
		t.Fatal(err)
	}
	logSigner, _, _, _, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cp, err := CheckpointBytes(tr.TlogTree(), "ebi.example.com", logSigner)
	if err != nil {
		t.Fatal(err)
	}
	old := tlog.Tree{N: 1, Hash: tr.TlogTree().Hash}
	proof, err := tr.TreeProof(old.N)
	if err != nil {
		t.Fatal(err)
	}
	req, err := AddCheckpointRequest(t.Context(), "https://witness.example.com", old.N, proof, cp)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != http.MethodPost {
		t.Fatalf("method %q", req.Method)
	}
	if req.URL.String() != "https://witness.example.com/add-checkpoint" {
		t.Fatalf("url %q", req.URL.String())
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(body), "\n")
	if parts[0] != "old 1" {
		t.Fatalf("old size line: %q", parts[0])
	}
	if !bytes.Contains(body, cp) {
		t.Fatal("request body missing signed checkpoint")
	}
}

func TestParseWitnessResponse(t *testing.T) {
	// 200 OK with complete signed-note signature lines.
	sig := "— witness.example/w1 " + base64.StdEncoding.EncodeToString([]byte("example-signature"))
	resp := httptest.NewRecorder()
	resp.WriteHeader(http.StatusOK)
	resp.WriteString(sig + "\n")
	sigs, size, err := ParseWitnessResponse(resp.Result())
	if err != nil {
		t.Fatal(err)
	}
	if size != 0 {
		t.Fatalf("size %d", size)
	}
	if len(sigs) != 1 || string(sigs[0]) != sig+"\n" {
		t.Fatalf("sigs: %v", sigs)
	}

	// 409 Conflict with size.
	resp2 := httptest.NewRecorder()
	resp2.Header().Set("Content-Type", "text/x.tlog.size")
	resp2.WriteHeader(http.StatusConflict)
	resp2.WriteString("42\n")
	sigs, size, err = ParseWitnessResponse(resp2.Result())
	if err != nil {
		t.Fatal(err)
	}
	if size != 42 {
		t.Fatalf("size %d", size)
	}
	if len(sigs) != 0 {
		t.Fatalf("expected no sigs, got %v", sigs)
	}

	// Non-200/409 is an error.
	resp3 := httptest.NewRecorder()
	resp3.WriteHeader(http.StatusBadRequest)
	if _, _, err := ParseWitnessResponse(resp3.Result()); err == nil {
		t.Fatal("expected error for bad request")
	}
}

func makeRecord(t *testing.T, seed string) (schema.Record, Leaf) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: time.Now().Unix(),
		Auditor:   schema.AuditorHash(pub),
		Target: schema.Target{
			URL:    "https://example.com/" + seed,
			SHA256: hex64(seed),
			Size:   1,
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
	leaf, err := RecordToLeaf(*rec)
	if err != nil {
		t.Fatal(err)
	}
	return *rec, leaf
}
