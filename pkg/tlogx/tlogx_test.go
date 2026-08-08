package tlogx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/co3k/ebi/pkg/storage"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func hex64(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hex128(s string) string {
	return hex64(s) + hex64(s+":sig")
}

func makeLeaf(s string) Leaf {
	return Leaf{RecordID: hex64(s), AuditorID: hex64(s), Signature: hex128(s)}
}

func TestLeafHash(t *testing.T) {
	l := makeLeaf("a")
	lh, err := LeafHash(l)
	if err != nil {
		t.Fatal(err)
	}
	if lh == (tlog.Hash{}) {
		t.Fatal("leaf hash is zero")
	}
	_, err = LeafHash(Leaf{})
	if err == nil {
		t.Fatal("expected error for empty leaf")
	}
}

func TestTreeAppend(t *testing.T) {
	tr := NewTree()
	leaf := makeLeaf("a")
	lh, _ := LeafHash(leaf)
	if err := tr.Append(lh); err != nil {
		t.Fatal(err)
	}
	if tr.Size() != 1 {
		t.Fatalf("size %d", tr.Size())
	}
	idx, err := tr.AppendLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if idx != 1 {
		t.Fatalf("index %d", idx)
	}
	if tr.Size() != 2 {
		t.Fatalf("size %d", tr.Size())
	}
}

func TestRecordProof(t *testing.T) {
	tr := NewTree()
	leaves := []Leaf{makeLeaf("a"), makeLeaf("b"), makeLeaf("c")}
	for _, l := range leaves {
		lh, _ := LeafHash(l)
		tr.Append(lh)
	}
	proof, err := tr.RecordProof(1)
	if err != nil {
		t.Fatal(err)
	}
	lh, _ := LeafHash(leaves[1])
	if err := VerifyRecord(tr.TlogTree(), 1, lh, proof); err != nil {
		t.Fatal(err)
	}
}

func TestConsistencyProof(t *testing.T) {
	tr := NewTree()
	leaves := []Leaf{makeLeaf("a"), makeLeaf("b"), makeLeaf("c"), makeLeaf("d")}
	for _, l := range leaves[:2] {
		lh, _ := LeafHash(l)
		tr.Append(lh)
	}
	old := tr.TlogTree()
	for _, l := range leaves[2:] {
		lh, _ := LeafHash(l)
		tr.Append(lh)
	}
	new := tr.TlogTree()
	proof, err := tr.TreeProof(old.N)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(new, old, proof); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointSignVerify(t *testing.T) {
	tr := NewTree()
	tr.AppendLeaf(makeLeaf("a"))
	signer, _, _, vkey, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cp, err := CheckpointBytes(tr.TlogTree(), "ebi.example.com", signer)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{LogName: "ebi.example.com", LogKeys: []string{vkey}}
	got, _, err := VerifyCheckpoint(cp, policy)
	if err != nil {
		t.Fatal(err)
	}
	if got.N != tr.Size() {
		t.Fatalf("size %d", got.N)
	}
	if got.Hash != tr.Root() {
		t.Fatal("root mismatch")
	}
	// Witness verification with a self-signed witness should fail (no log key).
	wPolicy := Policy{LogName: "ebi.example.com", WitnessKeys: []string{vkey}, RequiredWitnesses: 1}
	_, _, err = VerifyCheckpoint(cp, wPolicy)
	if err == nil {
		t.Fatal("expected missing log signature error")
	}
}

func TestCheckpointConsistency(t *testing.T) {
	old := tlog.Tree{N: 5, Hash: tlog.Hash{1}}
	new := tlog.Tree{N: 5, Hash: tlog.Hash{1}}
	if err := VerifyCheckpointConsistency(new, old); err != nil {
		t.Fatal(err)
	}
	bad := tlog.Tree{N: 4, Hash: tlog.Hash{1}}
	if err := VerifyCheckpointConsistency(bad, old); err == nil {
		t.Fatal("expected rollback error")
	}
	new2 := tlog.Tree{N: 5, Hash: tlog.Hash{2}}
	if err := VerifyCheckpointConsistency(new2, old); err == nil {
		t.Fatal("expected equivocation error")
	}
}

func TestCheckpointTamper(t *testing.T) {
	tr := NewTree()
	tr.AppendLeaf(makeLeaf("a"))
	signer, _, _, vkey, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cp, err := CheckpointBytes(tr.TlogTree(), "ebi.example.com", signer)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{LogName: "ebi.example.com", LogKeys: []string{vkey}}
	// Tamper with the checkpoint bytes.
	for i := range cp {
		if cp[i] != '\n' {
			bad := make([]byte, len(cp))
			copy(bad, cp)
			bad[i] ^= 0xff
			if _, _, err := VerifyCheckpoint(bad, policy); err == nil {
				t.Fatalf("tampered checkpoint at byte %d verified", i)
			}
			break
		}
	}
	// Wrong origin.
	cp2, err := CheckpointBytes(tr.TlogTree(), "evil.example.com", signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCheckpoint(cp2, policy); err == nil {
		t.Fatal("expected origin mismatch error")
	}
}

func TestWitnessCosignature(t *testing.T) {
	logSigner, logVerifier, _, logKey, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	witnessSigner, _, _, witnessKey, err := GenerateKeyPair("wit.example.com")
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
	// Add witness cosignature.
	n, err := note.Open(cp, note.VerifierList(logVerifier))
	if err != nil {
		t.Fatal(err)
	}
	cosigned, err := note.Sign(n, witnessSigner)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{LogName: origin, LogKeys: []string{logKey}, WitnessKeys: []string{witnessKey}, RequiredWitnesses: 1}
	_, witnesses, err := VerifyCheckpoint(cosigned, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(witnesses) != 1 {
		t.Fatalf("expected 1 witness, got %d", len(witnesses))
	}
	// Missing witness.
	policy2 := Policy{LogName: origin, LogKeys: []string{logKey}, WitnessKeys: []string{witnessKey}, RequiredWitnesses: 2}
	if _, _, err := VerifyCheckpoint(cosigned, policy2); err == nil {
		t.Fatal("expected missing witness error")
	}
}

func TestWriteTiles(t *testing.T) {
	tr := NewTree()
	for i := 0; i < 20; i++ {
		tr.AppendLeaf(makeLeaf(string(rune('a' + i))))
	}
	store, err := storage.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteTiles(tr, store, DefaultTileHeight); err != nil {
		t.Fatal(err)
	}
	items, err := store.List(context.Background(), "v1/tile")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("expected tiles written")
	}
	// Verify all records via tiles.
	leaves := tr.Leaves()
	for i, l := range leaves {
		proof, err := tr.RecordProof(int64(i))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyRecord(tr.TlogTree(), int64(i), l, proof); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCheckpointStorage(t *testing.T) {
	tr := NewTree()
	tr.AppendLeaf(makeLeaf("a"))
	signer, _, _, vkey, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteCheckpoint(tr.TlogTree(), "ebi.example.com", signer, store); err != nil {
		t.Fatal(err)
	}
	policy := Policy{LogName: "ebi.example.com", LogKeys: []string{vkey}}
	got, _, err := ReadCheckpoint(store, policy)
	if err != nil {
		t.Fatal(err)
	}
	if got.N != tr.Size() {
		t.Fatalf("size %d", got.N)
	}
	if got.Hash != tr.Root() {
		t.Fatal("root mismatch")
	}
}

func TestCheckpointParse(t *testing.T) {
	tr := tlog.Tree{N: 5, Hash: tlog.Hash{1}}
	text := FormatCheckpoint(tr, "ebi.example.com")
	got, origin, err := ParseCheckpoint(text)
	if err != nil {
		t.Fatal(err)
	}
	if origin != "ebi.example.com" {
		t.Fatalf("origin %q", origin)
	}
	if got.N != tr.N || got.Hash != tr.Hash {
		t.Fatal("parse mismatch")
	}
	// Canonical base64 with a trailing newline is required.
	if _, _, err := ParseCheckpoint([]byte("origin\n5\n" + Base64Hash(tr.Hash) + "\n")); err != nil {
		t.Fatal(err)
	}
	// Bad size.
	if _, _, err := ParseCheckpoint([]byte("origin\nfoo\n" + Base64Hash(tr.Hash) + "\n")); err == nil {
		t.Fatal("expected bad size")
	}
	// Bad hash.
	if _, _, err := ParseCheckpoint([]byte("origin\n5\nnotahash\n")); err == nil {
		t.Fatal("expected bad hash")
	}
	if _, _, err := ParseCheckpoint([]byte("origin\n05\n" + Base64Hash(tr.Hash) + "\n")); err == nil {
		t.Fatal("expected non-canonical size")
	}
	if _, _, err := ParseCheckpoint([]byte("origin\n5\n" + Base64Hash(tr.Hash))); err == nil {
		t.Fatal("expected missing final newline")
	}
}

func TestCheckpointBytesOrigin(t *testing.T) {
	tr := NewTree()
	tr.AppendLeaf(makeLeaf("a"))
	signer, _, _, _, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cp, err := CheckpointBytes(tr.TlogTree(), "ebi.example.com", signer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(cp, []byte("ebi.example.com\n")) {
		t.Fatal("missing origin in checkpoint")
	}
}

func repeatZero(n int) string {
	s := "a"
	for len(s) < n {
		s += "0"
	}
	return s[:n]
}
