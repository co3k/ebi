package tlogx

import (
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

func TestLeafHash(t *testing.T) {
	l := Leaf{
		RecordID:  "a" + repeatZero(63),
		AuditorID: "b" + repeatZero(63),
		Signature: "c" + repeatZero(127),
	}
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
	leaf := Leaf{RecordID: "a" + repeatZero(63), AuditorID: "b" + repeatZero(63), Signature: "c" + repeatZero(127)}
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
	leaves := []Leaf{
		{RecordID: "a" + repeatZero(63), AuditorID: "b" + repeatZero(63), Signature: "c" + repeatZero(127)},
		{RecordID: "d" + repeatZero(63), AuditorID: "e" + repeatZero(63), Signature: "f" + repeatZero(127)},
		{RecordID: "0" + repeatZero(63), AuditorID: "1" + repeatZero(63), Signature: "2" + repeatZero(127)},
	}
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
	leaves := []Leaf{
		{RecordID: "a" + repeatZero(63), AuditorID: "b" + repeatZero(63), Signature: "c" + repeatZero(127)},
		{RecordID: "d" + repeatZero(63), AuditorID: "e" + repeatZero(63), Signature: "f" + repeatZero(127)},
		{RecordID: "0" + repeatZero(63), AuditorID: "1" + repeatZero(63), Signature: "2" + repeatZero(127)},
		{RecordID: "3" + repeatZero(63), AuditorID: "4" + repeatZero(63), Signature: "5" + repeatZero(127)},
	}
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
	leaves := []Leaf{
		{RecordID: "a" + repeatZero(63), AuditorID: "b" + repeatZero(63), Signature: "c" + repeatZero(127)},
	}
	for _, l := range leaves {
		lh, _ := LeafHash(l)
		tr.Append(lh)
	}
	signer, verifier, _, vkey, err := GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cp, err := CheckpointBytes(tr.TlogTree(), signer)
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
	wPolicy := Policy{LogName: "ebi.example.com", WitnessKeys: []string{verifier.String()}, RequiredWitnesses: 1}
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

func repeatZero(n int) string {
	s := "a"
	for len(s) < n {
		s += "0"
	}
	return s[:n]
}
