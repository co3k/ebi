// Package tlogx implements a transparency log for ebi using golang.org/x/mod/sumdb/tlog
// and the note signing format. It supports Merkle append, inclusion/consistency
// verification, tile-compatible storage, and k-of-N witness policies.
package tlogx

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/co3k/ebi/pkg/storage"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Leaf is the input to a single log leaf hash.
type Leaf struct {
	RecordID   string
	AuditorID  string
	Signature  string
}

// LeafHash returns SHA-256(recordID || auditorID || signature) bytes.
// All fields are passed as the canonical hex string for record and auditor IDs
// and the hex signature.
func LeafHash(l Leaf) (tlog.Hash, error) {
	if l.RecordID == "" || l.AuditorID == "" || l.Signature == "" {
		return tlog.Hash{}, fmt.Errorf("leaf fields are required")
	}
	rec, err := hex.DecodeString(l.RecordID)
	if err != nil {
		return tlog.Hash{}, fmt.Errorf("decode record id: %w", err)
	}
	aud, err := hex.DecodeString(l.AuditorID)
	if err != nil {
		return tlog.Hash{}, fmt.Errorf("decode auditor id: %w", err)
	}
	sig, err := hex.DecodeString(l.Signature)
	if err != nil {
		return tlog.Hash{}, fmt.Errorf("decode signature: %w", err)
	}
	buf := make([]byte, 0, len(rec)+len(aud)+len(sig))
	buf = append(buf, rec...)
	buf = append(buf, aud...)
	buf = append(buf, sig...)
	h := sha256.Sum256(buf)
	return tlog.Hash(h), nil
}

// Tree is a memory-only transparency tree. It is not safe for concurrent use.
type Tree struct {
	leaves []tlog.Hash
	stored map[int64]tlog.Hash
	root   tlog.Hash
	size   int64
}

// NewTree creates an empty tree.
func NewTree() *Tree {
	return &Tree{leaves: []tlog.Hash{}, stored: map[int64]tlog.Hash{}}
}

// Size returns the current tree size.
func (t *Tree) Size() int64 { return t.size }

// Root returns the current tree root hash.
func (t *Tree) Root() tlog.Hash { return t.root }

// Leaves returns a defensive copy of the leaf hashes.
func (t *Tree) Leaves() []tlog.Hash {
	out := make([]tlog.Hash, len(t.leaves))
	copy(out, t.leaves)
	return out
}

// Append adds a new leaf hash to the tree and recomputes the stored hashes.
func (t *Tree) Append(leaf tlog.Hash) error {
	t.leaves = append(t.leaves, leaf)
	t.size = int64(len(t.leaves))
	t.rebuild()
	return nil
}

// AppendLeaf adds a leaf derived from a record and returns its index.
func (t *Tree) AppendLeaf(l Leaf) (int64, error) {
	lh, err := LeafHash(l)
	if err != nil {
		return 0, err
	}
	idx := t.size
	if err := t.Append(lh); err != nil {
		return 0, err
	}
	return idx, nil
}

// AppendRecords appends multiple leaves and returns the new tree size.
func (t *Tree) AppendRecords(records []Leaf) (int64, error) {
	for _, r := range records {
		lh, err := LeafHash(r)
		if err != nil {
			return 0, err
		}
		t.leaves = append(t.leaves, lh)
	}
	t.size = int64(len(t.leaves))
	t.rebuild()
	return t.size, nil
}

// TlogTree returns a tlog.Tree description for the current tree.
func (t *Tree) TlogTree() tlog.Tree {
	return tlog.Tree{N: t.size, Hash: t.root}
}

// rebuild recomputes all stored hashes and the root.
func (t *Tree) rebuild() {
	t.stored = map[int64]tlog.Hash{}
	count := tlog.StoredHashCount(t.size)
	for i := int64(0); i < count; i++ {
		level, n := tlog.SplitStoredHashIndex(i)
		t.stored[i] = subtreeHash(level, n, t.leaves)
	}
	if t.size == 0 {
		t.root = tlog.Hash{}
		return
	}
	root := rootHash(t.leaves)
	t.root = root
}

// subtreeHash returns the hash of the perfect subtree at level, index n.
func subtreeHash(level int, n int64, leaves []tlog.Hash) tlog.Hash {
	start := n << level
	if start >= int64(len(leaves)) {
		return tlog.Hash{}
	}
	if level == 0 {
		return leaves[start]
	}
	left := subtreeHash(level-1, n*2, leaves)
	right := subtreeHash(level-1, n*2+1, leaves)
	return tlog.NodeHash(left, right)
}

// rootHash returns the Merkle root of the given leaves.
func rootHash(leaves []tlog.Hash) tlog.Hash {
	if len(leaves) == 0 {
		return tlog.Hash{}
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	next := make([]tlog.Hash, 0, (len(leaves)+1)/2)
	for i := 0; i < len(leaves); i += 2 {
		if i+1 < len(leaves) {
			next = append(next, tlog.NodeHash(leaves[i], leaves[i+1]))
		} else {
			next = append(next, leaves[i])
		}
	}
	return rootHash(next)
}

// hashReader returns a HashReader backed by the tree's stored hashes.
func (t *Tree) hashReader() tlog.HashReader {
	return tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			h, ok := t.stored[idx]
			if !ok {
				return nil, fmt.Errorf("missing stored hash index %d", idx)
			}
			out[i] = h
		}
		return out, nil
	})
}

// RecordProof returns an inclusion proof for leaf at index n.
func (t *Tree) RecordProof(n int64) (tlog.RecordProof, error) {
	if n < 0 || n >= t.size {
		return nil, fmt.Errorf("leaf index %d out of range [0,%d)", n, t.size)
	}
	return tlog.ProveRecord(t.size, n, t.hashReader())
}

// TreeProof returns a consistency proof against an older tree size.
func (t *Tree) TreeProof(oldSize int64) (tlog.TreeProof, error) {
	if oldSize < 0 || oldSize > t.size {
		return nil, fmt.Errorf("old size %d out of range [0,%d]", oldSize, t.size)
	}
	return tlog.ProveTree(t.size, oldSize, t.hashReader())
}

// VerifyRecord checks an inclusion proof for leaf n against tree.
func VerifyRecord(tree tlog.Tree, n int64, leaf tlog.Hash, proof tlog.RecordProof) error {
	return tlog.CheckRecord(proof, tree.N, tree.Hash, n, leaf)
}

// VerifyConsistency checks a consistency proof between old and new trees.
func VerifyConsistency(new, old tlog.Tree, proof tlog.TreeProof) error {
	return tlog.CheckTree(proof, new.N, new.Hash, old.N, old.Hash)
}

// DefaultTileHeight is the tile height used for tile storage.
const DefaultTileHeight = 8

// tileStorage is a tlog.TileReader that reads from a storage.Store.
type tileStorage struct {
	store  storage.Store
	height int
}

// NewTileReader returns a TileReader that reads tile data from store.
func NewTileReader(store storage.Store, height int) tlog.TileReader {
	if height <= 0 {
		height = DefaultTileHeight
	}
	return &tileStorage{store: store, height: height}
}

func (ts *tileStorage) Height() int { return ts.height }

func (ts *tileStorage) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, tile := range tiles {
		path := tilePath(tile)
		data, err := ts.store.Get(context.Background(), path)
		if err != nil {
			return nil, fmt.Errorf("read tile %s: %w", path, err)
		}
		expected := tile.W * tlog.HashSize
		if len(data) != expected {
			return nil, fmt.Errorf("tile %s has wrong size %d, want %d", path, len(data), expected)
		}
		out[i] = data
	}
	return out, nil
}

func (ts *tileStorage) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	for i, tile := range tiles {
		path := tilePath(tile)
		_ = ts.store.Put(context.Background(), storage.Object{
			Path:        path,
			Data:        data[i],
			ContentType: "application/octet-stream",
			Immutable:   true,
		})
	}
}

func tilePath(tile tlog.Tile) string {
	return fmt.Sprintf("v1/tile/%d/%d/%d/%d", tile.H, tile.L, tile.N, tile.W)
}

// WriteTiles writes all stored hash tiles for the tree to store.
func WriteTiles(t *Tree, store storage.Store, height int) error {
	if height <= 0 {
		height = DefaultTileHeight
	}
	// Group stored hashes by tile.
	byTile := map[tlog.Tile][]tlog.Hash{}
	for idx, h := range t.stored {
		level, n := tlog.SplitStoredHashIndex(idx)
		tile := tlog.TileForIndex(height, tlog.StoredHashIndex(level, n))
		byTile[tile] = append(byTile[tile], h)
	}
	for tile, hashes := range byTile {
		if len(hashes) != tile.W {
			// This should not happen if tile.W matches the count of indexes in the tile.
			return fmt.Errorf("tile %v count mismatch %d vs %d", tile, len(hashes), tile.W)
		}
		data := make([]byte, 0, len(hashes)*tlog.HashSize)
		for _, h := range hashes {
			data = append(data, h[:]...)
		}
		if err := store.Put(context.Background(), storage.Object{
			Path:        tilePath(tile),
			Data:        data,
			ContentType: "application/octet-stream",
			Immutable:   true,
		}); err != nil {
			return err
		}
	}
	return nil
}

// WriteCheckpoint stores a signed note checkpoint to store.
func WriteCheckpoint(tree tlog.Tree, signer note.Signer, store storage.Store) error {
	text := string(tlog.FormatTree(tree))
	msg, err := note.Sign(&note.Note{Text: text}, signer)
	if err != nil {
		return err
	}
	return store.Put(context.Background(), storage.Object{
		Path:        storage.CheckpointPath(),
		Data:        msg,
		ContentType: "text/plain; charset=utf-8",
		CacheSeconds: 60,
	})
}

// ReadCheckpoint reads and verifies a signed checkpoint from store.
func ReadCheckpoint(store storage.Store, policy Policy) (tlog.Tree, []VerifiedSignature, error) {
	data, err := store.Get(context.Background(), storage.CheckpointPath())
	if err != nil {
		return tlog.Tree{}, nil, err
	}
	return VerifyCheckpoint(data, policy)
}

// VerifiedSignature records a signature that passed policy verification.
type VerifiedSignature struct {
	Name string
	KeyHash uint32
}

// Policy describes the trusted log key and required witnesses.
type Policy struct {
	LogName           string
	LogKeys           []string // verifier key strings
	WitnessKeys       []string // verifier key strings
	RequiredWitnesses int
}

// NewSigner creates a note signer from an Ed25519 private key and log name.
func NewSigner(name string, priv []byte) (note.Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size")
	}
	pub := priv.Public().(ed25519.PublicKey)
	h := sha256.Sum256(pub)
	keyHash := hex.EncodeToString(h[:8])
	key := "PRIVATE+KEY+" + name + "+" + keyHash + "+" + hex.EncodeToString(priv)
	return note.NewSigner(key)
}

// NewVerifier creates a note verifier from an Ed25519 public key and name.
func NewVerifier(name string, pub []byte) (note.Verifier, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size")
	}
	h := sha256.Sum256(pub)
	keyHash := hex.EncodeToString(h[:8])
	key := name + "+" + keyHash + "+" + hex.EncodeToString(pub)
	return note.NewVerifier(key)
}

// GenerateKeyPair generates a new log key pair.
func GenerateKeyPair(name string) (note.Signer, note.Verifier, string, string, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, "", "", err
	}
	signer, err := NewSigner(name, priv)
	if err != nil {
		return nil, nil, "", "", err
	}
	verifier, err := NewVerifier(name, priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, nil, "", "", err
	}
	return signer, verifier, signer.String(), verifier.String(), nil
}

// VerifyCheckpoint verifies a signed note checkpoint against a policy.
// prior, if non-empty, is checked for consistency (no rollback, matching prior root).
func VerifyCheckpoint(data []byte, policy Policy) (tlog.Tree, []VerifiedSignature, error) {
	verifiers, err := buildVerifiers(policy)
	if err != nil {
		return tlog.Tree{}, nil, err
	}
	n, err := note.Open(data, verifiers)
	if err != nil {
		return tlog.Tree{}, nil, fmt.Errorf("open checkpoint: %w", err)
	}
	if len(n.Sigs) == 0 {
		return tlog.Tree{}, nil, fmt.Errorf("no verified signatures")
	}
	var logSig bool
	var witnesses []VerifiedSignature
	for _, sig := range n.Sigs {
		v := VerifiedSignature{Name: sig.Name, KeyHash: sig.Hash}
		if isLogKey(policy, sig.Name, sig.Hash) {
			logSig = true
		} else {
			witnesses = append(witnesses, v)
		}
	}
	if !logSig {
		return tlog.Tree{}, nil, fmt.Errorf("missing verified log signature")
	}
	if len(witnesses) < policy.RequiredWitnesses {
		return tlog.Tree{}, nil, fmt.Errorf("witness quorum not met: %d < %d", len(witnesses), policy.RequiredWitnesses)
	}
	if !strings.Contains(n.Text, "\n") {
		return tlog.Tree{}, nil, fmt.Errorf("malformed checkpoint text")
	}
	tree, err := tlog.ParseTree([]byte(n.Text))
	if err != nil {
		return tlog.Tree{}, nil, fmt.Errorf("parse tree: %w", err)
	}
	return tree, witnesses, nil
}

// VerifyCheckpointConsistency verifies a new checkpoint against a prior checkpoint.
// It hard-fails if the new checkpoint is smaller or if the prior root is not consistent.
func VerifyCheckpointConsistency(new, prior tlog.Tree) error {
	if new.N < prior.N {
		return fmt.Errorf("checkpoint rollback: %d < %d", new.N, prior.N)
	}
	if new.N == prior.N && new.Hash != prior.Hash {
		return fmt.Errorf("checkpoint equivocation at size %d", new.N)
	}
	return nil
}

func buildVerifiers(policy Policy) (note.Verifiers, error) {
	var list []note.Verifier
	for _, key := range policy.LogKeys {
		v, err := note.NewVerifier(key)
		if err != nil {
			return nil, fmt.Errorf("log key: %w", err)
		}
		list = append(list, v)
	}
	for _, key := range policy.WitnessKeys {
		v, err := note.NewVerifier(key)
		if err != nil {
			return nil, fmt.Errorf("witness key: %w", err)
		}
		list = append(list, v)
	}
	return note.VerifierList(list...), nil
}

func isLogKey(policy Policy, name string, hash uint32) bool {
	for _, key := range policy.LogKeys {
		v, err := note.NewVerifier(key)
		if err != nil {
			continue
		}
		if v.Name() == name && v.KeyHash() == hash {
			return true
		}
	}
	return false
}

// VerifyInclusion verifies that a record is included in a checkpoint, using tile storage.
func VerifyInclusion(store storage.Store, leaf Leaf, tree tlog.Tree, policy Policy) error {
	if tree.N == 0 {
		return fmt.Errorf("empty tree cannot contain records")
	}
	lh, err := LeafHash(leaf)
	if err != nil {
		return err
	}
	// Find leaf index by linear scan of stored records. For large logs this should be
	// replaced by an index.
	records, err := listRecords(store)
	if err != nil {
		return err
	}
	var index int64 = -1
	for i, r := range records {
		rh, err := LeafHash(r)
		if err != nil {
			return err
		}
		if rh == lh {
			index = int64(i)
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("record not found in log")
	}
	tr := NewTileReader(store, DefaultTileHeight)
	hr := tlog.TileHashReader(tree, tr)
	proof, err := tlog.ProveRecord(tree.N, index, hr)
	if err != nil {
		return err
	}
	return tlog.CheckRecord(proof, tree.N, tree.Hash, index, lh)
}

// listRecords reads record blobs from storage and returns their leaves.
// This is a simple implementation; a production server should keep an index.
func listRecords(store storage.Store) ([]Leaf, error) {
	keys, err := store.List(context.Background(), "v1/blob")
	if err != nil {
		return nil, err
	}
	var records []Leaf
	for _, key := range keys {
		data, err := store.Get(context.Background(), key)
		if err != nil {
			return nil, err
		}
		rec, err := parseBlob(data)
		if err != nil {
			continue
		}
		records = append(records, rec)
	}
	// Sort by record ID for deterministic ordering.
	sort.Slice(records, func(i, j int) bool { return records[i].RecordID < records[j].RecordID })
	return records, nil
}

// parseBlob expects data in the form "record_id\nauditor_id\nsignature".
func parseBlob(data []byte) (Leaf, error) {
	parts := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(parts) != 3 {
		return Leaf{}, fmt.Errorf("invalid blob format")
	}
	return Leaf{RecordID: parts[0], AuditorID: parts[1], Signature: parts[2]}, nil
}

// WriteBlob stores a record leaf blob at v1/blob/<recordID>.
func WriteBlob(store storage.Store, leaf Leaf) error {
	data := []byte(leaf.RecordID + "\n" + leaf.AuditorID + "\n" + leaf.Signature)
	return store.Put(context.Background(), storage.Object{
		Path:        storage.BlobPath(leaf.RecordID),
		Data:        data,
		ContentType: "text/plain; charset=utf-8",
		Immutable:   true,
	})
}

// CheckpointBytes returns the raw signed checkpoint bytes for a tree.
func CheckpointBytes(tree tlog.Tree, signer note.Signer) ([]byte, error) {
	text := string(tlog.FormatTree(tree))
	return note.Sign(&note.Note{Text: text}, signer)
}

// ParseTree wraps tlog.ParseTree.
func ParseTree(text []byte) (tlog.Tree, error) {
	return tlog.ParseTree(text)
}

// HexHash returns the hex string of a tlog.Hash.
func HexHash(h tlog.Hash) string {
	return hex.EncodeToString(h[:])
}

