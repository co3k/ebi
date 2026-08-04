// Package tlogx implements a transparency log for ebi using golang.org/x/mod/sumdb/tlog
// and the note signing format. It supports Merkle append, inclusion/consistency
// verification, tile-compatible storage, and k-of-N witness policies.
package tlogx

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/co3k/ebi/pkg/schema"
	"github.com/co3k/ebi/pkg/storage"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// DefaultTileHeight is the tile height used for tile storage.
const DefaultTileHeight = 8

// hash lengths for leaf payloads.
const (
	recordHashSize      = 32
	auditorHashSize     = 32
	recordSignatureSize = 64

	cosignatureEd25519 = byte(0x04)
)

// Leaf is the input to a single log leaf hash.
// The leaf hash is the SHA-256 of the raw concatenation of the 32-byte record
// ID, 32-byte auditor key hash, and 64-byte Ed25519 record signature. All three
// fields are represented as lower-case hex strings.
// The optional Hash field is a precomputed base64 leaf hash used for tombstone
// records whose original record blob has been replaced.
type Leaf struct {
	RecordID  string
	AuditorID string
	Signature string
	Hash      string
}

// LeafHash returns the tlog leaf hash for the record.
// It hashes the concatenation of the decoded fields:
//
//	SHA-256(recordID || auditorID || signature)
//
// Each decoded field must have exactly the canonical length: 32 bytes for the
// record ID and auditor key hash, 64 bytes for the Ed25519 record signature.
// If the optional Hash field is set, it is decoded and returned directly.
func LeafHash(l Leaf) (tlog.Hash, error) {
	if l.Hash != "" {
		b, err := base64.StdEncoding.DecodeString(l.Hash)
		if err != nil || len(b) != tlog.HashSize {
			return tlog.Hash{}, fmt.Errorf("invalid leaf hash")
		}
		var h tlog.Hash
		copy(h[:], b)
		return h, nil
	}
	if l.RecordID == "" || l.AuditorID == "" || l.Signature == "" {
		return tlog.Hash{}, fmt.Errorf("leaf fields are required")
	}
	rec, err := hex.DecodeString(l.RecordID)
	if err != nil {
		return tlog.Hash{}, fmt.Errorf("decode record id: %w", err)
	}
	if len(rec) != recordHashSize {
		return tlog.Hash{}, fmt.Errorf("record id must be %d bytes, got %d", recordHashSize, len(rec))
	}
	aud, err := hex.DecodeString(l.AuditorID)
	if err != nil {
		return tlog.Hash{}, fmt.Errorf("decode auditor id: %w", err)
	}
	if len(aud) != auditorHashSize {
		return tlog.Hash{}, fmt.Errorf("auditor id must be %d bytes, got %d", auditorHashSize, len(aud))
	}
	sig, err := hex.DecodeString(l.Signature)
	if err != nil {
		return tlog.Hash{}, fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != recordSignatureSize {
		return tlog.Hash{}, fmt.Errorf("signature must be %d bytes, got %d", recordSignatureSize, len(sig))
	}
	buf := make([]byte, 0, recordHashSize+auditorHashSize+recordSignatureSize)
	buf = append(buf, rec...)
	buf = append(buf, aud...)
	buf = append(buf, sig...)
	h := sha256.Sum256(buf)
	return tlog.Hash(h), nil
}

// Tree is a memory-only transparency tree. It is not safe for concurrent use.
// The tree is represented using the append-only stored hash slice from
// tlog.StoredHashesForRecordHash, so appends always produce a consistent root.
type Tree struct {
	leaves []tlog.Hash
	stored []tlog.Hash
	size   int64
	root   tlog.Hash
}

// NewTree creates an empty tree.
func NewTree() *Tree {
	emptyRoot, _ := tlog.TreeHash(0, tlog.HashReaderFunc(func([]int64) ([]tlog.Hash, error) { return nil, nil }))
	return &Tree{root: emptyRoot}
}

// NewTreeFromLeaves builds a consistent tree from the given leaves in order.
func NewTreeFromLeaves(leaves []Leaf) (*Tree, error) {
	t := NewTree()
	for _, l := range leaves {
		if _, err := t.AppendLeaf(l); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// LoadTree is an alias for NewTreeFromLeaves; it rebuilds a tree from a set
// of leaves while preserving the original append order.
func LoadTree(leaves []Leaf) (*Tree, error) {
	return NewTreeFromLeaves(leaves)
}

// Size returns the current tree size.
func (t *Tree) Size() int64 { return t.size }

// Root returns the current tree root hash.
func (t *Tree) Root() tlog.Hash { return t.root }

// TlogTree returns the tlog.Tree description for the current tree.
func (t *Tree) TlogTree() tlog.Tree { return tlog.Tree{N: t.size, Hash: t.root} }

// Leaves returns a defensive copy of the leaf hashes in append order.
func (t *Tree) Leaves() []tlog.Hash {
	out := make([]tlog.Hash, len(t.leaves))
	copy(out, t.leaves)
	return out
}

// Append adds a new leaf hash to the tree and recomputes the root.
// The root is always recomputed from the stored hash slice so an inconsistent
// root cannot be produced.
func (t *Tree) Append(leaf tlog.Hash) error {
	hashes, err := tlog.StoredHashesForRecordHash(t.size, leaf, t.storedHashReader())
	if err != nil {
		return err
	}
	t.leaves = append(t.leaves, leaf)
	t.stored = append(t.stored, hashes...)
	t.size++
	t.recompute()
	return nil
}

// AppendLeaf adds a leaf derived from a record and returns its index.
func (t *Tree) AppendLeaf(l Leaf) (int64, error) {
	lh, err := LeafHash(l)
	if err != nil {
		return 0, err
	}
	idx := t.Size()
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
		if err := t.Append(lh); err != nil {
			return 0, err
		}
	}
	return t.Size(), nil
}

func (t *Tree) recompute() {
	root, err := tlog.TreeHash(t.size, t.storedHashReader())
	if err != nil {
		// This should not happen with valid stored hashes.
		root = tlog.Hash{}
	}
	t.root = root
}

func (t *Tree) storedHashReader() tlog.HashReader {
	return tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			if idx < 0 || idx >= int64(len(t.stored)) {
				return nil, fmt.Errorf("stored hash index %d out of range [0,%d)", idx, len(t.stored))
			}
			out[i] = t.stored[idx]
		}
		return out, nil
	})
}

// HashReader returns a HashReader backed by the tree's stored hashes.
func (t *Tree) HashReader() tlog.HashReader {
	return t.storedHashReader()
}

// RecordProof returns an inclusion proof for leaf at index n.
func (t *Tree) RecordProof(n int64) (tlog.RecordProof, error) {
	if n < 0 || n >= t.Size() {
		return nil, fmt.Errorf("leaf index %d out of range [0,%d)", n, t.Size())
	}
	return tlog.ProveRecord(t.Size(), n, t.HashReader())
}

// TreeProof returns a consistency proof against an older tree size.
func (t *Tree) TreeProof(oldSize int64) (tlog.TreeProof, error) {
	if oldSize < 1 || oldSize > t.Size() {
		return nil, fmt.Errorf("old size %d out of range [1,%d]", oldSize, t.Size())
	}
	return tlog.ProveTree(t.Size(), oldSize, t.HashReader())
}

// VerifyRecord checks an inclusion proof for leaf n against tree.
func VerifyRecord(tree tlog.Tree, n int64, leaf tlog.Hash, proof tlog.RecordProof) error {
	return tlog.CheckRecord(proof, tree.N, tree.Hash, n, leaf)
}

// VerifyConsistency checks a consistency proof between old and new trees.
func VerifyConsistency(new, old tlog.Tree, proof tlog.TreeProof) error {
	return tlog.CheckTree(proof, new.N, new.Hash, old.N, old.Hash)
}

// tileStorage is a tlog.TileReader that reads from a storage.Store.
type tileStorage struct {
	store  storage.Store
	height int
	err    error
}

// NewTileReader returns a TileReader that reads tile data from store.
func NewTileReader(store storage.Store, height int) *tileStorage {
	if height <= 0 {
		height = DefaultTileHeight
	}
	return &tileStorage{store: store, height: height}
}

func (ts *tileStorage) Height() int { return ts.height }

func (ts *tileStorage) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, tile := range tiles {
		path := TilePath(tile)
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

// SaveTiles implements tlog.TileReader. Errors are stored and surfaced via Err.
func (ts *tileStorage) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	if ts.err != nil {
		return
	}
	if len(tiles) != len(data) {
		ts.err = fmt.Errorf("tile/data count mismatch")
		return
	}
	for i, tile := range tiles {
		path := TilePath(tile)
		if err := ts.store.Put(context.Background(), storage.Object{
			Path:        path,
			Data:        data[i],
			ContentType: "application/octet-stream",
			Immutable:   true,
		}); err != nil {
			ts.err = fmt.Errorf("save tile %s: %w", path, err)
			return
		}
	}
}

// Err returns the first error encountered during tile writes.
func (ts *tileStorage) Err() error { return ts.err }

// TilePath returns a C2SP-compatible tile storage path.
// The path is "v1/" followed by tlog.Tile.Path(), e.g.
// v1/tile/8/0/000.p/3 for a partial tile or v1/tile/8/0/000 for a complete tile.
func TilePath(tile tlog.Tile) string {
	return "v1/" + tile.Path()
}

// WriteTiles writes all stored hash tiles for the tree to store.
func WriteTiles(t *Tree, store storage.Store, height int) error {
	if height <= 0 {
		height = DefaultTileHeight
	}
	if t.Size() == 0 {
		return nil
	}
	tiles := tlog.NewTiles(height, 0, t.Size())
	tr := NewTileReader(store, height)
	for _, tile := range tiles {
		data, err := tlog.ReadTileData(tile, t.HashReader())
		if err != nil {
			return fmt.Errorf("read tile data %s: %w", TilePath(tile), err)
		}
		tr.SaveTiles([]tlog.Tile{tile}, [][]byte{data})
		if err := tr.Err(); err != nil {
			return err
		}
	}
	return nil
}

// WriteCheckpoint stores a signed note checkpoint to store.
func WriteCheckpoint(tree tlog.Tree, origin string, signer note.Signer, store storage.Store) error {
	text := string(FormatCheckpoint(tree, origin))
	msg, err := note.Sign(&note.Note{Text: text}, signer)
	if err != nil {
		return err
	}
	return store.Put(context.Background(), storage.Object{
		Path:         storage.CheckpointPath(),
		Data:         msg,
		ContentType:  "text/plain; charset=utf-8",
		CacheSeconds: 60,
	})
}

// FormatCheckpoint formats the C2SP checkpoint text for a tree.
// The body is exactly: origin line, decimal size, base64 root hash, and a
// trailing newline.
func FormatCheckpoint(tree tlog.Tree, origin string) []byte {
	return []byte(origin + "\n" + fmt.Sprintf("%d\n%s\n", tree.N, tree.Hash))
}

// ParseCheckpoint parses C2SP checkpoint note text (or a complete signed note)
// and returns the tree and origin. Tree sizes and hashes must use their
// canonical decimal and RFC 4648 base64 encodings.
func ParseCheckpoint(text []byte) (tlog.Tree, string, error) {
	body := string(text)
	// Accept a complete signed note by stripping its blank-line signature
	// section. The note body itself may contain non-empty extension lines.
	if idx := strings.Index(body, "\n\n— "); idx >= 0 {
		body = body[:idx+1]
	}
	if !strings.HasSuffix(body, "\n") {
		return tlog.Tree{}, "", fmt.Errorf("checkpoint text must end in newline")
	}
	body = strings.TrimSuffix(body, "\n")
	lines := strings.Split(body, "\n")
	if len(lines) < 3 {
		return tlog.Tree{}, "", fmt.Errorf("checkpoint text too short")
	}
	origin := lines[0]
	if origin == "" {
		return tlog.Tree{}, "", fmt.Errorf("checkpoint origin is empty")
	}
	for i, extension := range lines[3:] {
		if extension == "" {
			return tlog.Tree{}, "", fmt.Errorf("checkpoint extension line %d is empty", i+4)
		}
	}
	size, err := parseInt64(lines[1])
	if err != nil {
		return tlog.Tree{}, "", fmt.Errorf("parse checkpoint size: %w", err)
	}
	hash, err := parseHash(lines[2])
	if err != nil {
		return tlog.Tree{}, "", fmt.Errorf("parse checkpoint hash: %w", err)
	}
	return tlog.Tree{N: size, Hash: hash}, origin, nil
}

func parseInt64(s string) (int64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') || strings.HasPrefix(s, "+") {
		return 0, fmt.Errorf("non-canonical decimal %q", s)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("negative size")
	}
	return n, nil
}

func parseHash(s string) (tlog.Hash, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == tlog.HashSize {
		if base64.StdEncoding.EncodeToString(b) != s {
			return tlog.Hash{}, fmt.Errorf("non-canonical base64 hash")
		}
		var h tlog.Hash
		copy(h[:], b)
		return h, nil
	}
	return tlog.Hash{}, fmt.Errorf("invalid hash encoding or length")
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
	Name    string
	KeyHash uint32
}

// Policy describes the trusted log key and required witnesses.
type Policy struct {
	LogName           string
	LogKeys           []string // verifier key strings
	WitnessKeys       []string // verifier key strings
	RequiredWitnesses int
}

// GenerateKeyPair generates a new log key pair using note.GenerateKey.
func GenerateKeyPair(name string) (note.Signer, note.Verifier, string, string, error) {
	signerKey, verifierKey, err := note.GenerateKey(nil, name)
	if err != nil {
		return nil, nil, "", "", err
	}
	signer, err := note.NewSigner(signerKey)
	if err != nil {
		return nil, nil, "", "", err
	}
	verifier, err := note.NewVerifier(verifierKey)
	if err != nil {
		return nil, nil, "", "", err
	}
	return signer, verifier, signerKey, verifierKey, nil
}

// VerifyCheckpoint verifies a signed note checkpoint against a policy.
// It returns the verified tree and the list of verified witness signatures.
// Duplicate keys are not counted toward quorum, and unknown signatures are
// ignored by note's verifier semantics.
func VerifyCheckpoint(data []byte, policy Policy) (tlog.Tree, []VerifiedSignature, error) {
	if err := validatePolicy(policy); err != nil {
		return tlog.Tree{}, nil, err
	}
	if len(policy.LogKeys) == 0 {
		return tlog.Tree{}, nil, fmt.Errorf("at least one trusted log key is required")
	}
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
	logSeen := map[string]struct{}{}
	witnessSeen := map[string]struct{}{}
	var witnesses []VerifiedSignature
	for _, sig := range n.Sigs {
		key := sig.Name + "\x00" + fmt.Sprintf("%08x", sig.Hash)
		if isLogKey(policy, sig.Name, sig.Hash) {
			logSeen[key] = struct{}{}
		} else {
			if _, ok := witnessSeen[key]; ok {
				continue
			}
			witnessSeen[key] = struct{}{}
			witnesses = append(witnesses, VerifiedSignature{Name: sig.Name, KeyHash: sig.Hash})
		}
	}
	if len(logSeen) == 0 {
		return tlog.Tree{}, nil, fmt.Errorf("missing verified log signature")
	}
	if len(witnesses) < policy.RequiredWitnesses {
		return tlog.Tree{}, nil, fmt.Errorf("witness quorum not met: %d < %d", len(witnesses), policy.RequiredWitnesses)
	}
	if !strings.Contains(n.Text, "\n") {
		return tlog.Tree{}, nil, fmt.Errorf("malformed checkpoint text")
	}
	tree, origin, err := ParseCheckpoint([]byte(n.Text))
	if err != nil {
		return tlog.Tree{}, nil, fmt.Errorf("parse checkpoint: %w", err)
	}
	if origin != policy.LogName {
		return tlog.Tree{}, nil, fmt.Errorf("checkpoint origin mismatch: got %q, want %q", origin, policy.LogName)
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

func validatePolicy(p Policy) error {
	if strings.TrimSpace(p.LogName) == "" {
		return fmt.Errorf("log origin is required")
	}
	if p.RequiredWitnesses < 0 {
		return fmt.Errorf("required witnesses cannot be negative")
	}
	logSet := map[string]struct{}{}
	for _, k := range p.LogKeys {
		if _, err := note.NewVerifier(k); err != nil {
			return fmt.Errorf("invalid log key: %w", err)
		}
		if _, ok := logSet[k]; ok {
			return fmt.Errorf("duplicate log key")
		}
		logSet[k] = struct{}{}
	}
	witnessSet := map[string]struct{}{}
	for _, k := range p.WitnessKeys {
		if _, err := newWitnessVerifier(k); err != nil {
			return fmt.Errorf("invalid witness key: %w", err)
		}
		if _, ok := witnessSet[k]; ok {
			return fmt.Errorf("duplicate witness key")
		}
		witnessSet[k] = struct{}{}
	}
	for k := range logSet {
		if _, ok := witnessSet[k]; ok {
			return fmt.Errorf("log key %q also listed as witness key", k)
		}
	}
	if p.RequiredWitnesses > len(witnessSet) {
		return fmt.Errorf("required witnesses %d exceeds available %d", p.RequiredWitnesses, len(witnessSet))
	}
	return nil
}

func buildVerifiers(policy Policy) (note.Verifiers, error) {
	seen := map[string]struct{}{}
	var list []note.Verifier
	for _, key := range policy.LogKeys {
		v, err := note.NewVerifier(key)
		if err != nil {
			return nil, fmt.Errorf("log key: %w", err)
		}
		key := v.Name() + "\x00" + fmt.Sprintf("%08x", v.KeyHash())
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		list = append(list, v)
	}
	for _, key := range policy.WitnessKeys {
		v, err := newWitnessVerifier(key)
		if err != nil {
			return nil, fmt.Errorf("witness key: %w", err)
		}
		key := v.Name() + "\x00" + fmt.Sprintf("%08x", v.KeyHash())
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		list = append(list, v)
	}
	return note.VerifierList(list...), nil
}

// newWitnessVerifier accepts C2SP tlog-cosignature Ed25519 vkeys (algorithm
// byte 0x04) and legacy Go-note Ed25519 verifier keys for backward-compatible
// local deployments. Production policies should use timestamped C2SP keys.
func newWitnessVerifier(key string) (note.Verifier, error) {
	if verifier, err := note.NewVerifier(key); err == nil {
		return verifier, nil
	}

	name, rest, ok := strings.Cut(key, "+")
	if !ok || name == "" {
		return nil, fmt.Errorf("malformed C2SP witness key")
	}
	hashHex, key64, ok := strings.Cut(rest, "+")
	if !ok || len(hashHex) != 8 || key64 == "" {
		return nil, fmt.Errorf("malformed C2SP witness key")
	}
	hashValue, err := strconv.ParseUint(hashHex, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("malformed C2SP witness key hash")
	}
	encoded, err := base64.StdEncoding.DecodeString(key64)
	if err != nil || base64.StdEncoding.EncodeToString(encoded) != key64 ||
		len(encoded) != 1+ed25519.PublicKeySize || encoded[0] != cosignatureEd25519 {
		return nil, fmt.Errorf("unsupported C2SP witness key")
	}
	expectedHash := namedKeyHash(name, encoded)
	if uint32(hashValue) != expectedHash {
		return nil, fmt.Errorf("C2SP witness key hash mismatch")
	}
	publicKey := append(ed25519.PublicKey(nil), encoded[1:]...)
	return &c2spWitnessVerifier{
		name: name,
		hash: expectedHash,
		key:  publicKey,
	}, nil
}

type c2spWitnessVerifier struct {
	name string
	hash uint32
	key  ed25519.PublicKey
}

func (v *c2spWitnessVerifier) Name() string    { return v.name }
func (v *c2spWitnessVerifier) KeyHash() uint32 { return v.hash }
func (v *c2spWitnessVerifier) Verify(checkpointBody, signature []byte) bool {
	if len(signature) != 8+ed25519.SignatureSize {
		return false
	}
	timestamp := binary.BigEndian.Uint64(signature[:8])
	if timestamp > uint64(^uint64(0)>>1) {
		return false
	}
	message := make([]byte, 0, len(checkpointBody)+64)
	message = append(message, "cosignature/v1\ntime "...)
	message = strconv.AppendUint(message, timestamp, 10)
	message = append(message, '\n')
	message = append(message, checkpointBody...)
	return ed25519.Verify(v.key, message, signature[8:])
}

func namedKeyHash(name string, encodedPublicKey []byte) uint32 {
	h := sha256.New()
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte("\n"))
	_, _ = h.Write(encodedPublicKey)
	return binary.BigEndian.Uint32(h.Sum(nil)[:4])
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

// LeafIndex is the stored append-order index for a record. Leaf is the
// base64-encoded Merkle leaf hash, not the record-body hash.
type LeafIndex struct {
	Index    int64  `json:"index"`
	Leaf     string `json:"leaf"`      // base64-encoded leaf hash
	RecordID string `json:"record_id"` // hex SHA-256 record ID
}

// leafIndexPath returns the storage path for an append-order index entry.
func leafIndexPath(index int64) string {
	return fmt.Sprintf("v1/leaf/%d", index)
}

// WriteBlob stores a verified record envelope blob at v1/blob/<recordID>.
// The record ID is the SHA-256 of the canonical body, so the path is a
// content-addressable sha256 reference. The returned string is the record ID.
func WriteBlob(store storage.Store, rec schema.Record) (string, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	body, _, err := schema.Verify(&rec)
	if err != nil {
		return "", err
	}
	id, err := schema.RecordID(*body)
	if err != nil {
		return "", err
	}
	path := "v1/blob/" + id
	if existing, err := store.Get(context.Background(), path); err == nil {
		if !bytes.Equal(existing, data) {
			return "", fmt.Errorf("blob %s already exists with different content", id)
		}
		return id, nil
	} else if !storage.IsNotFound(err) {
		return "", err
	}
	if err := store.Put(context.Background(), storage.Object{
		Path:        path,
		Data:        data,
		ContentType: "application/json",
		Immutable:   true,
	}); err != nil {
		return "", err
	}
	return id, nil
}

// WriteLeafIndex stores the append-order index object for a record.
func WriteLeafIndex(store storage.Store, index int64, leaf tlog.Hash, recordID string) error {
	idx := LeafIndex{
		Index:    index,
		Leaf:     base64.StdEncoding.EncodeToString(leaf[:]),
		RecordID: recordID,
	}
	data, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	path := leafIndexPath(index)
	if existing, err := store.Get(context.Background(), path); err == nil {
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("leaf index %d already exists with different content", index)
		}
		return nil
	} else if !storage.IsNotFound(err) {
		return err
	}
	return store.Put(context.Background(), storage.Object{
		Path:        path,
		Data:        data,
		ContentType: "application/json",
		Immutable:   true,
	})
}

// WriteRecord writes both the record blob and its append-order index entry.
func WriteRecord(store storage.Store, index int64, rec schema.Record) error {
	leaf, err := RecordToLeaf(rec)
	if err != nil {
		return err
	}
	lh, err := LeafHash(leaf)
	if err != nil {
		return err
	}
	id, err := WriteBlob(store, rec)
	if err != nil {
		return err
	}
	return WriteLeafIndex(store, index, lh, id)
}

// DecodeLeafIndex strictly decodes a v1/leaf/<index> object. The decimal path
// suffix must be canonical and must agree with the JSON index field.
func DecodeLeafIndex(path string, data []byte) (LeafIndex, tlog.Hash, error) {
	const prefix = "v1/leaf/"
	if !strings.HasPrefix(path, prefix) {
		return LeafIndex{}, tlog.Hash{}, fmt.Errorf("invalid leaf index path %q", path)
	}
	suffix := strings.TrimPrefix(path, prefix)
	if suffix == "" || strings.Contains(suffix, "/") {
		return LeafIndex{}, tlog.Hash{}, fmt.Errorf("invalid leaf index path %q", path)
	}
	pathIndex, err := strconv.ParseInt(suffix, 10, 64)
	if err != nil || pathIndex < 0 || strconv.FormatInt(pathIndex, 10) != suffix {
		return LeafIndex{}, tlog.Hash{}, fmt.Errorf("invalid leaf index path %q", path)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var idx LeafIndex
	if err := dec.Decode(&idx); err != nil {
		return LeafIndex{}, tlog.Hash{}, fmt.Errorf("decode %s: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return LeafIndex{}, tlog.Hash{}, fmt.Errorf("decode %s: trailing data", path)
		}
		return LeafIndex{}, tlog.Hash{}, fmt.Errorf("decode %s: trailing data: %w", path, err)
	}
	if idx.Index != pathIndex {
		return LeafIndex{}, tlog.Hash{}, fmt.Errorf("leaf path index %d does not match document index %d", pathIndex, idx.Index)
	}
	if !schema.IsHexHash(idx.RecordID) {
		return LeafIndex{}, tlog.Hash{}, fmt.Errorf("leaf index %d has invalid record_id", idx.Index)
	}
	raw, err := base64.StdEncoding.DecodeString(idx.Leaf)
	if err != nil || len(raw) != tlog.HashSize || base64.StdEncoding.EncodeToString(raw) != idx.Leaf {
		return LeafIndex{}, tlog.Hash{}, fmt.Errorf("leaf index %d has invalid leaf hash", idx.Index)
	}
	var hash tlog.Hash
	copy(hash[:], raw)
	return idx, hash, nil
}

// LoadLeafIndexes reads all append-order index objects and requires a single
// contiguous sequence beginning at zero.
func LoadLeafIndexes(ctx context.Context, store storage.Store) ([]LeafIndex, error) {
	keys, err := store.List(ctx, "v1/leaf")
	if err != nil {
		return nil, err
	}
	byIndex := make(map[int64]LeafIndex, len(keys))
	recordIDs := make(map[string]int64, len(keys))
	for _, key := range keys {
		data, err := store.Get(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", key, err)
		}
		idx, _, err := DecodeLeafIndex(key, data)
		if err != nil {
			return nil, err
		}
		if _, ok := byIndex[idx.Index]; ok {
			return nil, fmt.Errorf("duplicate leaf index %d", idx.Index)
		}
		if prior, ok := recordIDs[idx.RecordID]; ok {
			return nil, fmt.Errorf("record %s appears at leaf indexes %d and %d", idx.RecordID, prior, idx.Index)
		}
		byIndex[idx.Index] = idx
		recordIDs[idx.RecordID] = idx.Index
	}
	out := make([]LeafIndex, len(byIndex))
	for i := range out {
		idx, ok := byIndex[int64(i)]
		if !ok {
			return nil, fmt.Errorf("missing leaf index %d", i)
		}
		out[i] = idx
	}
	return out, nil
}

// LeafIndexHash decodes and validates the leaf hash stored in idx.
func LeafIndexHash(idx LeafIndex) (tlog.Hash, error) {
	raw, err := base64.StdEncoding.DecodeString(idx.Leaf)
	if err != nil || len(raw) != tlog.HashSize || base64.StdEncoding.EncodeToString(raw) != idx.Leaf {
		return tlog.Hash{}, fmt.Errorf("leaf index %d has invalid leaf hash", idx.Index)
	}
	var hash tlog.Hash
	copy(hash[:], raw)
	return hash, nil
}

// Tombstone is the strict replacement document stored at the original record
// blob path after a privacy deletion. The original Merkle leaf remains in the
// append-only log and is authenticated through its LeafIndex hash.
type Tombstone struct {
	Tombstone bool   `json:"tombstone"`
	RecordID  string `json:"record_id"`
	Reason    string `json:"reason"`
	Message   string `json:"message"`
	DeletedAt string `json:"deleted_at"`
}

// DecodeTombstoneBlob returns (nil, false, nil) when data is not a tombstone
// document. If the tombstone field is present, the complete document is
// strictly decoded and validated.
func DecodeTombstoneBlob(data []byte, expectedRecordID string) (*Tombstone, bool, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, false, nil
	}
	if _, ok := probe["tombstone"]; !ok {
		return nil, false, nil
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var tomb Tombstone
	if err := dec.Decode(&tomb); err != nil {
		return nil, true, fmt.Errorf("decode tombstone: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, true, fmt.Errorf("decode tombstone: trailing data")
		}
		return nil, true, fmt.Errorf("decode tombstone: trailing data: %w", err)
	}
	if !tomb.Tombstone {
		return nil, true, fmt.Errorf("tombstone marker must be true")
	}
	if !schema.IsHexHash(tomb.RecordID) {
		return nil, true, fmt.Errorf("tombstone record_id is invalid")
	}
	if expectedRecordID != "" && tomb.RecordID != expectedRecordID {
		return nil, true, fmt.Errorf("tombstone record_id %s does not match blob path %s", tomb.RecordID, expectedRecordID)
	}
	if strings.TrimSpace(tomb.Reason) == "" {
		return nil, true, fmt.Errorf("tombstone reason is required")
	}
	if strings.TrimSpace(tomb.Message) == "" {
		return nil, true, fmt.Errorf("tombstone message is required")
	}
	if _, err := time.Parse(time.RFC3339, tomb.DeletedAt); err != nil {
		return nil, true, fmt.Errorf("tombstone deleted_at is invalid: %w", err)
	}
	return &tomb, true, nil
}

// TombstoneSHA256 returns the hash used by moderation/v1 to bind an exact
// tombstone blob.
func TombstoneSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// LoadLeavesFromIndex reconstructs the leaves in append order from the stored
// leaf index objects. It verifies each leaf hash against the corresponding blob
// and returns an error if any leaf is missing or inconsistent.
func LoadLeavesFromIndex(store storage.Store) ([]Leaf, error) {
	idxs, err := LoadLeafIndexes(context.Background(), store)
	if err != nil {
		return nil, err
	}
	leaves := make([]Leaf, len(idxs))
	for i, idx := range idxs {
		blob, err := store.Get(context.Background(), "v1/blob/"+idx.RecordID)
		if err != nil {
			return nil, fmt.Errorf("read blob %s: %w", idx.RecordID, err)
		}
		if _, isTombstone, err := DecodeTombstoneBlob(blob, idx.RecordID); err != nil {
			return nil, fmt.Errorf("blob %s: %w", idx.RecordID, err)
		} else if isTombstone {
			// The original signed envelope was deliberately deleted. The stored
			// append-order leaf hash remains authoritative; monitor/snapshot
			// verification additionally requires a later moderation binding.
			leaves[i] = Leaf{RecordID: idx.RecordID, Hash: idx.Leaf}
			continue
		}
		leaf, err := parseBlob(blob)
		if err != nil {
			return nil, fmt.Errorf("blob %s: %w", idx.RecordID, err)
		}
		lh, err := LeafHash(leaf)
		if err != nil {
			return nil, err
		}
		want, err := base64.StdEncoding.DecodeString(idx.Leaf)
		if err != nil || len(want) != tlog.HashSize {
			return nil, fmt.Errorf("leaf index %d: bad leaf encoding", idx.Index)
		}
		var wantHash tlog.Hash
		copy(wantHash[:], want)
		if lh != wantHash {
			return nil, fmt.Errorf("leaf index %d: leaf hash mismatch", idx.Index)
		}
		leaves[i] = leaf
	}
	return leaves, nil
}

// VerifyInclusionAt verifies an inclusion proof for a leaf at a given index using
// the tile storage and the supplied immutable tree. The caller must have already
// authenticated the tree against the policy; this function does not re-fetch the
// mutable v1/checkpoint. Bounds checks on the index are preserved.
func VerifyInclusionAt(store storage.Store, index int64, leaf tlog.Hash, tree tlog.Tree, policy Policy) error {
	if index < 0 || index >= tree.N {
		return fmt.Errorf("leaf index %d out of range [0,%d)", index, tree.N)
	}
	tr := NewTileReader(store, DefaultTileHeight)
	hr := tlog.TileHashReader(tree, tr)
	proof, err := tlog.ProveRecord(tree.N, index, hr)
	if err != nil {
		return err
	}
	return tlog.CheckRecord(proof, tree.N, tree.Hash, index, leaf)
}

// parseBlob parses a record blob (a signed schema.Record envelope).
func parseBlob(data []byte) (Leaf, error) {
	var rec schema.Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return Leaf{}, fmt.Errorf("unmarshal record blob: %w", err)
	}
	return RecordToLeaf(rec)
}

// CheckpointBytes returns the raw signed checkpoint bytes for a tree.
func CheckpointBytes(tree tlog.Tree, origin string, signer note.Signer) ([]byte, error) {
	text := string(FormatCheckpoint(tree, origin))
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

// Base64Hash returns the base64 string of a tlog.Hash.
func Base64Hash(h tlog.Hash) string {
	return base64.StdEncoding.EncodeToString(h[:])
}

// RecordToLeaf converts a verified record to a log leaf.
func RecordToLeaf(rec schema.Record) (Leaf, error) {
	body, auditorID, err := schema.Verify(&rec)
	if err != nil {
		return Leaf{}, err
	}
	id, err := schema.RecordID(*body)
	if err != nil {
		return Leaf{}, err
	}
	return Leaf{RecordID: id, AuditorID: auditorID, Signature: rec.Signature}, nil
}

// AddCheckpointRequest builds a C2SP witness /add-checkpoint POST request.
// The body is: old <oldSize>, base64 consistency proof lines, a blank line, and
// the signed checkpoint.
func AddCheckpointRequest(ctx context.Context, baseURL string, oldSize int64, proof tlog.TreeProof, signedCheckpoint []byte) (*http.Request, error) {
	if oldSize < 0 {
		return nil, fmt.Errorf("old size must be non-negative")
	}
	if len(proof) > 63 {
		return nil, fmt.Errorf("consistency proof has %d lines, maximum is 63", len(proof))
	}
	if oldSize == 0 && len(proof) != 0 {
		return nil, fmt.Errorf("consistency proof must be empty when old size is zero")
	}
	if len(signedCheckpoint) == 0 {
		return nil, fmt.Errorf("signed checkpoint is required")
	}
	checkpointTree, _, err := ParseCheckpoint(signedCheckpoint)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: %w", err)
	}
	if oldSize > checkpointTree.N {
		return nil, fmt.Errorf("old size %d exceeds checkpoint size %d", oldSize, checkpointTree.N)
	}
	u, err := url.Parse(strings.TrimSuffix(baseURL, "/") + "/add-checkpoint")
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("invalid witness submission URL")
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "old %d\n", oldSize)
	for _, h := range proof {
		buf.WriteString(h.String())
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n')
	buf.Write(signedCheckpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	return req, nil
}

// MergeWitnessSignature appends one witness signature line to a checkpoint
// note after proving that the line is well formed, belongs to a configured
// witness key, and cryptographically verifies over the checkpoint text.
func MergeWitnessSignature(signedCheckpoint, signatureLine []byte, witnessKeys []string) ([]byte, error) {
	if len(signatureLine) == 0 || signatureLine[len(signatureLine)-1] != '\n' {
		return nil, fmt.Errorf("witness signature line must end in newline")
	}
	line := strings.TrimSuffix(string(signatureLine), "\n")
	parts := strings.Split(line, " ")
	if len(parts) != 3 || parts[0] != "—" {
		return nil, fmt.Errorf("malformed witness signature line")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) < 5 || base64.StdEncoding.EncodeToString(raw) != parts[2] {
		return nil, fmt.Errorf("malformed witness signature encoding")
	}
	keyHash := binary.BigEndian.Uint32(raw[:4])
	var verifier note.Verifier
	for _, key := range witnessKeys {
		candidate, err := newWitnessVerifier(key)
		if err != nil {
			return nil, fmt.Errorf("witness key: %w", err)
		}
		if candidate.Name() == parts[1] && candidate.KeyHash() == keyHash {
			verifier = candidate
			break
		}
	}
	if verifier == nil {
		return nil, fmt.Errorf("signature is not from a configured witness")
	}

	allVerifiers, err := verifierListForSignedNote(signedCheckpoint, verifier)
	if err != nil {
		return nil, err
	}
	candidate := append(append([]byte(nil), signedCheckpoint...), signatureLine...)
	if _, err := note.Open(candidate, allVerifiers); err != nil {
		return nil, fmt.Errorf("verify witness signature: %w", err)
	}
	return candidate, nil
}

func verifierListForSignedNote(signedCheckpoint []byte, witness note.Verifier) (note.Verifiers, error) {
	// The existing log signatures may be unknown here. note.Open still parses
	// and retains them as UnverifiedSigs as long as the new witness verifies.
	return note.VerifierList(witness), nil
}

const maxWitnessResponse = 1 << 20 // 1 MiB

// ParseWitnessResponse parses a C2SP witness response.
// On 200 OK it returns complete signed-note signature lines and size 0.
// On 409 Conflict it returns the returned size and no signatures.
// Other status codes are errors.
func ParseWitnessResponse(resp *http.Response) ([][]byte, int64, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWitnessResponse+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > maxWitnessResponse {
		return nil, 0, fmt.Errorf("witness response exceeds %d bytes", maxWitnessResponse)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		if len(body) == 0 || body[len(body)-1] != '\n' {
			return nil, 0, fmt.Errorf("witness signature response must end in newline")
		}
		lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
		var sigs [][]byte
		for _, line := range lines {
			if line == "" {
				return nil, 0, fmt.Errorf("empty witness signature line")
			}
			parts := strings.Split(line, " ")
			if len(parts) != 3 || parts[0] != "—" || parts[1] == "" || parts[2] == "" {
				return nil, 0, fmt.Errorf("malformed witness signature line")
			}
			payload, err := base64.StdEncoding.DecodeString(parts[2])
			if err != nil || len(payload) < 5 || base64.StdEncoding.EncodeToString(payload) != parts[2] {
				return nil, 0, fmt.Errorf("decode witness signature: %w", err)
			}
			sigs = append(sigs, []byte(line+"\n"))
		}
		if len(sigs) == 0 {
			return nil, 0, fmt.Errorf("witness returned no signatures")
		}
		return sigs, 0, nil
	case http.StatusConflict:
		contentType := resp.Header.Get("Content-Type")
		if contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "text/x.tlog.size") {
			return nil, 0, fmt.Errorf("unexpected witness size content type %q", contentType)
		}
		size, err := parseWitnessSize(body)
		if err != nil {
			return nil, 0, err
		}
		return nil, size, nil
	default:
		return nil, 0, fmt.Errorf("witness response %d", resp.StatusCode)
	}
}

func parseWitnessSize(body []byte) (int64, error) {
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return 0, fmt.Errorf("witness size response must end in newline")
	}
	s := strings.TrimSuffix(string(body), "\n")
	if strings.ContainsRune(s, '\n') {
		return 0, fmt.Errorf("parse witness size: %q", s)
	}
	n, err := parseInt64(s)
	if err != nil {
		return 0, fmt.Errorf("parse witness size: %q: %w", s, err)
	}
	return n, nil
}

// policyDocument is the TOML serialization for a Policy.
type policyDocument struct {
	Origin            string   `toml:"origin"`
	LogKeys           []string `toml:"log_keys"`
	WitnessKeys       []string `toml:"witness_keys"`
	RequiredWitnesses int      `toml:"required_witnesses"`
}

// DefaultPolicy returns a placeholder policy with no real production keys.
// Operators must configure real log and witness keys before use.
func DefaultPolicy() Policy {
	return Policy{
		LogName:           "ebi.example.com",
		LogKeys:           []string{},
		WitnessKeys:       []string{},
		RequiredWitnesses: 0,
	}
}

// LoadPolicy reads a strict TOML policy from path.
func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	var doc policyDocument
	dec := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return Policy{}, fmt.Errorf("decode policy: %w", err)
	}
	p := Policy{
		LogName:           doc.Origin,
		LogKeys:           doc.LogKeys,
		WitnessKeys:       doc.WitnessKeys,
		RequiredWitnesses: doc.RequiredWitnesses,
	}
	if err := validatePolicy(p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// SavePolicy writes a strict TOML policy to path.
func SavePolicy(path string, p Policy) error {
	if err := validatePolicy(p); err != nil {
		return err
	}
	doc := policyDocument{
		Origin:            p.LogName,
		LogKeys:           p.LogKeys,
		WitnessKeys:       p.WitnessKeys,
		RequiredWitnesses: p.RequiredWitnesses,
	}
	data, err := toml.Marshal(&doc)
	if err != nil {
		return err
	}
	return writeFile(path, data, 0600)
}

// checkpointStateDocument is the TOML serialization for a checkpoint state file.
type checkpointStateDocument struct {
	Size       int64  `toml:"size"`
	Root       string `toml:"root"`
	Checkpoint string `toml:"checkpoint"`
}

// SaveCheckpointState atomically writes the checkpoint state file to path.
func SaveCheckpointState(path string, tree tlog.Tree, signed []byte) error {
	doc := checkpointStateDocument{
		Size:       tree.N,
		Root:       base64.StdEncoding.EncodeToString(tree.Hash[:]),
		Checkpoint: base64.StdEncoding.EncodeToString(signed),
	}
	data, err := toml.Marshal(&doc)
	if err != nil {
		return err
	}
	return writeFile(path, data, 0600)
}

// LoadCheckpointState reads the checkpoint state file at path.
func LoadCheckpointState(path string) (tlog.Tree, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tlog.Tree{}, nil, err
	}
	var doc checkpointStateDocument
	dec := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return tlog.Tree{}, nil, fmt.Errorf("decode checkpoint state: %w", err)
	}
	if doc.Size < 0 {
		return tlog.Tree{}, nil, fmt.Errorf("checkpoint state has negative size")
	}
	root, err := base64.StdEncoding.DecodeString(doc.Root)
	if err != nil || len(root) != tlog.HashSize {
		return tlog.Tree{}, nil, fmt.Errorf("checkpoint state has invalid root")
	}
	signed, err := base64.StdEncoding.DecodeString(doc.Checkpoint)
	if err != nil {
		return tlog.Tree{}, nil, fmt.Errorf("checkpoint state has invalid checkpoint")
	}
	var h tlog.Hash
	copy(h[:], root)
	return tlog.Tree{N: doc.Size, Hash: h}, signed, nil
}

// VerifyCheckpointState verifies a new checkpoint against a prior checkpoint,
// rejecting rollback and equivocation. When the new checkpoint grows, it loads a
// real consistency proof from the tile storage and verifies it with tlog.CheckTree.
func VerifyCheckpointState(newRaw []byte, priorTree tlog.Tree, policy Policy, store storage.Store) (tlog.Tree, []byte, error) {
	newTree, _, err := VerifyCheckpoint(newRaw, policy)
	if err != nil {
		return tlog.Tree{}, nil, err
	}
	if newTree.N < priorTree.N {
		return tlog.Tree{}, nil, fmt.Errorf("checkpoint rollback: %d < %d", newTree.N, priorTree.N)
	}
	if newTree.N == priorTree.N {
		if newTree.Hash == priorTree.Hash {
			return newTree, newRaw, nil
		}
		return tlog.Tree{}, nil, fmt.Errorf("checkpoint equivocation at size %d", newTree.N)
	}
	// Growing checkpoint: verify consistency against prior tree using tiles.
	if priorTree.N > 0 {
		tr := NewTileReader(store, DefaultTileHeight)
		hr := tlog.TileHashReader(newTree, tr)
		proof, err := tlog.ProveTree(newTree.N, priorTree.N, hr)
		if err != nil {
			return tlog.Tree{}, nil, fmt.Errorf("prove consistency: %w", err)
		}
		if err := tlog.CheckTree(proof, newTree.N, newTree.Hash, priorTree.N, priorTree.Hash); err != nil {
			return tlog.Tree{}, nil, fmt.Errorf("check consistency: %w", err)
		}
	}
	return newTree, newRaw, nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return err
		}
	}
	f, err := os.CreateTemp(dir, ".tlogx-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}

// VerifyInclusion verifies that a record is included in a checkpoint, using
// the authoritative append-order leaf index to locate it.
func VerifyInclusion(store storage.Store, leaf Leaf, tree tlog.Tree, policy Policy) error {
	if tree.N == 0 {
		return fmt.Errorf("empty tree cannot contain records")
	}
	lh, err := LeafHash(leaf)
	if err != nil {
		return err
	}
	indexes, err := LoadLeafIndexes(context.Background(), store)
	if err != nil {
		return err
	}
	var index int64 = -1
	for _, entry := range indexes {
		indexedHash, err := LeafIndexHash(entry)
		if err != nil {
			return err
		}
		if indexedHash == lh {
			index = entry.Index
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("record not found in log")
	}
	return VerifyInclusionAt(store, index, lh, tree, policy)
}

// PublicKeyBytes decodes an Ed25519 public key string to raw bytes.
// It is a small helper for callers that need the raw key bytes.
func PublicKeyBytes(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	return b, nil
}

// SignatureBytes decodes an Ed25519 signature string to raw bytes.
func SignatureBytes(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature must be %d bytes", ed25519.SignatureSize)
	}
	return b, nil
}
