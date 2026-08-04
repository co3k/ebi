// Package ebi-server is the transparency log server for ebi.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/co3k/ebi/pkg/fetch"
	"github.com/co3k/ebi/pkg/llm"
	"github.com/co3k/ebi/pkg/prefixdb"
	"github.com/co3k/ebi/pkg/schema"
	"github.com/co3k/ebi/pkg/secrets"
	"github.com/co3k/ebi/pkg/snapshot"
	"github.com/co3k/ebi/pkg/storage"
	"github.com/co3k/ebi/pkg/tlogx"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const (
	maxBodySize     = 1 << 20 // 1 MiB
	leaseDuration   = 30 * time.Second
	checkpointCache = 60
	checkpointRetry = 10 * time.Second

	pendingCheckpointPath   = "v1/pending-checkpoint"
	witnessedCheckpointPath = "v1/witnessed-checkpoint"
	checkpointStateDataEnv  = "EBI_CHECKPOINT_STATE_B64"
)

// ServerConfig configures the ebi server.
type ServerConfig struct {
	Port              string
	DataDir           string
	LogKey            string
	LogKeyFile        string
	LogOrigin         string
	WitnessKeys       []string
	WitnessURLs       []string
	RequiredWitnesses int
	PolicyPath        string
	CheckpointState   string
	FetchTimeout      time.Duration
	RequestTimeout    time.Duration
	SubmissionLimit   int
	SubmissionWindow  time.Duration
}

// DefaultServerConfig returns the default configuration.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Port:             "8080",
		DataDir:          "./data",
		LogOrigin:        "ebi.example.com",
		FetchTimeout:     30 * time.Second,
		RequestTimeout:   60 * time.Second,
		SubmissionLimit:  60,
		SubmissionWindow: time.Minute,
	}
}

// Fetcher fetches a URL into a private temporary file. It is the production
// boundary and may be overridden in tests.
type Fetcher interface {
	Fetch(ctx context.Context, rawURL string, opts fetch.Options) (*fetch.Fetched, error)
}

type fetcherFunc func(ctx context.Context, rawURL string, opts fetch.Options) (*fetch.Fetched, error)

func (f fetcherFunc) Fetch(ctx context.Context, rawURL string, opts fetch.Options) (*fetch.Fetched, error) {
	return f(ctx, rawURL, opts)
}

// defaultFetcher uses the strict fetch package.
var defaultFetcher Fetcher = fetcherFunc(fetch.FetchURL)

// logKey holds the log signing key in both the note checkpoint format and the
// raw Ed25519 format used for operator records.
type logKey struct {
	seed        []byte
	name        string
	hash        uint32
	signer      note.Signer
	verifierKey string
	publicKey   string
	private     ed25519.PrivateKey
	auditorID   string
}

// Server is the ebi transparency log server.
type Server struct {
	cfg             ServerConfig
	store           storage.Store
	key             *logKey
	policy          tlogx.Policy
	origin          string
	tree            *tlogx.Tree
	treeSize        atomic.Int64
	checkpointState string
	ownerID         string
	leasePath       string
	maxBody         int64
	requestTimeout  time.Duration
	fetchTimeout    time.Duration
	witnessURLs     []string
	fetcher         Fetcher
	queue           chan job
	done            chan struct{}
	wg              sync.WaitGroup
	witnessRetrying atomic.Bool
	mu              sync.RWMutex
	rateMu          sync.Mutex
	rateWindows     map[string]submissionWindow
	httpServer      *http.Server
	listener        net.Listener
}

// job is a single unit of sequenced work.
type job struct {
	ctx        context.Context
	rec        schema.Record
	validate   func(context.Context) error
	prepare    func(context.Context) error
	originalID string
	pending    bool
	warning    string
	resp       chan jobResult
}

type jobResult struct {
	recordID string
	pending  bool
	warning  string
	err      error
}

// NewServer creates a server from configuration. It does not start the
// sequencer or HTTP listener.
func NewServer(ctx context.Context, cfg ServerConfig) (*Server, error) {
	cfg = withDefaults(cfg)

	store, err := openStore(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	key, err := loadOrCreateLogKey(cfg.LogKeyFile, cfg.LogOrigin, cfg.LogKey)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("log key: %w", err)
	}

	policy, err := buildPolicy(cfg, key.verifierKey)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("policy: %w", err)
	}

	origin := cfg.LogOrigin
	if origin == "" {
		origin = key.name
	}

	leaves, err := tlogx.LoadLeavesFromIndex(store)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("load leaves: %w", err)
	}
	tree, err := tlogx.LoadTree(leaves)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("load tree: %w", err)
	}

	checkpointState := cfg.CheckpointState
	if checkpointState == "" {
		checkpointState = filepath.Join(cfg.DataDir, "checkpoint-state")
	}
	if err := restoreCheckpointStateFromEnv(checkpointState); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("restore checkpoint state: %w", err)
	}
	if _, err := os.Stat(checkpointState); err == nil {
		if err := verifyCheckpointState(ctx, store, checkpointState, policy, tree); err != nil {
			_ = store.Close()
			return nil, fmt.Errorf("checkpoint state: %w", err)
		}
	} else if !os.IsNotExist(err) {
		_ = store.Close()
		return nil, fmt.Errorf("stat checkpoint state: %w", err)
	}
	if err := verifyPublishedCheckpoint(ctx, store, policy, leaves); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("published checkpoint: %w", err)
	}

	ownerID, err := randomOwnerID()
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("owner id: %w", err)
	}

	s := &Server{
		cfg:             cfg,
		store:           store,
		key:             key,
		policy:          policy,
		origin:          origin,
		tree:            tree,
		checkpointState: checkpointState,
		ownerID:         ownerID,
		leasePath:       "v1/lease",
		maxBody:         maxBodySize,
		requestTimeout:  cfg.RequestTimeout,
		fetchTimeout:    cfg.FetchTimeout,
		witnessURLs:     append([]string(nil), cfg.WitnessURLs...),
		fetcher:         defaultFetcher,
		rateWindows:     make(map[string]submissionWindow),
	}
	s.treeSize.Store(tree.Size())
	return s, nil
}

func restoreCheckpointStateFromEnv(path string) error {
	encoded := os.Getenv(checkpointStateDataEnv)
	if encoded == "" {
		return nil
	}
	_ = os.Unsetenv(checkpointStateDataEnv)
	const maxCheckpointStateBytes = 1 << 20
	if len(encoded) > (maxCheckpointStateBytes*4/3)+8 {
		return fmt.Errorf("encoded checkpoint state exceeds limit")
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decode checkpoint state: %w", err)
	}
	if len(data) == 0 || len(data) > maxCheckpointStateBytes {
		return fmt.Errorf("checkpoint state size is invalid")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".checkpoint-state-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// SetFetcher overrides the fetcher. It is intended for tests.
func (s *Server) SetFetcher(f Fetcher) {
	s.fetcher = f
}

// Origin returns the log origin.
func (s *Server) Origin() string { return s.origin }

// Tree returns the current tree.
func (s *Server) Tree() *tlogx.Tree { return s.tree }

// Store returns the underlying store.
func (s *Server) Store() storage.Store { return s.store }

// Policy returns the active policy.
func (s *Server) Policy() tlogx.Policy { return s.policy }

// StartSequencer starts the single-writer goroutine and acquires the lease.
func (s *Server) StartSequencer(ctx context.Context) error {
	s.mu.Lock()
	if s.queue != nil {
		s.mu.Unlock()
		return fmt.Errorf("sequencer already started")
	}
	s.mu.Unlock()
	if err := s.acquireLease(ctx); err != nil {
		return fmt.Errorf("acquire lease: %w", err)
	}
	checkpointCurrent, err := s.publishedCheckpointIsCurrent(ctx)
	if err != nil {
		_ = s.releaseLease(ctx)
		return fmt.Errorf("read checkpoint before start: %w", err)
	}
	if !checkpointCurrent {
		s.mu.Lock()
		_, err := s.reconcileDerivedLocked(ctx)
		s.mu.Unlock()
		if err != nil {
			_ = s.releaseLease(ctx)
			return fmt.Errorf("reconcile initial checkpoint: %w", err)
		}
	} else {
		// Prefix shards are mutable derivatives and may have been interrupted
		// after a retraction/tombstone. Rebuild them on every startup even when
		// the authenticated checkpoint is already current.
		s.mu.Lock()
		err := s.updateShards(ctx)
		s.mu.Unlock()
		if err != nil {
			_ = s.releaseLease(ctx)
			return fmt.Errorf("rebuild prefix shards: %w", err)
		}
		if err := s.ensureCheckpointState(ctx); err != nil {
			_ = s.releaseLease(ctx)
			return fmt.Errorf("initialize checkpoint state: %w", err)
		}
	}
	if err := s.cleanupUnreferencedContentBlobs(ctx); err != nil {
		_ = s.releaseLease(ctx)
		return fmt.Errorf("cleanup content blobs: %w", err)
	}
	s.queue = make(chan job)
	s.done = make(chan struct{})
	s.wg.Add(1)
	go s.runSequencer()
	s.kickWitnessRetry()
	return nil
}

func (s *Server) ensureCheckpointState(ctx context.Context) error {
	if _, err := os.Stat(s.checkpointState); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := s.store.Get(ctx, storage.CheckpointPath())
	if err != nil {
		return err
	}
	tree, _, err := tlogx.VerifyCheckpoint(data, s.policy)
	if err != nil {
		return err
	}
	return tlogx.SaveCheckpointState(s.checkpointState, tree, data)
}

// StartHTTP starts the HTTP listener in a goroutine.
func (s *Server) StartHTTP(ctx context.Context) error {
	ln, err := net.Listen("tcp", net.JoinHostPort("", s.cfg.Port))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = ln
	s.httpServer = &http.Server{
		Addr:         ln.Addr().String(),
		Handler:      s.Handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: s.requestTimeout + 5*time.Second,
	}
	go func() {
		if err := s.httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Serve errors are surfaced by the caller via the listener.
		}
	}()
	return nil
}

// Addr returns the listening address, if StartHTTP was called.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Shutdown gracefully stops the HTTP listener, drains the sequencer queue, and
// releases the lease.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		_ = s.httpServer.Shutdown(ctx)
	}
	if s.done != nil {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	}
	s.wg.Wait()
	if s.store != nil {
		_ = s.releaseLease(ctx)
		return s.store.Close()
	}
	return nil
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/v1/records", s.withMethod(http.MethodPost, s.withSubmissionLimit(s.withTimeout(s.handleRecords))))
	mux.Handle("/v1/reports", s.withMethod(http.MethodPost, s.withSubmissionLimit(s.withTimeout(s.handleReports))))
	mux.Handle("/healthz", s.withMethod(http.MethodGet, s.handleHealth))
	return s.withSecurity(mux)
}

// runSequencer is the single writer goroutine.
func (s *Server) runSequencer() {
	defer s.wg.Done()
	ticker := time.NewTicker(checkpointRetry)
	defer ticker.Stop()
	for {
		select {
		case j, ok := <-s.queue:
			if !ok {
				return
			}
			s.processJob(j)
		case <-s.done:
			// Drain any remaining jobs before exiting.
			for {
				select {
				case j, ok := <-s.queue:
					if !ok {
						return
					}
					s.processJob(j)
				default:
					return
				}
			}
		case <-ticker.C:
			s.mu.Lock()
			ctx := context.Background()
			if err := s.renewLease(ctx); err == nil {
				current, err := s.publishedCheckpointIsCurrent(ctx)
				if err == nil && !current {
					_, _ = s.reconcileDerivedLocked(ctx)
				}
			}
			s.mu.Unlock()
			s.kickWitnessRetry()
		}
	}
}

func (s *Server) processJob(j job) {
	res := s.sequenceRecord(j.ctx, j.rec, j.validate, j.prepare)
	if j.originalID != "" {
		res.recordID = j.originalID
	}
	if j.pending {
		res.pending = true
		if j.warning != "" {
			res.warning = j.warning
		}
	}
	j.resp <- res
	if res.pending {
		s.kickWitnessRetry()
	}
}

func (s *Server) sequenceRecord(
	ctx context.Context,
	rec schema.Record,
	validate func(context.Context) error,
	prepare func(context.Context) error,
) jobResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sequenceRecordLocked(ctx, rec, validate, prepare)
}

// sequenceRecordLocked appends one record while s.mu is held. Validation and
// artifact preparation run in the same critical section as the append so a
// concurrent tombstone/cleanup cannot invalidate their result.
func (s *Server) sequenceRecordLocked(
	ctx context.Context,
	rec schema.Record,
	validate func(context.Context) error,
	prepare func(context.Context) error,
) jobResult {
	id, err := schema.RecordID(rec.Body)
	if err != nil {
		return jobResult{err: fmt.Errorf("record id: %w", err)}
	}
	indexes, err := tlogx.LoadLeafIndexes(ctx, s.store)
	if err != nil {
		return jobResult{err: fmt.Errorf("load leaf indexes: %w", err)}
	}
	for _, index := range indexes {
		if index.RecordID == id {
			current, err := s.publishedCheckpointIsCurrent(ctx)
			if err != nil {
				return jobResult{recordID: id, err: fmt.Errorf("read checkpoint for duplicate record: %w", err)}
			}
			if current {
				return jobResult{recordID: id, warning: "duplicate record"}
			}
			published, err := s.reconcileDerivedLocked(ctx)
			if err != nil {
				return jobResult{recordID: id, err: fmt.Errorf("reconcile duplicate record: %w", err)}
			}
			if !published {
				return jobResult{recordID: id, pending: true, warning: "witness quorum not yet available"}
			}
			return jobResult{recordID: id, warning: "duplicate record"}
		}
	}
	if validate != nil {
		if err := validate(ctx); err != nil {
			return jobResult{recordID: id, err: err}
		}
	}
	prepared := false
	if prepare != nil {
		// Mark preparation as started before invoking the hook: it may have
		// written one artifact before a later write fails.
		prepared = true
		if err := prepare(ctx); err != nil {
			res := jobResult{recordID: id, err: fmt.Errorf("prepare record artifacts: %w", err)}
			if cleanupErr := s.cleanupUnreferencedContentBlobsLocked(ctx); cleanupErr != nil {
				res.err = errors.Join(res.err, fmt.Errorf("cleanup prepared artifacts: %w", cleanupErr))
			}
			return res
		}
	}
	cleanupPrepared := func(res jobResult) jobResult {
		if !prepared || res.err == nil {
			return res
		}
		if cleanupErr := s.cleanupUnreferencedContentBlobsLocked(ctx); cleanupErr != nil {
			res.err = errors.Join(res.err, fmt.Errorf("cleanup prepared artifacts: %w", cleanupErr))
		}
		return res
	}
	if err := s.renewLease(ctx); err != nil {
		return cleanupPrepared(jobResult{recordID: id, err: fmt.Errorf("lease: %w", err)})
	}
	idx := s.tree.Size()
	if err := tlogx.WriteRecord(s.store, idx, rec); err != nil {
		return cleanupPrepared(jobResult{recordID: id, err: fmt.Errorf("write record: %w", err)})
	}
	leaf, err := tlogx.RecordToLeaf(rec)
	if err != nil {
		return cleanupPrepared(jobResult{recordID: id, err: fmt.Errorf("to leaf: %w", err)})
	}
	if _, err := s.tree.AppendLeaf(leaf); err != nil {
		return cleanupPrepared(jobResult{recordID: id, err: fmt.Errorf("append leaf: %w", err)})
	}
	s.treeSize.Store(s.tree.Size())
	published, err := s.reconcileDerivedLocked(ctx)
	if err != nil {
		return cleanupPrepared(jobResult{recordID: id, err: err})
	}
	if !published {
		return jobResult{recordID: id, pending: true, warning: "witness quorum not yet available"}
	}
	return jobResult{recordID: id, pending: false}
}

// reconcileDerivedLocked rebuilds every public derivative from the
// append-order leaf index and publishes the checkpoint last. s.mu must be held.
func (s *Server) reconcileDerivedLocked(ctx context.Context) (bool, error) {
	if err := s.renewLease(ctx); err != nil {
		return false, fmt.Errorf("lease: %w", err)
	}
	if err := tlogx.WriteTiles(s.tree, s.store, tlogx.DefaultTileHeight); err != nil {
		return false, fmt.Errorf("write tiles: %w", err)
	}
	if err := s.updateShards(ctx); err != nil {
		return false, fmt.Errorf("update shards: %w", err)
	}
	published, err := s.publishCheckpoint(ctx)
	if err != nil {
		return false, fmt.Errorf("checkpoint: %w", err)
	}
	return published, nil
}

// publishCheckpoint signs the current checkpoint, persists the local state file,
// and publishes it to storage only when no witness quorum is required. It returns
// true if the checkpoint was published to storage.
func (s *Server) publishCheckpoint(ctx context.Context) (bool, error) {
	tree := s.tree.TlogTree()
	signed, err := tlogx.CheckpointBytes(tree, s.origin, s.key.signer)
	if err != nil {
		return false, fmt.Errorf("sign checkpoint: %w", err)
	}
	if s.policy.RequiredWitnesses > 0 {
		// Expose the log-signed candidate in static storage so an external
		// C2SP-compatible collector can obtain consistency proofs, cosign it,
		// and stage the result. Never publish the log-only candidate as the
		// public checkpoint when the policy requires a quorum.
		if err := s.store.Put(ctx, storage.Object{
			Path:         pendingCheckpointPath,
			Data:         signed,
			ContentType:  "text/plain; charset=utf-8",
			CacheSeconds: 60,
			Mutable:      true,
		}); err != nil {
			return false, fmt.Errorf("stage pending checkpoint: %w", err)
		}
		candidate, err := s.store.Get(ctx, witnessedCheckpointPath)
		if err != nil {
			if storage.IsNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("read witnessed checkpoint: %w", err)
		}
		got, _, err := tlogx.VerifyCheckpoint(candidate, s.policy)
		if err != nil {
			return false, fmt.Errorf("verify witnessed checkpoint: %w", err)
		}
		if got != tree {
			if got.N < tree.N {
				// A collector commonly stages the last witnessed checkpoint
				// while the log has already advanced. Keep the new tree pending;
				// it is not corruption and the retry loop will publish once a
				// matching cosigned checkpoint arrives.
				return false, nil
			}
			return false, fmt.Errorf("witnessed checkpoint does not match current tree")
		}
		signed = candidate
	}
	obj := storage.Object{
		Path:         storage.CheckpointPath(),
		Data:         signed,
		ContentType:  "text/plain; charset=utf-8",
		CacheSeconds: checkpointCache,
	}
	if err := s.store.Publish(ctx, obj); err != nil {
		return false, fmt.Errorf("publish checkpoint: %w", err)
	}
	// Persist only an actually published (and, when required, witnessed)
	// checkpoint. This avoids treating an unpublished tree head as trusted
	// state after restart.
	if err := tlogx.SaveCheckpointState(s.checkpointState, tree, signed); err != nil {
		return false, fmt.Errorf("save checkpoint state: %w", err)
	}
	if s.policy.RequiredWitnesses > 0 {
		if err := s.store.Delete(ctx, pendingCheckpointPath); err != nil && !storage.IsNotFound(err) {
			return false, fmt.Errorf("delete pending checkpoint: %w", err)
		}
		if err := s.store.Delete(ctx, witnessedCheckpointPath); err != nil && !storage.IsNotFound(err) {
			return false, fmt.Errorf("delete witnessed checkpoint: %w", err)
		}
	}
	return true, nil
}

func (s *Server) collectWitnessCosignatures(ctx context.Context, checkpoint []byte, tree *tlogx.Tree) ([]byte, error) {
	candidate := append([]byte(nil), checkpoint...)
	client := &http.Client{Timeout: s.requestTimeout}
	var failures []string
	for _, baseURL := range s.witnessURLs {
		oldSize := int64(0)
		var proof tlog.TreeProof
		for attempt := 0; attempt < 2; attempt++ {
			req, err := tlogx.AddCheckpointRequest(ctx, baseURL, oldSize, proof, checkpoint)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", baseURL, err))
				break
			}
			req.Header.Set("User-Agent", "ebi-server")
			resp, err := client.Do(req)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", baseURL, err))
				break
			}
			signatures, currentSize, parseErr := tlogx.ParseWitnessResponse(resp)
			_ = resp.Body.Close()
			if parseErr != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", baseURL, parseErr))
				break
			}
			if resp.StatusCode == http.StatusConflict {
				if attempt > 0 || currentSize < 0 || currentSize > tree.Size() {
					failures = append(failures, fmt.Sprintf("%s: invalid witness size %d", baseURL, currentSize))
					break
				}
				oldSize = currentSize
				proof = nil
				if oldSize > 0 && oldSize < tree.Size() {
					proof, err = tree.TreeProof(oldSize)
					if err != nil {
						failures = append(failures, fmt.Sprintf("%s: consistency proof: %v", baseURL, err))
						break
					}
				}
				continue
			}
			for _, signature := range signatures {
				merged, err := tlogx.MergeWitnessSignature(candidate, signature, s.policy.WitnessKeys)
				if err != nil {
					failures = append(failures, fmt.Sprintf("%s: %v", baseURL, err))
					continue
				}
				candidate = merged
			}
			break
		}
		if _, _, err := tlogx.VerifyCheckpoint(candidate, s.policy); err == nil {
			return candidate, nil
		}
	}
	if _, _, err := tlogx.VerifyCheckpoint(candidate, s.policy); err == nil {
		return candidate, nil
	}
	if len(failures) > 0 {
		return nil, fmt.Errorf("witness quorum unavailable: %s", strings.Join(failures, "; "))
	}
	return nil, nil
}

func (s *Server) kickWitnessRetry() {
	if s.policy.RequiredWitnesses <= 0 || len(s.witnessURLs) == 0 || s.done == nil {
		return
	}
	if !s.witnessRetrying.CompareAndSwap(false, true) {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.witnessRetrying.Store(false)
		s.retryWitnessCheckpoint()
	}()
}

func (s *Server) retryWitnessCheckpoint() {
	ctx, cancel := context.WithTimeout(context.Background(), s.requestTimeout)
	defer cancel()
	go func() {
		select {
		case <-s.done:
			cancel()
		case <-ctx.Done():
		}
	}()

	s.mu.Lock()
	tree := s.tree.Clone()
	signed, err := tlogx.CheckpointBytes(tree.TlogTree(), s.origin, s.key.signer)
	if err == nil {
		err = s.store.Put(ctx, storage.Object{
			Path:         pendingCheckpointPath,
			Data:         signed,
			ContentType:  "text/plain; charset=utf-8",
			CacheSeconds: 60,
			Mutable:      true,
		})
	}
	s.mu.Unlock()
	if err != nil {
		return
	}

	candidate, err := s.collectWitnessCosignatures(ctx, signed, tree)
	if err != nil || len(candidate) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.tree.TlogTree()
	if current != tree.TlogTree() {
		return
	}
	if err := s.store.Put(ctx, storage.Object{
		Path:         witnessedCheckpointPath,
		Data:         candidate,
		ContentType:  "text/plain; charset=utf-8",
		CacheSeconds: 60,
		Mutable:      true,
	}); err != nil {
		return
	}
	_, _ = s.publishCheckpoint(ctx)
}

func (s *Server) publishedCheckpointIsCurrent(ctx context.Context) (bool, error) {
	data, err := s.store.Get(ctx, storage.CheckpointPath())
	if err != nil {
		if storage.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	tree, _, err := tlogx.VerifyCheckpoint(data, s.policy)
	if err != nil {
		return false, err
	}
	return tree.N == s.tree.Size() && tree.Hash == s.tree.Root(), nil
}

func (s *Server) updateShards(ctx context.Context) error {
	records, indices, err := s.recordsInOrder(ctx)
	if err != nil {
		return err
	}
	shards, err := prefixdb.BuildShardsWithIndex(records, indices)
	if err != nil {
		return err
	}
	for prefix, data := range shards {
		if err := s.store.Put(ctx, storage.Object{
			Path:         storage.PrefixPath(prefix),
			Data:         data,
			ContentType:  "application/json",
			CacheSeconds: 300,
		}); err != nil {
			return err
		}
	}
	existing, err := s.store.List(ctx, "v1/prefix")
	if err != nil {
		return err
	}
	for _, path := range existing {
		prefix := strings.TrimPrefix(path, "v1/prefix/")
		if prefix == "" || strings.Contains(prefix, "/") {
			return fmt.Errorf("invalid prefix object path %q", path)
		}
		if _, ok := shards[prefix]; ok {
			continue
		}
		if err := s.store.Delete(ctx, path); err != nil && !storage.IsNotFound(err) {
			return fmt.Errorf("delete stale prefix shard %s: %w", prefix, err)
		}
	}
	return nil
}

func (s *Server) recordsInOrder(ctx context.Context) ([]schema.Record, []int64, error) {
	leaves, err := tlogx.LoadLeavesFromIndex(s.store)
	if err != nil {
		return nil, nil, err
	}
	all := make([]schema.Record, 0, len(leaves))
	allIndices := make([]int64, 0, len(leaves))
	for i, leaf := range leaves {
		data, err := s.store.Get(ctx, "v1/blob/"+leaf.RecordID)
		if err != nil {
			return nil, nil, fmt.Errorf("read blob %s: %w", leaf.RecordID, err)
		}
		if _, isTombstone, err := tlogx.DecodeTombstoneBlob(data, leaf.RecordID); err != nil {
			return nil, nil, fmt.Errorf("decode tombstone %s: %w", leaf.RecordID, err)
		} else if isTombstone {
			continue
		}
		rec, err := schema.DecodeRecordStrict(bytes.NewReader(data))
		if err != nil {
			return nil, nil, fmt.Errorf("decode blob %s: %w", leaf.RecordID, err)
		}
		if rec.Body.Type != schema.SchemaAuditV1 && rec.Body.Type != schema.SchemaRetractV1 {
			continue
		}
		all = append(all, *rec)
		allIndices = append(allIndices, int64(i))
	}
	var retractions []schema.Record
	for _, rec := range all {
		if rec.Body.Type == schema.SchemaRetractV1 {
			retractions = append(retractions, rec)
		}
	}
	records := make([]schema.Record, 0, len(all))
	indices := make([]int64, 0, len(all))
	for i, rec := range all {
		if rec.Body.Type != schema.SchemaAuditV1 ||
			rec.Body.Target.SHA256 == "" || !schema.IsHexHash(rec.Body.Target.SHA256) {
			continue
		}
		retracted := false
		for j := range retractions {
			if schema.RetractionMatchesTarget(&retractions[j], &rec) {
				retracted = true
				break
			}
		}
		if retracted {
			continue
		}
		records = append(records, rec)
		indices = append(indices, allIndices[i])
	}
	return records, indices, nil
}

func (s *Server) sendJob(ctx context.Context, rec schema.Record, originalID string, pending bool, warning string) (jobResult, error) {
	return s.sendJobWithHooks(ctx, rec, nil, nil, originalID, pending, warning)
}

func (s *Server) sendJobWithHooks(
	ctx context.Context,
	rec schema.Record,
	validate func(context.Context) error,
	prepare func(context.Context) error,
	originalID string,
	pending bool,
	warning string,
) (jobResult, error) {
	resp := make(chan jobResult, 1)
	j := job{
		ctx:        ctx,
		rec:        rec,
		validate:   validate,
		prepare:    prepare,
		originalID: originalID,
		pending:    pending,
		warning:    warning,
		resp:       resp,
	}
	select {
	case s.queue <- j:
	case <-s.done:
		return jobResult{}, errors.New("server shutting down")
	case <-ctx.Done():
		return jobResult{}, ctx.Err()
	}
	select {
	case res := <-resp:
		return res, nil
	case <-s.done:
		return jobResult{}, errors.New("server shutting down")
	case <-ctx.Done():
		return jobResult{}, ctx.Err()
	}
}

func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	rec, err := decodeSubmitRecord(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid record: %v", err)})
		return
	}
	bodyVerified, auditorID, err := schema.Verify(rec)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("verify: %v", err)})
		return
	}
	id, err := schema.RecordID(*bodyVerified)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("record id: %v", err)})
		return
	}

	switch bodyVerified.Type {
	case schema.SchemaAuditV1:
		if !strings.HasPrefix(bodyVerified.Target.URL, "https://") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "audit target URL must use https"})
			return
		}
		// Pending records are idempotent: if already pending, do not append again.
		if _, err := s.store.Get(r.Context(), "v1/pending/"+id); err == nil {
			writeJSON(w, http.StatusAccepted, map[string]interface{}{
				"record_id": id,
				"pending":   true,
				"warning":   "target hash mismatch; use /v1/reports for mismatch review",
			})
			return
		} else if !storage.IsNotFound(err) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "read pending submission state"})
			return
		}

		// Fetch the target once and verify hash/size and line hashes.
		fetched, err := s.fetchTarget(r.Context(), bodyVerified.Target.URL)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "server could not fetch the public target"})
			return
		}
		defer fetch.RemoveTemp(fetched)
		if fetched.Hash != bodyVerified.Target.SHA256 || fetched.Size != bodyVerified.Target.Size {
			s.handleMismatch(w, r, id, rec)
			return
		}
		data, err := os.ReadFile(fetched.Path)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "read fetched target"})
			return
		}
		if err := s.verifyLineHashes(bodyVerified, data); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("claims do not match fetched target: %v", err)})
			return
		}
		var promptData []byte
		if bodyVerified.Analyzer.Kind == schema.KindLLM {
			prompt := llm.BuildPrompt(string(data))
			if got := llm.PromptHash(prompt); got != bodyVerified.Analyzer.PromptSHA256 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "LLM prompt hash does not match the published analyzer prompt"})
				return
			}
			promptData = llm.PromptBytes(prompt)
		}
		prepare := func(ctx context.Context) error {
			if err := s.putContentBlob(ctx, bodyVerified.Target.SHA256, data, "text/x-shellscript"); err != nil {
				return fmt.Errorf("store fetched target: %w", err)
			}
			if len(promptData) > 0 {
				if err := s.putContentBlob(ctx, bodyVerified.Analyzer.PromptSHA256, promptData, "application/octet-stream"); err != nil {
					return fmt.Errorf("store LLM prompt: %w", err)
				}
			}
			return nil
		}
		res, err := s.sendJobWithHooks(r.Context(), *rec, nil, prepare, "", false, "")
		s.writeSequenceResponse(w, auditorID, res, err)
		return
	case schema.SchemaRetractV1:
		if err := s.validateRetractionTarget(r.Context(), rec); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		validate := func(ctx context.Context) error {
			return s.validateRetractionTarget(ctx, rec)
		}
		res, err := s.sendJobWithHooks(r.Context(), *rec, validate, nil, "", false, "")
		s.writeSequenceResponse(w, auditorID, res, err)
		return
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "only audit/v1 and retract/v1 records are accepted"})
		return
	}
}

func (s *Server) writeSequenceResponse(w http.ResponseWriter, auditorID string, res jobResult, err error) {
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": fmt.Sprintf("sequence: %v", err)})
		return
	}
	if res.err != nil {
		var validationErr *recordValidationError
		if errors.As(res.err, &validationErr) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": validationErr.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("sequence: %v", res.err)})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"record_id": res.recordID,
		"pending":   res.pending,
		"warning":   res.warning,
		"auditor":   auditorID,
	})
}

type recordValidationError struct {
	message string
}

func (e *recordValidationError) Error() string { return e.message }

func (s *Server) validateRetractionTarget(ctx context.Context, rec *schema.Record) error {
	targetData, err := s.store.Get(ctx, storage.BlobPath(rec.Body.RecordID))
	if err != nil {
		return &recordValidationError{message: "retraction target does not exist"}
	}
	if _, isTombstone, err := tlogx.DecodeTombstoneBlob(targetData, rec.Body.RecordID); err != nil || isTombstone {
		return &recordValidationError{message: "retraction target is unavailable"}
	}
	target, err := schema.DecodeRecordStrict(bytes.NewReader(targetData))
	if err != nil {
		return &recordValidationError{message: "retraction target is unavailable"}
	}
	if _, _, err := schema.Verify(target); err != nil || !schema.RetractionMatchesTarget(rec, target) {
		return &recordValidationError{message: "retraction is not authorized by the target auditor"}
	}
	return nil
}

type submitRecordRequest struct {
	Record    schema.RecordBody `json:"record"`
	PublicKey string            `json:"public_key"`
	Signature string            `json:"signature"`
}

func decodeSubmitRecord(data []byte) (*schema.Record, error) {
	var req submitRecordRequest
	if err := decodeStrictJSON(data, &req); err != nil {
		return nil, err
	}
	return &schema.Record{
		Body:      req.Record,
		PublicKey: req.PublicKey,
		Signature: req.Signature,
	}, nil
}

func (s *Server) handleMismatch(w http.ResponseWriter, r *http.Request, id string, rec *schema.Record) {
	rawBody, err := json.Marshal(rec)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encode pending record"})
		return
	}
	if err := s.store.Put(r.Context(), storage.Object{
		Path:        "v1/pending/" + id,
		Data:        rawBody,
		ContentType: "application/json",
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("persist pending: %v", err)})
		return
	}
	pendingBody := schema.RecordBody{
		Type:      schema.SchemaModerationV1,
		CreatedAt: schema.UnixNow(),
		Auditor:   s.key.auditorID,
		Target:    rec.Body.Target,
		Reason:    "pending_mismatch",
	}
	pendingRec, _, err := s.signServerRecord(pendingBody)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("sign pending record: %v", err)})
		return
	}
	res, err := s.sendJob(r.Context(), pendingRec, id, true, "target hash mismatch; use /v1/reports for mismatch review")
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": fmt.Sprintf("sequence: %v", err)})
		return
	}
	if res.err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("sequence: %v", res.err)})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"record_id": id,
		"pending":   true,
		"warning":   res.warning,
	})
}

func (s *Server) fetchTarget(ctx context.Context, rawURL string) (*fetch.Fetched, error) {
	opts := fetch.ServerOptions()
	opts.Timeout = s.fetchTimeout
	return s.fetcher.Fetch(ctx, rawURL, opts)
}

func (s *Server) verifyLineHashes(body *schema.RecordBody, data []byte) error {
	lines := strings.Split(string(data), "\n")
	for i, c := range body.Claims {
		if c.Line <= 0 || c.Line > len(lines) {
			return fmt.Errorf("claim %d: line %d out of range", i, c.Line)
		}
		got := schema.LineHash(lines[c.Line-1])
		if c.LineSHA256 != "" && c.LineSHA256 != got {
			return fmt.Errorf("claim %d: line hash mismatch", i)
		}
	}
	return nil
}

func (s *Server) putContentBlob(ctx context.Context, hash string, data []byte, contentType string) error {
	if !schema.IsHexHash(hash) || storage.ContentHash(data) != hash {
		return fmt.Errorf("content hash mismatch")
	}
	path := storage.BlobPath(hash)
	if existing, err := s.store.Get(ctx, path); err == nil {
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("content-addressed blob %s already has different bytes", hash)
		}
		return nil
	} else if !storage.IsNotFound(err) {
		return err
	}
	return s.store.Put(ctx, storage.Object{
		Path:        path,
		Data:        data,
		ContentType: contentType,
		Immutable:   true,
	})
}

type reportRequest struct {
	RecordID           string          `json:"record_id"`
	Acknowledgement    string          `json:"acknowledgement"`
	MaskedReport       string          `json:"masked_report"`
	SecretScanMetadata json.RawMessage `json:"secret_scan_metadata"`
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	var req reportRequest
	if err := decodeStrictJSON(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid report: %v", err)})
		return
	}
	if req.Acknowledgement != "yes-i-reviewed-this" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "acknowledgement must be exactly 'yes-i-reviewed-this'"})
		return
	}
	if req.RecordID == "" || req.MaskedReport == "" || len(req.SecretScanMetadata) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "record_id, masked_report, and secret_scan_metadata are required"})
		return
	}
	pendingData, err := s.store.Get(r.Context(), "v1/pending/"+req.RecordID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no pending mismatch record for record_id"})
		return
	}
	var pendingRec schema.Record
	if err := json.Unmarshal(pendingData, &pendingRec); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "pending record is corrupted"})
		return
	}
	pendingBody, _, err := schema.Verify(&pendingRec)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "pending record is invalid"})
		return
	}
	if pendingBody.Target.SHA256 == "" {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "pending record has no target hash"})
		return
	}

	detector, err := secrets.NewDetector()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("secret detector: %v", err)})
		return
	}
	findings, err := detector.ScanString(req.MaskedReport)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("secret scan: %v", err)})
		return
	}
	if len(findings) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":    "secrets detected in masked report",
			"findings": findings,
		})
		return
	}

	maskedHash := sha256Hex([]byte(req.MaskedReport))
	if maskedHash == pendingBody.Target.SHA256 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "masked report hashes to the original target; secrets are not masked"})
		return
	}

	report := struct {
		RecordID           string          `json:"record_id"`
		Acknowledgement    string          `json:"acknowledgement"`
		MaskedReport       string          `json:"masked_report"`
		SecretScanMetadata json.RawMessage `json:"secret_scan_metadata"`
		OriginalTargetHash string          `json:"original_target_hash"`
		ReportedAt         string          `json:"reported_at"`
		Warning            string          `json:"warning"`
	}{
		RecordID:           req.RecordID,
		Acknowledgement:    req.Acknowledgement,
		MaskedReport:       req.MaskedReport,
		SecretScanMetadata: req.SecretScanMetadata,
		OriginalTargetHash: pendingBody.Target.SHA256,
		ReportedAt:         schema.NewTimestamp(),
		Warning:            "secret rotation is mandatory even after deletion",
	}
	reportBytes, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal report"})
		return
	}
	if err := s.store.Put(r.Context(), storage.Object{
		Path:        "v1/reports/" + req.RecordID + ".json",
		Data:        reportBytes,
		ContentType: "application/json",
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("store report: %v", err)})
		return
	}
	if err := s.store.Delete(r.Context(), "v1/pending/"+req.RecordID); err != nil && !storage.IsNotFound(err) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("clear pending report state: %v", err)})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"record_id": req.RecordID,
		"status":    "reported",
		"warning":   report.Warning,
	})
}

func (s *Server) handleTombstone(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	var req struct {
		RecordID string `json:"record_id"`
	}
	if err := decodeStrictJSON(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid request: %v", err)})
		return
	}
	if req.RecordID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "record_id is required"})
		return
	}
	res, err := s.Tombstone(r.Context(), req.RecordID)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": fmt.Sprintf("tombstone: %v", err)})
		return
	}
	if res.err != nil {
		code := http.StatusInternalServerError
		if storage.IsNotFound(res.err) {
			code = http.StatusNotFound
		}
		writeJSON(w, code, map[string]string{"error": fmt.Sprintf("tombstone: %v", res.err)})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"record_id":    req.RecordID,
		"tombstone_id": res.recordID,
		"warning":      "Deletion never substitutes for rotation; rotate exposed secrets immediately.",
	})
}

// Tombstone replaces a blob with a tombstone JSON and appends a moderation
// record. It is exported for use by the command-line tombstone subcommand.
func (s *Server) Tombstone(ctx context.Context, recordID string) (jobResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !schema.IsHexHash(recordID) {
		err := fmt.Errorf("record ID must be a lowercase SHA-256 hex string")
		return jobResult{err: err}, err
	}
	original, err := s.store.Get(ctx, "v1/blob/"+recordID)
	if err != nil {
		return jobResult{err: err}, err
	}
	if _, isTombstone, err := tlogx.DecodeTombstoneBlob(original, recordID); err != nil {
		return jobResult{err: err}, err
	} else if isTombstone {
		err := fmt.Errorf("record is already tombstoned")
		return jobResult{err: err}, err
	}
	target, err := schema.DecodeRecordStrict(bytes.NewReader(original))
	if err != nil {
		err := fmt.Errorf("tombstone target is not a signed record")
		return jobResult{err: err}, err
	}
	if _, _, err := schema.Verify(target); err != nil {
		err = fmt.Errorf("verify tombstone target: %w", err)
		return jobResult{err: err}, err
	}
	sequenced, err := s.isSequencedRecordLocked(ctx, recordID)
	if err != nil {
		return jobResult{err: err}, err
	}
	if !sequenced {
		err := fmt.Errorf("tombstone target is not a sequenced record")
		return jobResult{err: err}, err
	}
	if target.Body.Type == schema.SchemaModerationV1 && target.Body.Reason == "tombstone" {
		err := fmt.Errorf("tombstone moderation bindings cannot be tombstoned")
		return jobResult{err: err}, err
	}
	retracted, err := s.hasMatchingRetractionLocked(ctx, target)
	if err != nil {
		return jobResult{err: err}, err
	}
	if retracted {
		err := fmt.Errorf("record has a live retraction; tombstone the retraction first")
		return jobResult{err: err}, err
	}
	tombstone := map[string]interface{}{
		"tombstone":  true,
		"record_id":  recordID,
		"reason":     "operator request",
		"message":    "Deletion never substitutes for rotation; rotate exposed secrets immediately.",
		"deleted_at": schema.NewTimestamp(),
	}
	tombBytes, err := json.Marshal(tombstone)
	if err != nil {
		return jobResult{err: err}, err
	}
	body := schema.RecordBody{
		Type:            schema.SchemaModerationV1,
		CreatedAt:       schema.UnixNow(),
		Auditor:         s.key.auditorID,
		BlobSHA256:      recordID,
		TombstoneSHA256: sha256Hex(tombBytes),
		Reason:          "tombstone",
	}
	rec, _, err := s.signServerRecord(body)
	if err != nil {
		return jobResult{err: err}, err
	}
	res := s.sequenceRecordLocked(ctx, rec, nil, nil)
	if res.err != nil {
		return res, res.err
	}
	if res.pending {
		err := fmt.Errorf("moderation checkpoint is awaiting witness quorum; original blob was not deleted")
		return jobResult{
			recordID: res.recordID,
			pending:  true,
			warning:  res.warning,
			err:      err,
		}, err
	}
	// Append and publish the signed moderation binding before replacing the
	// original blob. A crash can therefore leave an extra no-op moderation
	// record, but can never delete the body without an authenticated binding.
	if err := s.store.Put(ctx, storage.Object{
		Path:         "v1/blob/" + recordID,
		Data:         tombBytes,
		ContentType:  "application/json",
		CacheSeconds: 60,
		Mutable:      true,
	}); err != nil {
		return jobResult{recordID: res.recordID, err: err}, err
	}
	err = s.updateShards(ctx)
	if err != nil {
		return jobResult{recordID: res.recordID, err: err}, err
	}
	if err := s.cleanupUnreferencedContentBlobsLocked(ctx); err != nil {
		return jobResult{recordID: res.recordID, err: err}, err
	}
	return res, nil
}

func (s *Server) cleanupUnreferencedContentBlobs(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleanupUnreferencedContentBlobsLocked(ctx)
}

func (s *Server) cleanupUnreferencedContentBlobsLocked(ctx context.Context) error {
	indexes, err := tlogx.LoadLeafIndexes(ctx, s.store)
	if err != nil {
		return err
	}
	leafIDs := make(map[string]bool, len(indexes))
	referencedArtifacts := make(map[string]bool)
	for _, index := range indexes {
		leafIDs[index.RecordID] = true
		data, err := s.store.Get(ctx, storage.BlobPath(index.RecordID))
		if err != nil {
			return err
		}
		if _, tombstone, err := tlogx.DecodeTombstoneBlob(data, index.RecordID); err != nil {
			return err
		} else if tombstone {
			continue
		}
		record, err := schema.DecodeRecordStrict(bytes.NewReader(data))
		if err != nil {
			return err
		}
		if record.Body.Type != schema.SchemaAuditV1 {
			continue
		}
		referencedArtifacts[record.Body.Target.SHA256] = true
		if record.Body.Analyzer.Kind == schema.KindLLM {
			referencedArtifacts[record.Body.Analyzer.PromptSHA256] = true
		}
	}
	keys, err := s.store.List(ctx, "v1/blob")
	if err != nil {
		return err
	}
	for _, path := range keys {
		id := strings.TrimPrefix(path, "v1/blob/")
		if strings.Contains(id, "/") || !schema.IsHexHash(id) || leafIDs[id] || referencedArtifacts[id] {
			continue
		}
		if err := s.store.Delete(ctx, path); err != nil && !storage.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (s *Server) isSequencedRecordLocked(ctx context.Context, recordID string) (bool, error) {
	indexes, err := tlogx.LoadLeafIndexes(ctx, s.store)
	if err != nil {
		return false, err
	}
	for _, index := range indexes {
		if index.RecordID == recordID {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) hasMatchingRetractionLocked(ctx context.Context, target *schema.Record) (bool, error) {
	indexes, err := tlogx.LoadLeafIndexes(ctx, s.store)
	if err != nil {
		return false, err
	}
	for _, index := range indexes {
		data, err := s.store.Get(ctx, storage.BlobPath(index.RecordID))
		if err != nil {
			return false, err
		}
		if _, tombstone, err := tlogx.DecodeTombstoneBlob(data, index.RecordID); err != nil {
			return false, err
		} else if tombstone {
			continue
		}
		rec, err := schema.DecodeRecordStrict(bytes.NewReader(data))
		if err != nil {
			return false, err
		}
		if rec.Body.Type == schema.SchemaRetractV1 && schema.RetractionMatchesTarget(rec, target) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	size := s.treeSize.Load()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"origin": s.origin,
		"size":   size,
	})
}

func (s *Server) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if !s.contentTypeOK(r) {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "content-type must be application/json"})
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, s.maxBody+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body"})
		return nil, false
	}
	_ = r.Body.Close()
	if int64(len(data)) > s.maxBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body exceeds 1 MiB"})
		return nil, false
	}
	return data, true
}

func (s *Server) contentTypeOK(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	if mt != "application/json" {
		return false
	}
	for k, v := range params {
		if !strings.EqualFold(k, "charset") || !strings.EqualFold(v, "utf-8") {
			return false
		}
	}
	return true
}

func (s *Server) withSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withMethod(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		h(w, r)
	}
}

func (s *Server) withTimeout(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), s.requestTimeout)
		defer cancel()
		h(w, r.WithContext(ctx))
	}
}

type submissionWindow struct {
	start time.Time
	count int
}

func (s *Server) withSubmissionLimit(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.SubmissionLimit <= 0 || s.cfg.SubmissionWindow <= 0 {
			h(w, r)
			return
		}
		now := time.Now()
		key := submissionRateKey(r.RemoteAddr)
		s.rateMu.Lock()
		for existingKey, window := range s.rateWindows {
			if now.Sub(window.start) >= s.cfg.SubmissionWindow {
				delete(s.rateWindows, existingKey)
			}
		}
		window, ok := s.rateWindows[key]
		if !ok {
			window = submissionWindow{start: now}
		}
		if window.count >= s.cfg.SubmissionLimit {
			retry := time.Until(window.start.Add(s.cfg.SubmissionWindow))
			s.rateMu.Unlock()
			if retry < time.Second {
				retry = time.Second
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retry.Round(time.Second)/time.Second)))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "submission rate limit exceeded"})
			return
		}
		window.count++
		s.rateWindows[key] = window
		s.rateMu.Unlock()
		h(w, r)
	}
}

func submissionRateKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	if remoteAddr == "" {
		return "unknown"
	}
	return remoteAddr
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeStrictJSON(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing data")
		}
		return err
	}
	return nil
}

func (s *Server) signServerRecord(body schema.RecordBody) (schema.Record, string, error) {
	rec, err := schema.Sign(body, s.key.private)
	if err != nil {
		return schema.Record{}, "", err
	}
	id, err := schema.RecordID(rec.Body)
	if err != nil {
		return schema.Record{}, "", err
	}
	return *rec, id, nil
}

// CreateSnapshot writes a snapshot of the current tree to w.
func (s *Server) CreateSnapshot(ctx context.Context, w io.Writer) (*snapshot.Metadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := s.store.Get(ctx, storage.CheckpointPath())
	if err != nil {
		return nil, fmt.Errorf("read published checkpoint: %w", err)
	}
	tree, _, err := tlogx.VerifyCheckpoint(data, s.policy)
	if err != nil {
		return nil, fmt.Errorf("verify published checkpoint: %w", err)
	}
	if tree.N != s.tree.Size() || tree.Hash != s.tree.Root() {
		return nil, fmt.Errorf("published checkpoint does not cover the current tree")
	}
	return snapshot.Create(ctx, s.store, tree.N, string(data), w)
}

// PublishSnapshot creates and publishes an immutable snapshot archive, then
// atomically updates v1/snapshot/latest.json last.
func (s *Server) PublishSnapshot(ctx context.Context, publicBaseURL string, mirrors []string) (*snapshot.Metadata, error) {
	s.mu.RLock()
	treeSize := s.tree.Size()
	s.mu.RUnlock()
	path := storage.SnapshotPath(treeSize)
	if _, err := s.store.Get(ctx, path); err == nil {
		return nil, fmt.Errorf("snapshot %d already exists", treeSize)
	} else if !storage.IsNotFound(err) {
		return nil, fmt.Errorf("check existing snapshot: %w", err)
	}

	var archive bytes.Buffer
	meta, err := s.CreateSnapshot(ctx, &archive)
	if err != nil {
		return nil, err
	}
	if err := s.store.Publish(ctx, storage.Object{
		Path:        path,
		Data:        archive.Bytes(),
		ContentType: "application/zstd",
		Immutable:   true,
	}); err != nil {
		return nil, fmt.Errorf("publish snapshot archive: %w", err)
	}
	publicURL := strings.TrimSuffix(publicBaseURL, "/") + "/" + path
	latest, err := snapshot.LatestJSON(meta, publicURL, mirrors)
	if err != nil {
		return nil, err
	}
	if err := s.store.Publish(ctx, storage.Object{
		Path:         "v1/snapshot/latest.json",
		Data:         latest,
		ContentType:  "application/json",
		CacheSeconds: 300,
	}); err != nil {
		return nil, fmt.Errorf("publish latest snapshot pointer: %w", err)
	}
	return meta, nil
}

// ImportSnapshot imports a snapshot in the given mode (mirror or fork).
func (s *Server) ImportSnapshot(ctx context.Context, r io.Reader, mode string) error {
	switch mode {
	case "mirror":
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, err := snapshot.ImportMirrorWithPolicy(r, s.store, s.policy); err != nil {
			return err
		}
		leaves, err := tlogx.LoadLeavesFromIndex(s.store)
		if err != nil {
			return fmt.Errorf("load imported mirror leaves: %w", err)
		}
		tree, err := tlogx.LoadTree(leaves)
		if err != nil {
			return fmt.Errorf("load imported mirror tree: %w", err)
		}
		s.tree = tree
		s.treeSize.Store(tree.Size())
		checkpoint, err := s.store.Get(ctx, storage.CheckpointPath())
		if err != nil {
			return fmt.Errorf("read imported mirror checkpoint: %w", err)
		}
		if err := tlogx.SaveCheckpointState(s.checkpointState, tree.TlogTree(), checkpoint); err != nil {
			return fmt.Errorf("save imported mirror checkpoint state: %w", err)
		}
		return nil
	case "fork":
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.tree.Size() != 0 {
			return fmt.Errorf("fork import requires an empty destination log")
		}
		tree := tlogx.NewTree()
		_, err := snapshot.ImportFork(r, s.store, &s.policy, func(rec schema.Record, index int64) error {
			if err := tlogx.WriteRecord(s.store, index, rec); err != nil {
				return err
			}
			leaf, err := tlogx.RecordToLeaf(rec)
			if err != nil {
				return err
			}
			if _, err := tree.AppendLeaf(leaf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
		s.tree = tree
		s.treeSize.Store(tree.Size())
		if _, err := s.reconcileDerivedLocked(ctx); err != nil {
			return fmt.Errorf("publish forked log: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("invalid mode %q (want mirror or fork)", mode)
	}
}

func verifyPublishedCheckpoint(ctx context.Context, store storage.Store, policy tlogx.Policy, leaves []tlogx.Leaf) error {
	data, err := store.Get(ctx, storage.CheckpointPath())
	if err != nil {
		if storage.IsNotFound(err) && len(leaves) == 0 {
			return nil
		}
		if storage.IsNotFound(err) {
			return fmt.Errorf("missing checkpoint for %d stored leaves", len(leaves))
		}
		return err
	}
	checkpoint, _, err := tlogx.VerifyCheckpoint(data, policy)
	if err != nil {
		return err
	}
	if checkpoint.N < 0 || checkpoint.N > int64(len(leaves)) {
		return fmt.Errorf("tree size %d is outside stored leaf range [0,%d]", checkpoint.N, len(leaves))
	}
	prefixTree, err := tlogx.NewTreeFromLeaves(leaves[:checkpoint.N])
	if err != nil {
		return err
	}
	if prefixTree.Root() != checkpoint.Hash {
		return fmt.Errorf("checkpoint root does not match the first %d stored leaves", checkpoint.N)
	}
	return nil
}

func withDefaults(cfg ServerConfig) ServerConfig {
	if cfg.Port == "" {
		cfg.Port = DefaultServerConfig().Port
	}
	if cfg.DataDir == "" {
		cfg.DataDir = DefaultServerConfig().DataDir
	}
	if cfg.LogOrigin == "" {
		cfg.LogOrigin = DefaultServerConfig().LogOrigin
	}
	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = DefaultServerConfig().FetchTimeout
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = DefaultServerConfig().RequestTimeout
	}
	if cfg.SubmissionLimit == 0 {
		cfg.SubmissionLimit = DefaultServerConfig().SubmissionLimit
	}
	if cfg.SubmissionWindow == 0 {
		cfg.SubmissionWindow = DefaultServerConfig().SubmissionWindow
	}
	return cfg
}

func openStore(ctx context.Context, cfg ServerConfig) (storage.Store, error) {
	if os.Getenv("EBI_STORAGE") != "" {
		return storage.NewFromEnv(ctx)
	}
	return storage.NewLocal(cfg.DataDir)
}

func buildPolicy(cfg ServerConfig, logKey string) (tlogx.Policy, error) {
	origin := cfg.LogOrigin
	if origin == "" {
		origin = DefaultServerConfig().LogOrigin
	}
	policy := tlogx.Policy{
		LogName:           origin,
		LogKeys:           []string{logKey},
		WitnessKeys:       cfg.WitnessKeys,
		RequiredWitnesses: cfg.RequiredWitnesses,
	}
	if cfg.PolicyPath != "" {
		loaded, err := tlogx.LoadPolicy(cfg.PolicyPath)
		if err != nil {
			return tlogx.Policy{}, err
		}
		policy = loaded
		policy.LogName = origin
		if !contains(policy.LogKeys, logKey) {
			policy.LogKeys = append(policy.LogKeys, logKey)
		}
		if cfg.RequiredWitnesses > 0 {
			policy.RequiredWitnesses = cfg.RequiredWitnesses
		}
		if len(cfg.WitnessKeys) > 0 {
			policy.WitnessKeys = cfg.WitnessKeys
		}
	}
	if err := validatePolicy(policy); err != nil {
		return tlogx.Policy{}, err
	}
	return policy, nil
}

func validatePolicy(p tlogx.Policy) error {
	if p.RequiredWitnesses < 0 {
		return fmt.Errorf("required witnesses cannot be negative")
	}
	if p.RequiredWitnesses > 0 && len(p.WitnessKeys) == 0 {
		return fmt.Errorf("required witnesses set but no witness keys configured")
	}
	if len(p.LogKeys) == 0 {
		return fmt.Errorf("at least one log key is required")
	}
	return nil
}

func contains(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

func verifyCheckpointState(ctx context.Context, store storage.Store, path string, policy tlogx.Policy, tree *tlogx.Tree) error {
	stateTree, signed, err := tlogx.LoadCheckpointState(path)
	if err != nil {
		return fmt.Errorf("load checkpoint state: %w", err)
	}
	got, _, err := tlogx.VerifyCheckpoint(signed, policy)
	if err != nil {
		return fmt.Errorf("verify checkpoint state: %w", err)
	}
	if stateTree.N != got.N || stateTree.Hash != got.Hash {
		return fmt.Errorf("checkpoint state file does not match signed tree")
	}
	if stateTree.N > tree.Size() {
		return fmt.Errorf("checkpoint state ahead of leaf index: %d > %d", stateTree.N, tree.Size())
	}
	if stateTree.N == tree.Size() && stateTree.Hash != tree.Root() {
		return fmt.Errorf("checkpoint state root mismatch")
	}
	if stateTree.N > 0 && stateTree.N < tree.Size() {
		proof, err := tree.TreeProof(stateTree.N)
		if err != nil {
			return fmt.Errorf("prove consistency: %w", err)
		}
		if err := tlogx.VerifyConsistency(tree.TlogTree(), stateTree, proof); err != nil {
			return fmt.Errorf("consistency proof: %w", err)
		}
	}
	return nil
}

func loadOrCreateLogKey(file, origin, envKey string) (*logKey, error) {
	if envKey != "" {
		seed, _, err := parseNoteSignerKey(envKey)
		if err != nil {
			return nil, fmt.Errorf("parse EBI_LOG_KEY: %w", err)
		}
		return newLogKey(seed, origin)
	}
	if _, err := os.Stat(file); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := saveSeed(file, seed); err != nil {
			return nil, err
		}
	}
	seed, err := loadSeed(file)
	if err != nil {
		return nil, err
	}
	return newLogKey(seed, origin)
}

func saveSeed(path string, seed []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".log-key-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.WriteString(hex.EncodeToString(seed)); err != nil {
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
	if err := os.Chmod(tmp, 0600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func loadSeed(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("key file is empty")
	}
	if len(data) == 64 {
		seed, err := hex.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("decode key: %w", err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid key seed size %d", len(seed))
		}
		return seed, nil
	}
	// If the file is not hex, try to parse it as a note signer key string.
	seed, _, err := parseNoteSignerKey(string(data))
	if err != nil {
		return nil, fmt.Errorf("key file must be hex seed or note signer key: %w", err)
	}
	return seed, nil
}

func newLogKey(seed []byte, name string) (*logKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid ed25519 seed size %d", len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	pubkey := append([]byte{1}, pub...)
	h := logKeyHash(name, pubkey)
	privkey := append([]byte{1}, seed...)
	skey := fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, h, base64.StdEncoding.EncodeToString(privkey))
	vkey := fmt.Sprintf("%s+%08x+%s", name, h, base64.StdEncoding.EncodeToString(pubkey))
	signer, err := note.NewSigner(skey)
	if err != nil {
		return nil, err
	}
	pubHex := hex.EncodeToString(pub)
	return &logKey{
		seed:        seed,
		name:        name,
		hash:        h,
		signer:      signer,
		verifierKey: vkey,
		publicKey:   pubHex,
		private:     priv,
		auditorID:   schema.AuditorHash(pubHex),
	}, nil
}

func parseNoteSignerKey(skey string) ([]byte, string, error) {
	parts := strings.Split(skey, "+")
	if len(parts) != 5 || parts[0] != "PRIVATE" || parts[1] != "KEY" {
		return nil, "", fmt.Errorf("malformed signer key")
	}
	name := parts[2]
	hash := parts[3]
	key64 := parts[4]
	if len(hash) != 8 {
		return nil, "", fmt.Errorf("invalid hash length")
	}
	key, err := base64.StdEncoding.DecodeString(key64)
	if err != nil {
		return nil, "", fmt.Errorf("decode key: %w", err)
	}
	if len(key) < 1 || key[0] != 1 || len(key[1:]) != 32 {
		return nil, "", fmt.Errorf("invalid ed25519 key")
	}
	_ = hash
	return key[1:], name, nil
}

func logKeyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}

func randomOwnerID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type leaseDoc struct {
	Owner  string    `json:"owner"`
	Expiry time.Time `json:"expiry"`
}

func (s *Server) acquireLease(ctx context.Context) error {
	data, err := s.store.Get(ctx, s.leasePath)
	if err != nil {
		if storage.IsNotFound(err) {
			swapped, err := s.compareAndSwapLease(ctx, nil, time.Now().Add(leaseDuration))
			if err != nil {
				return err
			}
			if !swapped {
				return fmt.Errorf("lease was acquired concurrently")
			}
			return nil
		}
		return err
	}
	var doc leaseDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("decode lease: %w", err)
	}
	if time.Now().Before(doc.Expiry) && doc.Owner != s.ownerID {
		return fmt.Errorf("lease held by %s until %s", doc.Owner, doc.Expiry.Format(time.RFC3339))
	}
	swapped, err := s.compareAndSwapLease(ctx, data, time.Now().Add(leaseDuration))
	if err != nil {
		return err
	}
	if !swapped {
		return fmt.Errorf("lease changed during acquisition")
	}
	return nil
}

func (s *Server) renewLease(ctx context.Context) error {
	data, err := s.store.Get(ctx, s.leasePath)
	if err != nil {
		return err
	}
	var current leaseDoc
	if err := json.Unmarshal(data, &current); err != nil {
		return fmt.Errorf("decode lease: %w", err)
	}
	if current.Owner != s.ownerID {
		return fmt.Errorf("lease ownership lost to %s", current.Owner)
	}
	swapped, err := s.compareAndSwapLease(ctx, data, time.Now().Add(leaseDuration))
	if err != nil {
		return err
	}
	if !swapped {
		return fmt.Errorf("lease changed during renewal")
	}
	return nil
}

func (s *Server) compareAndSwapLease(ctx context.Context, old []byte, expiry time.Time) (bool, error) {
	atomicStore, ok := s.store.(storage.AtomicStore)
	if !ok {
		return false, fmt.Errorf("storage backend does not support atomic leases")
	}
	doc := leaseDoc{Owner: s.ownerID, Expiry: expiry}
	b, err := json.Marshal(doc)
	if err != nil {
		return false, err
	}
	return atomicStore.CompareAndSwap(ctx, s.leasePath, old, storage.Object{
		Path:        s.leasePath,
		Data:        b,
		ContentType: "application/json",
	})
}

func (s *Server) releaseLease(ctx context.Context) error {
	data, err := s.store.Get(ctx, s.leasePath)
	if err != nil {
		if storage.IsNotFound(err) {
			return nil
		}
		return err
	}
	var current leaseDoc
	if err := json.Unmarshal(data, &current); err != nil {
		return err
	}
	if current.Owner != s.ownerID {
		return nil
	}
	atomicStore, ok := s.store.(storage.AtomicStore)
	if !ok {
		return fmt.Errorf("storage backend does not support atomic leases")
	}
	_, err = atomicStore.CompareAndDelete(ctx, s.leasePath, data)
	return err
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
