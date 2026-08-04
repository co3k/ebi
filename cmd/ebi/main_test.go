package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/co3k/ebi/internal/config"
	"github.com/co3k/ebi/internal/key"
	"github.com/co3k/ebi/pkg/analyze"
	"github.com/co3k/ebi/pkg/fetch"
	"github.com/co3k/ebi/pkg/llm"
	"github.com/co3k/ebi/pkg/prefixdb"
	"github.com/co3k/ebi/pkg/schema"
	"github.com/co3k/ebi/pkg/score"
	"github.com/co3k/ebi/pkg/secrets"
	"github.com/co3k/ebi/pkg/snapshot"
	"github.com/co3k/ebi/pkg/storage"
	"github.com/co3k/ebi/pkg/tlogx"
	"golang.org/x/mod/sumdb/tlog"
)

func TestParseRunFlagsURLAfterArgs(t *testing.T) {
	args := []string{"--yes", "https://example.com/script.sh", "--", "arg1", "arg2"}
	f, positional, scriptArgs, err := parseRunFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Yes {
		t.Fatal("expected --yes")
	}
	if len(positional) != 1 || positional[0] != "https://example.com/script.sh" {
		t.Fatalf("unexpected positional: %v", positional)
	}
	if len(scriptArgs) != 2 || scriptArgs[0] != "arg1" || scriptArgs[1] != "arg2" {
		t.Fatalf("unexpected script args: %v", scriptArgs)
	}
}

func TestParseRunFlagsURLBeforeFlags(t *testing.T) {
	args := []string{"https://example.com/script.sh", "--yes", "--", "a", "b"}
	f, positional, scriptArgs, err := parseRunFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Yes {
		t.Fatal("expected --yes")
	}
	if len(positional) != 1 || positional[0] != "https://example.com/script.sh" {
		t.Fatalf("unexpected positional: %v", positional)
	}
	if len(scriptArgs) != 2 || scriptArgs[0] != "a" || scriptArgs[1] != "b" {
		t.Fatalf("unexpected script args: %v", scriptArgs)
	}
}

func TestRunSubcommand(t *testing.T) {
	out := captureOutput(t, func() {
		_ = run([]string{"version"})
	})
	if !strings.Contains(out, "ebi") {
		t.Fatalf("expected version output, got %q", out)
	}
}

func TestKeySubcommand(t *testing.T) {
	tmp := t.TempDir()
	os.Setenv("EBI_HOME", tmp)
	defer os.Unsetenv("EBI_HOME")

	out := captureOutput(t, func() {
		_ = run([]string{"key", "init"})
	})
	if !strings.Contains(out, "key initialized") {
		t.Fatalf("expected key init, got %q", out)
	}
}

func TestPipeNoTTYExits10(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("skipping TTY test in CI")
	}
	if os.Getenv("EBI_TEST_SUBPROCESS") == "1" {
		os.Stdin.WriteString("echo hello\n")
		os.Exit(run([]string{"--yes"}))
	}
	bin := buildBinary(t)
	cmd := exec.Command(bin, "--yes")
	cmd.Env = append(os.Environ(), "EBI_TEST_SUBPROCESS=1", "HOME="+t.TempDir())
	cmd.Stdin = strings.NewReader("")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error")
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != exitNoTTY {
			t.Fatalf("expected exit %d, got %d: %s", exitNoTTY, exitErr.ExitCode(), out.String())
		}
	} else {
		t.Fatal(err)
	}
}

func TestPipeYesExecutes(t *testing.T) {
	if os.Getenv("EBI_TEST_SUBPROCESS") == "1" {
		os.Exit(run([]string{"--yes"}))
	}
	bin := buildBinary(t)
	cmd := exec.Command(bin, "--yes")
	cmd.Env = append(os.Environ(), "EBI_TEST_SUBPROCESS=1", "HOME="+t.TempDir())
	cmd.Stdin = strings.NewReader("#!/bin/sh\necho 'hello from child'\nexit 42\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 42 {
			t.Fatalf("expected child exit 42, got %d: %s", exitErr.ExitCode(), out.String())
		}
	} else {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "hello from child") {
		t.Fatalf("expected child output, got %s", out.String())
	}
}

func TestPipeDangerBlocked(t *testing.T) {
	if os.Getenv("EBI_TEST_SUBPROCESS") == "1" {
		os.Exit(run([]string{"--yes"}))
	}
	bin := buildBinary(t)
	cmd := exec.Command(bin, "--yes")
	cmd.Env = append(os.Environ(), "EBI_TEST_SUBPROCESS=1", "HOME="+t.TempDir())
	cmd.Stdin = strings.NewReader("#!/bin/sh\neval 'echo should-not-run'\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != exitFlagged {
			t.Fatalf("expected exit %d, got %d: %s", exitFlagged, exitErr.ExitCode(), out.String())
		}
	} else {
		t.Fatal(err)
	}
	if outputHasLine(out.String(), "should-not-run") {
		t.Fatalf("flagged script unexpectedly executed: %s", out.String())
	}
}

func TestPipeForceFlagged(t *testing.T) {
	if os.Getenv("EBI_TEST_SUBPROCESS") == "1" {
		os.Exit(run([]string{"--yes", "--force-flagged"}))
	}
	bin := buildBinary(t)
	cmd := exec.Command(bin, "--yes", "--force-flagged")
	cmd.Env = append(os.Environ(), "EBI_TEST_SUBPROCESS=1", "HOME="+t.TempDir())
	cmd.Stdin = strings.NewReader("#!/bin/sh\neval 'echo forced'\nexit 0\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		t.Fatalf("expected success, got %v: %s", err, out.String())
	}
	if !outputHasLine(out.String(), "forced") {
		t.Fatalf("expected forced output, got %s", out.String())
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "ebi")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", bin, "./cmd/ebi")
	cmd.Dir = moduleRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "env", "GOMOD")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("locate module root: %v\n%s", err, out)
	}
	goMod := strings.TrimSpace(string(out))
	if goMod == "" || goMod == os.DevNull {
		t.Fatalf("locate module root: go env GOMOD returned %q", goMod)
	}
	info, err := os.Stat(goMod)
	if err != nil {
		t.Fatalf("locate module root: stat %q: %v", goMod, err)
	}
	if info.IsDir() {
		t.Fatalf("locate module root: GOMOD path %q is a directory", goMod)
	}
	return filepath.Dir(goMod)
}

func outputHasLine(output, want string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return true
		}
	}
	return false
}

func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestExitCodes(t *testing.T) {
	if exitNoTTY != 10 || exitFlagged != 11 || exitVerifyFail != 12 || exitFetchFail != 13 || exitInternal != 14 {
		t.Fatal("exit codes changed")
	}
}

func TestBuildLocalRecordsSeparatesStaticAndLLMAnalyzers(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("EBI_HOME", tmp)
	k := testKey(t)
	fetched := &fetch.Fetched{
		Hash:          strings.Repeat("a", 64),
		Size:          12,
		URL:           "https://example.com/install.sh",
		NormalizedURL: "https://example.com/install.sh",
	}
	staticClaim := schema.Claim{
		Category:   "net.fetch",
		Line:       1,
		LineSHA256: strings.Repeat("b", 64),
	}
	llmClaim := schema.Claim{
		Category:   "priv.sudo",
		Line:       2,
		LineSHA256: strings.Repeat("c", 64),
	}
	records, err := buildLocalRecords(k, fetched, &analyze.Result{
		Claims: []schema.Claim{staticClaim},
	}, &llm.Result{
		Verdict:      schema.VerdictDanger,
		Claims:       []schema.Claim{llmClaim},
		Model:        "qwen2.5-coder",
		ModelFamily:  "qwen",
		Agreement:    1,
		PromptHash:   strings.Repeat("d", 64),
		Backend:      "ollama",
		Quantization: "q4_k_m",
		Runs:         5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected static and LLM records, got %d", len(records))
	}
	if records[0].Body.Analyzer.Kind != schema.KindStatic ||
		len(records[0].Body.Claims) != 1 ||
		records[0].Body.Claims[0].Category != staticClaim.Category {
		t.Fatalf("unexpected static record: %+v", records[0].Body)
	}
	if records[1].Body.Analyzer.Kind != schema.KindLLM ||
		len(records[1].Body.Claims) != 1 ||
		records[1].Body.Claims[0].Category != llmClaim.Category {
		t.Fatalf("unexpected LLM record: %+v", records[1].Body)
	}
	for _, rec := range records {
		if _, _, err := schema.Verify(rec); err != nil {
			t.Fatalf("generated record did not verify: %v", err)
		}
	}
}

func TestSecretLineRedactsDisplayedClaims(t *testing.T) {
	claims := []schema.Claim{
		{Line: 1, Excerpt: "safe"},
		{Line: 2, Excerpt: "ghp_should_not_be_visible"},
	}
	redactClaimExcerpts(claims, []secrets.Finding{{Line: 2, RuleID: "github-pat"}})
	if claims[0].Excerpt != "safe" || claims[1].Excerpt != "[REDACTED]" {
		t.Fatalf("unexpected excerpt redaction: %+v", claims)
	}
}

func TestShowDiffRedactsSecretLines(t *testing.T) {
	oldPath := filepath.Join(t.TempDir(), "old.sh")
	newPath := filepath.Join(t.TempDir(), "new.sh")
	const secret = "ghp_1234567890abcdef1234567890abcdef1234"
	if err := os.WriteFile(oldPath, []byte("echo safe\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("export GITHUB_TOKEN="+secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out := captureOutput(t, func() { showDiff(oldPath, newPath) })
	if strings.Contains(out, secret) {
		t.Fatalf("diff leaked secret text: %s", out)
	}
	if !strings.Contains(out, "+1: [REDACTED]") {
		t.Fatalf("diff did not redact the secret line: %s", out)
	}
}

func TestMirrorURLRequiresHTTPS(t *testing.T) {
	if got := mirrorURL(config.Config{MirrorURL: "http://mirror.example"}); got != "" {
		t.Fatalf("accepted insecure mirror URL: %q", got)
	}
	if got := mirrorURL(config.Config{MirrorURL: "https://user@example.com"}); got != "" {
		t.Fatalf("accepted mirror URL credentials: %q", got)
	}
	if got := mirrorURL(config.Config{MirrorURL: "https://mirror.example/"}); got != "https://mirror.example" {
		t.Fatalf("unexpected normalized mirror URL: %q", got)
	}
}

func TestIsNetworkErrorIncludesConnectionFailures(t *testing.T) {
	for _, err := range []error{
		&url.Error{Op: "Get", URL: "https://mirror.example", Err: errors.New("connection refused")},
		&net.DNSError{Name: "missing.invalid", Err: "no such host"},
	} {
		if !isNetworkError(err) {
			t.Fatalf("expected network error classification for %T: %v", err, err)
		}
	}
	if isNetworkError(errors.New("invalid checkpoint signature")) {
		t.Fatal("classified integrity error as a network error")
	}
}

func TestFetchMirrorBytesUsesBoundedClientTimeout(t *testing.T) {
	orig := mirrorHTTPClient
	mirrorHTTPClient = &http.Client{Timeout: 20 * time.Millisecond}
	defer func() { mirrorHTTPClient = orig }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("late"))
	}))
	defer srv.Close()

	start := time.Now()
	_, _, err := fetchMirrorBytes(t.Context(), srv.URL, "v1/checkpoint")
	if err == nil || !isNetworkError(err) {
		t.Fatalf("expected bounded network timeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("mirror request ignored client timeout: %v", elapsed)
	}
}

func testKey(t *testing.T) *key.Key {
	t.Helper()
	k, err := key.LoadOrCreate()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return k
}

func makeTestRecord(t *testing.T, k *key.Key, targetHash string) schema.Record {
	t.Helper()
	body := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: time.Now().UTC().Unix(),
		Auditor:   k.AuditorID(),
		Target:    schema.Target{URL: "https://example.com/test", SHA256: targetHash, Size: 1},
		Analyzer:  schema.Analyzer{Kind: schema.KindStatic},
		Verdict:   schema.VerdictOK,
	}
	rec, err := schema.Sign(body, k.Private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return *rec
}

func sortRecordsByID(t *testing.T, records []schema.Record) {
	t.Helper()
	sort.Slice(records, func(i, j int) bool {
		idi, err := schema.RecordID(records[i].Body)
		if err != nil {
			t.Fatalf("record id: %v", err)
		}
		idj, err := schema.RecordID(records[j].Body)
		if err != nil {
			t.Fatalf("record id: %v", err)
		}
		return idi < idj
	})
}

func buildTestLogStore(t *testing.T, records []schema.Record) (storage.Store, tlogx.Policy, []schema.Record) {
	t.Helper()
	ctx := context.Background()
	store := storage.NewMem()
	sortRecordsByID(t, records)

	tree := tlogx.NewTree()
	for _, rec := range records {
		leaf, err := tlogx.RecordToLeaf(rec)
		if err != nil {
			t.Fatalf("record to leaf: %v", err)
		}
		index, err := tree.AppendLeaf(leaf)
		if err != nil {
			t.Fatalf("append leaf: %v", err)
		}
		if err := tlogx.WriteRecord(store, index, rec); err != nil {
			t.Fatalf("write record: %v", err)
		}
	}
	if err := tlogx.WriteTiles(tree, store, tlogx.DefaultTileHeight); err != nil {
		t.Fatalf("write tiles: %v", err)
	}

	logSigner, _, _, logVerifierKey, err := tlogx.GenerateKeyPair("ebi.example.com")
	if err != nil {
		t.Fatalf("generate log key: %v", err)
	}
	if err := tlogx.WriteCheckpoint(tree.TlogTree(), "ebi.example.com", logSigner, store); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}

	shards, err := prefixdb.BuildShards(records)
	if err != nil {
		t.Fatalf("build shards: %v", err)
	}
	for prefix, data := range shards {
		if err := store.Put(ctx, storage.Object{Path: "v1/prefix/" + prefix, Data: data, Immutable: true}); err != nil {
			t.Fatalf("write prefix: %v", err)
		}
	}

	policy := tlogx.Policy{LogName: "ebi.example.com", LogKeys: []string{logVerifierKey}}
	return store, policy, records
}

func mirrorHandler(store storage.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		path := strings.TrimPrefix(r.URL.Path, "/")
		data, err := store.Get(ctx, path)
		if err != nil {
			if storage.IsNotFound(err) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(data)
	})
}

func startMirrorServer(t *testing.T, store storage.Store) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(mirrorHandler(store))
	t.Cleanup(srv.Close)
	return srv
}

func writePolicy(t *testing.T, policy tlogx.Policy) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.toml")
	if err := tlogx.SavePolicy(path, policy); err != nil {
		t.Fatalf("save policy: %v", err)
	}
	return path
}

func writeCheckpointState(t *testing.T, store storage.Store, tree tlog.Tree) string {
	t.Helper()
	ctx := context.Background()
	cp, err := store.Get(ctx, storage.CheckpointPath())
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	path := filepath.Join(t.TempDir(), "checkpoint-state.toml")
	if err := tlogx.SaveCheckpointState(path, tree, cp); err != nil {
		t.Fatalf("save checkpoint state: %v", err)
	}
	return path
}

func TestVerifyLocalRecord(t *testing.T) {
	tmp := t.TempDir()
	os.Setenv("EBI_HOME", tmp)
	defer os.Unsetenv("EBI_HOME")

	k := testKey(t)
	targetHash := strings.Repeat("aa", 32)
	rec := makeTestRecord(t, k, targetHash)

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(tmp, "record.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	bin := buildBinary(t)
	cmd := exec.Command(bin, "verify", path)
	cmd.Env = append(os.Environ(), "EBI_HOME="+tmp)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "verified: true") {
		t.Fatalf("expected verified: true, got %s", out)
	}
}

func TestVerifySnapshot(t *testing.T) {
	tmp := t.TempDir()
	os.Setenv("EBI_HOME", tmp)
	defer os.Unsetenv("EBI_HOME")

	k := testKey(t)
	targetHash := strings.Repeat("bb", 32)
	rec := makeTestRecord(t, k, targetHash)
	store, policy, records := buildTestLogStore(t, []schema.Record{rec})

	cp, err := store.Get(context.Background(), storage.CheckpointPath())
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	var buf bytes.Buffer
	meta, err := snapshot.Create(context.Background(), store, int64(len(records)), string(cp), &buf)
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	path := filepath.Join(tmp, "snapshot.tar.zst")
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}

	policyPath := writePolicy(t, policy)

	bin := buildBinary(t)
	cmd := exec.Command(bin, "verify", "--policy", policyPath, path)
	cmd.Env = append(os.Environ(), "EBI_HOME="+tmp)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify snapshot failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "verified: true") {
		t.Fatalf("expected verified: true, got %s", out)
	}
	_ = meta
}

func TestVerifyRemoteRecordSuccess(t *testing.T) {
	tmp := t.TempDir()
	os.Setenv("EBI_HOME", tmp)
	defer os.Unsetenv("EBI_HOME")

	k := testKey(t)
	targetHash := strings.Repeat("cc", 32)
	rec := makeTestRecord(t, k, targetHash)
	store, policy, records := buildTestLogStore(t, []schema.Record{rec})

	srv := startMirrorServer(t, store)
	policyPath := writePolicy(t, policy)
	cpPath := writeCheckpointState(t, store, tlogx.NewTree().TlogTree())

	recordID, err := schema.RecordID(rec.Body)
	if err != nil {
		t.Fatalf("record id: %v", err)
	}
	_ = records

	bin := buildBinary(t)
	cmd := exec.Command(bin, "verify", "--mirror", srv.URL, "--policy", policyPath, "--checkpoint", cpPath, recordID)
	cmd.Env = append(os.Environ(), "EBI_HOME="+tmp)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify remote failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "verified: true") {
		t.Fatalf("expected verified: true, got %s", out)
	}
}

func TestLookupCommunityRecordsLoadsDeltaPredecessor(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("EBI_HOME", tmp)
	k := testKey(t)
	oldHash := strings.Repeat("1a", 32)
	newHash := strings.Repeat("2b", 32)
	oldRecord := makeTestRecord(t, k, oldHash)
	newRecord := makeTestRecord(t, k, newHash)
	newRecord.Body.PrevSHA256 = oldHash
	newRecordPtr, err := schema.Sign(newRecord.Body, k.Private)
	if err != nil {
		t.Fatal(err)
	}
	newRecord = *newRecordPtr

	store, policy, _ := buildTestLogStore(t, []schema.Record{oldRecord, newRecord})
	srv := startMirrorServer(t, store)
	cfg := config.Config{
		MirrorURL:      srv.URL,
		PolicyPath:     writePolicy(t, policy),
		CheckpointPath: filepath.Join(tmp, "checkpoint-state.toml"),
	}
	lookup, err := lookupCommunityRecords(t.Context(), newHash, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(lookup.Records) != 1 || lookup.Records[0].Body.Target.SHA256 != newHash {
		t.Fatalf("current records: %+v", lookup.Records)
	}
	if len(lookup.PriorRecords) != 1 || lookup.PriorRecords[0].Body.Target.SHA256 != oldHash {
		t.Fatalf("prior records: %+v", lookup.PriorRecords)
	}
	report := score.Compute(score.Input{
		TargetHash:   newHash,
		Records:      lookup.Records,
		PriorRecords: lookup.PriorRecords,
		Trust: map[string]float64{
			lookup.Records[0].AuditorID: 1,
		},
	})
	if !report.DeltaInheritance {
		t.Fatal("expected locally verified delta inheritance")
	}
}

func TestVerifyRemoteRecordTamperedCheckpoint(t *testing.T) {
	tmp := t.TempDir()
	os.Setenv("EBI_HOME", tmp)
	defer os.Unsetenv("EBI_HOME")

	k := testKey(t)
	targetHash := strings.Repeat("dd", 32)
	rec := makeTestRecord(t, k, targetHash)
	store, policy, records := buildTestLogStore(t, []schema.Record{rec})

	// Tamper with the checkpoint in the store.
	ctx := context.Background()
	cp, err := store.Get(ctx, storage.CheckpointPath())
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	bad := make([]byte, len(cp))
	copy(bad, cp)
	bad[0] ^= 0xff
	if err := store.Put(ctx, storage.Object{Path: storage.CheckpointPath(), Data: bad}); err != nil {
		t.Fatalf("put checkpoint: %v", err)
	}

	srv := startMirrorServer(t, store)
	policyPath := writePolicy(t, policy)
	cpPath := writeCheckpointState(t, store, tlogx.NewTree().TlogTree())

	recordID, err := schema.RecordID(rec.Body)
	if err != nil {
		t.Fatalf("record id: %v", err)
	}
	_ = records

	bin := buildBinary(t)
	cmd := exec.Command(bin, "verify", "--mirror", srv.URL, "--policy", policyPath, "--checkpoint", cpPath, recordID)
	cmd.Env = append(os.Environ(), "EBI_HOME="+tmp)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected tampered checkpoint to fail, got %s", out)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != exitVerifyFail {
		t.Fatalf("expected exit %d, got %v: %s", exitVerifyFail, err, out)
	}
}

func TestVerifyRemoteRecordTamperedBlob(t *testing.T) {
	tmp := t.TempDir()
	os.Setenv("EBI_HOME", tmp)
	defer os.Unsetenv("EBI_HOME")

	k := testKey(t)
	targetHash := strings.Repeat("ee", 32)
	rec := makeTestRecord(t, k, targetHash)
	store, policy, records := buildTestLogStore(t, []schema.Record{rec})

	recordID, err := schema.RecordID(rec.Body)
	if err != nil {
		t.Fatalf("record id: %v", err)
	}
	ctx := context.Background()
	blob, err := store.Get(ctx, "v1/blob/"+recordID)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	bad := make([]byte, len(blob))
	copy(bad, blob)
	for i := range bad {
		if bad[i] != ' ' {
			bad[i] ^= 0xff
			break
		}
	}
	if err := store.Put(ctx, storage.Object{Path: "v1/blob/" + recordID, Data: bad, Immutable: true}); err != nil {
		t.Fatalf("put blob: %v", err)
	}

	srv := startMirrorServer(t, store)
	policyPath := writePolicy(t, policy)
	cpPath := writeCheckpointState(t, store, tlogx.NewTree().TlogTree())
	_ = records

	bin := buildBinary(t)
	cmd := exec.Command(bin, "verify", "--mirror", srv.URL, "--policy", policyPath, "--checkpoint", cpPath, recordID)
	cmd.Env = append(os.Environ(), "EBI_HOME="+tmp)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected tampered blob to fail, got %s", out)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != exitVerifyFail {
		t.Fatalf("expected exit %d, got %v: %s", exitVerifyFail, err, out)
	}
}

func TestVerifyRemoteRecordMissingInclusion(t *testing.T) {
	tmp := t.TempDir()
	os.Setenv("EBI_HOME", tmp)
	defer os.Unsetenv("EBI_HOME")

	k := testKey(t)
	targetHash := strings.Repeat("ff", 32)
	rec1 := makeTestRecord(t, k, targetHash)
	rec2 := makeTestRecord(t, k, strings.Repeat("f0", 32))
	store, policy, records := buildTestLogStore(t, []schema.Record{rec1, rec2})

	recordID, err := schema.RecordID(rec1.Body)
	if err != nil {
		t.Fatalf("record id: %v", err)
	}
	// Remove the tile data so the inclusion proof cannot be constructed.
	ctx := context.Background()
	tiles, err := store.List(ctx, "v1/tile")
	if err != nil {
		t.Fatalf("list tiles: %v", err)
	}
	for _, tile := range tiles {
		if err := store.Delete(ctx, tile); err != nil {
			t.Fatalf("delete tile %s: %v", tile, err)
		}
	}

	srv := startMirrorServer(t, store)
	policyPath := writePolicy(t, policy)
	cpPath := writeCheckpointState(t, store, tlogx.NewTree().TlogTree())
	_ = records

	bin := buildBinary(t)
	cmd := exec.Command(bin, "verify", "--mirror", srv.URL, "--policy", policyPath, "--checkpoint", cpPath, recordID)
	cmd.Env = append(os.Environ(), "EBI_HOME="+tmp)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected missing inclusion to fail, got %s", out)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != exitVerifyFail {
		t.Fatalf("expected exit %d, got %v: %s", exitVerifyFail, err, out)
	}
}

func TestRunKeepRetainsTemp(t *testing.T) {
	tmp := t.TempDir()
	os.Setenv("EBI_HOME", tmp)
	defer os.Unsetenv("EBI_HOME")

	script := "#!/bin/sh\necho 'ok'\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(script))
	}))
	defer srv.Close()

	bin := buildBinary(t)
	cmd := exec.Command(bin, "run", "--yes", "--keep", srv.URL)
	cmd.Env = append(os.Environ(), "EBI_HOME="+tmp)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	outStr := string(out)
	if !strings.Contains(outStr, "retained:") {
		t.Fatalf("expected retained path in output, got %s", outStr)
	}
}

func TestVerifyFlagsOverrideConfig(t *testing.T) {
	tmp := t.TempDir()
	os.Setenv("EBI_HOME", tmp)
	defer os.Unsetenv("EBI_HOME")

	k := testKey(t)
	targetHash := strings.Repeat("99", 32)
	rec := makeTestRecord(t, k, targetHash)
	store, policy, records := buildTestLogStore(t, []schema.Record{rec})

	srv := startMirrorServer(t, store)

	// Create a config with a bad mirror URL.
	cfgPath := filepath.Join(tmp, "config.toml")
	badConfig := `mirror_url = "http://127.0.0.1:1/"
opt_in = false
`
	if err := os.WriteFile(cfgPath, []byte(badConfig), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	policyPath := writePolicy(t, policy)
	cpPath := writeCheckpointState(t, store, tlogx.NewTree().TlogTree())

	recordID, err := schema.RecordID(rec.Body)
	if err != nil {
		t.Fatalf("record id: %v", err)
	}
	_ = records

	bin := buildBinary(t)
	cmd := exec.Command(bin, "verify", "--mirror", srv.URL, "--policy", policyPath, "--checkpoint", cpPath, recordID)
	cmd.Env = append(os.Environ(), "EBI_HOME="+tmp)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify with flags failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "verified: true") {
		t.Fatalf("expected verified: true, got %s", out)
	}
}
