// Command ebi-server is the transparency server for ebi.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/co3k/ebi/pkg/snapshot"
	"github.com/co3k/ebi/pkg/tlogx"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "snapshot":
			snapshotCmd(os.Args[2:])
			return
		case "import":
			importCmd(os.Args[2:])
			return
		case "tombstone":
			tombstoneCmd(os.Args[2:])
			return
		case "healthcheck":
			healthcheckCmd(os.Args[2:])
			return
		case "init-policy":
			initPolicyCmd(os.Args[2:])
			return
		}
	}
	runServer()
}

func runServer() {
	cfg, err := serverConfigFromFlags(flag.CommandLine, os.Args[1:])
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	s, err := NewServer(ctx, cfg)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	if err := s.StartSequencer(ctx); err != nil {
		log.Fatalf("sequencer: %v", err)
	}
	if err := s.StartHTTP(ctx); err != nil {
		log.Fatalf("http: %v", err)
	}
	log.Printf("server listening on %s", s.Addr())

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func initPolicyCmd(args []string) {
	fs := flag.NewFlagSet("init-policy", flag.ExitOnError)
	output := fs.String("output", "", "path to write the generated trust policy")
	cfg, err := serverConfigFromFlags(fs, args)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *output == "" {
		*output = filepath.Join(cfg.DataDir, "trust-policy.toml")
	}
	key, err := loadOrCreateLogKey(cfg.LogKeyFile, cfg.LogOrigin, cfg.LogKey)
	if err != nil {
		log.Fatalf("log key: %v", err)
	}
	// The output policy is being initialized here, so do not try to load a
	// pre-existing --policy path while constructing it.
	cfg.PolicyPath = ""
	policy, err := buildPolicy(cfg, key.verifierKey)
	if err != nil {
		log.Fatalf("policy: %v", err)
	}
	if err := tlogx.SavePolicy(*output, policy); err != nil {
		log.Fatalf("write policy: %v", err)
	}
	log.Printf("policy initialized at %s (log verifier: %s)", *output, key.verifierKey)
}

func healthcheckCmd(args []string) {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	url := fs.String("url", envString("EBI_HEALTHCHECK_URL", "http://127.0.0.1:8080/healthz"), "health endpoint URL")
	timeout := fs.Duration("timeout", 5*time.Second, "healthcheck timeout")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("healthcheck: %v", err)
	}
	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get(*url)
	if err != nil {
		log.Fatalf("healthcheck: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("healthcheck: HTTP %d", resp.StatusCode)
	}
}

func snapshotCmd(args []string) {
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	output := fs.String("output", "", "path to write the tar.zst snapshot")
	publish := fs.Bool("publish", false, "publish the archive and latest.json to configured storage")
	publicBaseURL := fs.String("public-base-url", "", "public static-store base URL used in latest.json")
	mirrorURLs := fs.String("mirror-urls", "", "comma-separated equivalent snapshot archive URLs")
	cfg, err := serverConfigFromFlags(fs, args)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *output == "" && !*publish {
		log.Fatalf("at least one of --output or --publish is required")
	}
	if *publish && *publicBaseURL == "" {
		log.Fatalf("--public-base-url is required with --publish")
	}
	ctx := context.Background()
	s, err := NewServer(ctx, cfg)
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	defer s.Shutdown(ctx)

	var meta *snapshot.Metadata
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			log.Fatalf("create output: %v", err)
		}
		meta, err = s.CreateSnapshot(ctx, f)
		closeErr := f.Close()
		if err != nil {
			log.Fatalf("snapshot: %v", err)
		}
		if closeErr != nil {
			log.Fatalf("close output: %v", closeErr)
		}
	}
	if *publish {
		meta, err = s.PublishSnapshot(ctx, *publicBaseURL, splitKeys(*mirrorURLs))
		if err != nil {
			log.Fatalf("publish snapshot: %v", err)
		}
	}
	log.Printf("snapshot: compressed_size=%d content_size=%d sha256=%s tree_size=%d",
		meta.CompressedSize, meta.Size, meta.SHA256, meta.TreeSize)
}

func importCmd(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	mode := fs.String("mode", "mirror", "import mode: mirror or fork")
	cfg, err := serverConfigFromFlags(fs, args)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if fs.NArg() != 1 {
		log.Fatalf("usage: ebi-server import [--mode=...] <snapshot.tar.zst>")
	}
	if *mode != "mirror" && *mode != "fork" {
		log.Fatalf("invalid mode %q", *mode)
	}
	ctx := context.Background()
	s, err := NewServer(ctx, cfg)
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	if err := s.StartSequencer(ctx); err != nil {
		log.Fatalf("sequencer: %v", err)
	}
	defer s.Shutdown(ctx)

	f, err := os.Open(fs.Arg(0))
	if err != nil {
		log.Fatalf("open snapshot: %v", err)
	}
	defer f.Close()
	if err := s.ImportSnapshot(ctx, f, *mode); err != nil {
		log.Fatalf("import: %v", err)
	}
	log.Printf("import: %s completed", *mode)
}

func tombstoneCmd(args []string) {
	fs := flag.NewFlagSet("tombstone", flag.ExitOnError)
	recordID := fs.String("record-id", "", "record ID to tombstone")
	cfg, err := serverConfigFromFlags(fs, args)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *recordID == "" {
		log.Fatalf("--record-id is required")
	}
	ctx := context.Background()
	s, err := NewServer(ctx, cfg)
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	if err := s.StartSequencer(ctx); err != nil {
		log.Fatalf("sequencer: %v", err)
	}
	defer s.Shutdown(ctx)

	res, err := s.Tombstone(ctx, *recordID)
	if err != nil {
		log.Fatalf("tombstone: %v", err)
	}
	if res.err != nil {
		log.Fatalf("tombstone: %v", res.err)
	}
	log.Printf("tombstone: record_id=%s tombstone_id=%s", *recordID, res.recordID)
}

func serverConfigFromFlags(fs *flag.FlagSet, args []string) (ServerConfig, error) {
	cfg := DefaultServerConfig()

	port := fs.String("port", envString("EBI_PORT", cfg.Port), "HTTP port")
	dataDir := fs.String("data-dir", envString("EBI_DATA_DIR", cfg.DataDir), "local storage root")
	logKeyFile := fs.String("log-key-file", envString("EBI_LOG_KEY_FILE", ""), "path to persisted log signer key")
	logOrigin := fs.String("log-origin", envString("EBI_LOG_ORIGIN", cfg.LogOrigin), "log origin")
	policyPath := fs.String("policy", envString("EBI_POLICY", ""), "path to trust policy file")
	checkpointState := fs.String("checkpoint-state", envString("EBI_CHECKPOINT_STATE", ""), "path to checkpoint state file")
	fetchTimeout := fs.Duration("fetch-timeout", envDuration("EBI_FETCH_TIMEOUT", cfg.FetchTimeout), "per-fetch timeout")
	requestTimeout := fs.Duration("request-timeout", envDuration("EBI_REQUEST_TIMEOUT", cfg.RequestTimeout), "per-request timeout")
	witnessKeys := fs.String("witness-keys", envString("EBI_WITNESS_KEYS", ""), "comma-separated witness verifier keys")
	witnessURLs := fs.String("witness-urls", envString("EBI_WITNESS_URLS", ""), "comma-separated witness submission URL prefixes")
	requiredWitnesses := fs.Int("required-witnesses", envInt("EBI_REQUIRED_WITNESSES", 0), "required witness quorum")

	if err := fs.Parse(args); err != nil {
		return ServerConfig{}, err
	}

	cfg.Port = *port
	cfg.DataDir = *dataDir
	cfg.LogKeyFile = *logKeyFile
	cfg.LogOrigin = *logOrigin
	cfg.PolicyPath = *policyPath
	cfg.CheckpointState = *checkpointState
	cfg.FetchTimeout = *fetchTimeout
	cfg.RequestTimeout = *requestTimeout
	cfg.WitnessKeys = splitKeys(*witnessKeys)
	cfg.WitnessURLs = splitKeys(*witnessURLs)
	cfg.RequiredWitnesses = *requiredWitnesses
	cfg.LogKey = os.Getenv("EBI_LOG_KEY")

	if cfg.LogKeyFile == "" {
		cfg.LogKeyFile = filepath.Join(cfg.DataDir, "log-key")
	}
	if cfg.CheckpointState == "" {
		cfg.CheckpointState = filepath.Join(cfg.DataDir, "checkpoint-state")
	}

	if cfg.LogKey != "" && cfg.LogKeyFile != "" {
		// EBI_LOG_KEY takes precedence; do not require a key file.
	}

	return cfg, nil
}

func envString(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envDuration(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return def
	}
	return n
}

func splitKeys(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, k := range strings.Split(s, ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}
