// Command ebi is the main CLI for the ebi script-auditing system.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/co3k/ebi/internal/config"
	"github.com/co3k/ebi/internal/contrib"
	"github.com/co3k/ebi/internal/key"
	"github.com/co3k/ebi/pkg/analyze"
	"github.com/co3k/ebi/pkg/appmeta"
	"github.com/co3k/ebi/pkg/fetch"
	"github.com/co3k/ebi/pkg/llm"
	"github.com/co3k/ebi/pkg/schema"
	"github.com/co3k/ebi/pkg/score"
	"github.com/co3k/ebi/pkg/secrets"
	"github.com/co3k/ebi/pkg/snapshot"
	"github.com/co3k/ebi/pkg/storage"
	"github.com/co3k/ebi/pkg/tui"
)

const (
	exitOK         = 0
	exitNoTTY      = 10
	exitFlagged    = 11
	exitVerifyFail = 12
	exitFetchFail  = 13
	exitInternal   = 14
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		return doPipe(args)
	}
	switch args[0] {
	case "run":
		return doRun(args[1:])
	case "audit":
		return doAudit(args[1:])
	case "verify":
		return doVerify(args[1:])
	case "key":
		return doKey(args[1:])
	case "contribute":
		return doContribute(args[1:])
	case "version":
		fmt.Println(appmeta.AppName, appmeta.Version)
		return exitOK
	default:
		// No subcommand: treat as pipe mode.
		return doPipe(args)
	}
}

type runFlags struct {
	Yes            bool
	ForceFlagged   bool
	KeepTemp       bool
	LLM            bool
	OptIn          bool
	SourceURL      string
	ServerURLs     []string
	PolicyPath     string
	CheckpointPath string
	MirrorURL      string
	LLMRuns        int
}

func parseRunFlags(args []string) (runFlags, []string, []string, error) {
	var f runFlags
	var positional []string
	var afterSeparator []string
	seenSep := false
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			seenSep = true
			i++
			for i < len(args) {
				afterSeparator = append(afterSeparator, args[i])
				i++
			}
			break
		}
		if seenSep {
			afterSeparator = append(afterSeparator, a)
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			handled, err := parseFlag(&f, &i, args)
			if err != nil {
				return f, nil, nil, err
			}
			if !handled {
				return f, nil, nil, fmt.Errorf("unknown flag: %s", a)
			}
			continue
		}
		positional = append(positional, a)
		i++
	}
	return f, positional, afterSeparator, nil
}

func parseFlag(f *runFlags, i *int, args []string) (bool, error) {
	switch args[*i] {
	case "--yes":
		f.Yes = true
	case "--force-flagged":
		f.ForceFlagged = true
	case "--keep":
		f.KeepTemp = true
	case "--llm":
		f.LLM = true
	case "--llm-runs":
		if *i+1 >= len(args) {
			return true, fmt.Errorf("--llm-runs requires a value")
		}
		*i++
		if _, err := fmt.Sscanf(args[*i], "%d", &f.LLMRuns); err != nil || f.LLMRuns <= 0 {
			return true, fmt.Errorf("--llm-runs must be a positive integer")
		}
	case "--contribute":
		f.OptIn = true
	case "--source-url":
		if *i+1 >= len(args) {
			return true, fmt.Errorf("--source-url requires a value")
		}
		*i++
		f.SourceURL = args[*i]
	case "--policy":
		if *i+1 >= len(args) {
			return true, fmt.Errorf("--policy requires a value")
		}
		*i++
		f.PolicyPath = args[*i]
	case "--checkpoint":
		if *i+1 >= len(args) {
			return true, fmt.Errorf("--checkpoint requires a value")
		}
		*i++
		f.CheckpointPath = args[*i]
	case "--mirror":
		if *i+1 >= len(args) {
			return true, fmt.Errorf("--mirror requires a value")
		}
		*i++
		f.MirrorURL = args[*i]
	default:
		return false, nil
	}
	*i++
	return true, nil
}

// resolveConfig loads configuration and applies precedence: flags > env > config.
// The env vars are already merged into the config by config.Load, so only flags
// need to override.
func resolveConfig(f runFlags) (config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return cfg, err
	}
	if f.PolicyPath != "" {
		cfg.PolicyPath = f.PolicyPath
	}
	if f.CheckpointPath != "" {
		cfg.CheckpointPath = f.CheckpointPath
	}
	if f.MirrorURL != "" {
		cfg.MirrorURL = f.MirrorURL
	}
	if len(f.ServerURLs) > 0 {
		cfg.ServerURLs = f.ServerURLs
	}
	return cfg, nil
}

func doPipe(args []string) int {
	f, positional, scriptArgs, err := parseRunFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitInternal
	}
	if len(positional) != 0 {
		fmt.Fprintln(os.Stderr, "pipe mode does not accept positional arguments before --")
		return exitInternal
	}
	return executeFlow("", os.Stdin, f, scriptArgs)
}

func doRun(args []string) int {
	f, positional, scriptArgs, err := parseRunFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitInternal
	}
	if len(positional) != 1 {
		fmt.Fprintln(os.Stderr, "usage: ebi run URL [flags] [-- args...]")
		return exitInternal
	}
	return executeFlow(positional[0], nil, f, scriptArgs)
}

func executeFlow(rawURL string, stdin io.Reader, f runFlags, scriptArgs []string) int {
	ctx := context.Background()

	// Acquire exact bytes.
	var fetched *fetch.Fetched
	var err error
	if rawURL != "" {
		opts := fetch.DefaultOptions()
		opts.AllowHTTP = true
		fetched, err = fetch.FetchURL(ctx, rawURL, opts)
	} else if stdin != nil {
		fetched, err = fetch.FetchStdin(ctx, stdin, fetch.DefaultOptions())
	} else {
		fmt.Fprintln(os.Stderr, "no input")
		return exitInternal
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch: %v\n", err)
		return exitFetchFail
	}
	defer func() {
		if f.KeepTemp && fetched != nil && fetched.Path != "" {
			fmt.Printf("retained: %s\n", fetched.Path)
		} else {
			fetch.RemoveTemp(fetched)
		}
	}()

	if fetched.Size == 0 {
		fmt.Fprintln(os.Stderr, "empty input; nothing to execute")
		return exitNoTTY
	}

	// Read the script content for analysis.
	data, err := os.ReadFile(fetched.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		return exitInternal
	}

	// Static analysis always.
	analysis, err := analyze.AnalyzeScript(data, "script")
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze: %v\n", err)
		return exitInternal
	}
	secretFindings, err := scanAndRedactClaims(data, analysis.Claims)
	if err != nil {
		fmt.Fprintf(os.Stderr, "secret scan: %v\n", err)
		return exitInternal
	}

	// Load config and key.
	cfg, err := resolveConfig(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return exitInternal
	}
	if cfg.ContributionDelayHours < 0 || cfg.ContributionDelayHours > 24 {
		fmt.Fprintln(os.Stderr, "config: contribution_delay_hours must be between 0 and 24")
		return exitInternal
	}
	if f.OptIn || cfg.OptIn {
		f.OptIn = true
	}
	if f.LLMRuns > 0 {
		cfg.LLM.Runs = f.LLMRuns
	}
	k, err := key.LoadOrCreate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "key: %v\n", err)
		return exitInternal
	}

	// LLM analysis only if requested.
	var llmResult *llm.Result
	if f.LLM {
		client := llm.NewClient(llm.Options{
			Endpoint:     cfg.LLM.Endpoint,
			Model:        cfg.LLM.Model,
			APIKey:       cfg.LLM.APIKey,
			Runs:         cfg.LLM.Runs,
			Timeout:      time.Duration(cfg.LLM.TimeoutSec) * time.Second,
			Backend:      cfg.LLM.Backend,
			Quantization: cfg.LLM.Quantization,
		})
		llmResult, _ = client.Analyze(ctx, string(data))
		if llmResult != nil && llmResult.Error != "" {
			fmt.Fprintf(os.Stderr, "llm: skipped (%s)\n", llmResult.Error)
		} else if llmResult != nil {
			redactClaimExcerpts(llmResult.Claims, secretFindings)
		}
	}

	localVerdict := verdictFromAnalysis(analysis.Claims)

	// Build a local record only when we have a retrievable URL or contribution
	// is explicitly requested with a source URL.
	var localRecords []*schema.Record
	canBuildRecord := fetched.URL != "" || f.SourceURL != ""
	if canBuildRecord {
		var err error
		localRecords, err = buildLocalRecords(k, fetched, analysis, llmResult)
		if err != nil {
			fmt.Fprintf(os.Stderr, "record: %v\n", err)
			return exitInternal
		}
		if f.SourceURL != "" {
			normalized, err := normalizeHTTPSURL(f.SourceURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "record: --source-url: %v\n", err)
				return exitInternal
			}
			for i, rec := range localRecords {
				rec.Body.Target.URL = normalized
				localRecords[i], err = schema.Sign(rec.Body, k.Private)
				if err != nil {
					fmt.Fprintf(os.Stderr, "record: %v\n", err)
					return exitInternal
				}
			}
		}
		if fetched.URL != "" && !strings.HasPrefix(localRecords[0].Body.Target.URL, "https://") && (f.OptIn || cfg.OptIn) {
			fmt.Fprintln(os.Stderr, "contribution: public source URL must use https")
			return exitInternal
		}
	}

	// Community records via authenticated prefix lookup.
	community, err := lookupCommunityRecords(ctx, fetched.Hash, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		return exitVerifyFail
	}

	// Community score uses only logged records and uniform default trust weights.
	communityTrust := map[string]float64{}
	for _, r := range append(append([]score.VerifiedRecord(nil), community.Records...), community.PriorRecords...) {
		communityTrust[r.AuditorID] = score.TrustDefault
	}
	communityScore := score.Compute(score.Input{
		TargetHash:   fetched.Hash,
		Records:      community.Records,
		PriorRecords: community.PriorRecords,
		Trust:        communityTrust,
	})

	// Local static findings are kept separate from the community trust signal.
	hasStaticDanger := false
	for _, c := range analysis.Claims {
		switch c.Category {
		case "exec.remote_pipe", "exec.eval", "fs.delete_broad", "priv.sudo", "priv.persist", "env.exfil", "obfuscation.base64":
			hasStaticDanger = true
		}
	}
	localStaticFlagged := localVerdict == schema.VerdictDanger && len(analysis.Claims) > 0

	// Display.
	communityBadge := communityScore.Verdict
	if communityBadge == "" {
		communityBadge = score.VerdictUnknown
	}
	fmt.Printf("%s\n", tui.ProductBanner())
	fmt.Printf("target: %s\n", fetched.Hash)
	fmt.Printf("community verdict: %s\n", communityBadge)
	fmt.Printf("community score: %.3f (+%.3f / -%.3f)\n", communityScore.Total, communityScore.Positive, communityScore.Negative)
	fmt.Printf("community signals: %d  families: %d\n", communityScore.SignalsUsed, communityScore.FamiliesUsed)
	if localStaticFlagged {
		fmt.Println("local static: block")
	} else if len(analysis.Claims) > 0 {
		fmt.Println("local static: info")
	}
	if len(analysis.Claims) > 0 {
		fmt.Println("static findings:")
		for _, c := range analysis.Claims {
			fmt.Printf("  line %d [%s] %s\n", c.Line, c.Category, c.Excerpt)
		}
	}
	for _, finding := range secretFindings {
		fmt.Printf("secret-warning: line %d rule %s (matched value redacted)\n", finding.Line, finding.RuleID)
	}
	if llmResult != nil {
		fmt.Printf("llm verdict: %s (agreement %.2f)\n", llmResult.Verdict, llmResult.Agreement)
		for _, c := range llmResult.Claims {
			fmt.Printf("  llm claim: line %d [%s] %s\n", c.Line, c.Category, c.Excerpt)
		}
	}
	for _, s := range analysis.SecondStage {
		pinned := "unpinned"
		if s.Pinned {
			pinned = "pinned"
		}
		fmt.Printf("  second-stage: %s (%s)\n", s.URLPattern, pinned)
	}
	fmt.Println("This is not a safety guarantee. Execution is at your own risk.")

	// Flagged block from community signals or local static findings.
	blocked := communityScore.Verdict == score.VerdictFlagged || localStaticFlagged
	if tui.IsFlaggedBlocked(blocked, f.ForceFlagged) {
		if communityScore.Verdict == score.VerdictFlagged {
			fmt.Fprintln(os.Stderr, "blocked: flagged verdict")
		} else {
			fmt.Fprintln(os.Stderr, "blocked: local static block")
		}
		return exitFlagged
	}

	// Local dangerous static findings with an otherwise unknown community verdict
	// require at least caution-level confirmation.
	badge := communityBadge
	if hasStaticDanger && communityScore.Verdict == score.VerdictUnknown {
		badge = score.VerdictCaution
	}
	_ = badge

	// Confirm.
	confirmed, err := tui.Confirm("Execute this script?", f.Yes)
	if err != nil {
		if errors.Is(err, tui.ErrNoTTY) {
			fmt.Fprintln(os.Stderr, "no TTY available; use --yes to auto-confirm")
			return exitNoTTY
		}
		fmt.Fprintf(os.Stderr, "confirm: %v\n", err)
		return exitInternal
	}
	if !confirmed {
		fmt.Println("refused")
		return exitNoTTY
	}

	// Execute.
	execOpts := tui.ExecutionOptions{
		Args:         scriptArgs,
		Yes:          f.Yes,
		ForceFlagged: f.ForceFlagged,
		KeepTemp:     f.KeepTemp,
		TtyStdin:     true,
	}
	res, err := tui.RunScript(ctx, fetched.Path, execOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "exec: %v\n", err)
		return exitInternal
	}

	// Contribute.
	if f.OptIn {
		q, err := contrib.NewQueue()
		if err != nil {
			fmt.Fprintf(os.Stderr, "queue: %v\n", err)
			return exitInternal
		}
		if len(localRecords) == 0 {
			fmt.Fprintln(os.Stderr, "contribution: pipe-mode contribution requires --source-url with a retrievable HTTPS URL")
			return res.ExitCode
		}
		for _, localRec := range localRecords {
			if localRec.Body.Target.URL == "" {
				fmt.Fprintln(os.Stderr, "contribution: target URL is required")
				return res.ExitCode
			}
			if err := q.Enqueue(localRec, cfg.ContributionDelayHours > 0); err != nil {
				fmt.Fprintf(os.Stderr, "enqueue: %v\n", err)
				return res.ExitCode
			}
		}
		fmt.Printf("queued %d record(s) for contribution (%s)\n", len(localRecords), contrib.LicenseNotice())
	}

	return res.ExitCode
}

func buildLocalRecords(k *key.Key, fetched *fetch.Fetched, analysis *analyze.Result, llmResult *llm.Result) ([]*schema.Record, error) {
	now := time.Now().UTC().Unix()
	targetURL := fetched.NormalizedURL
	if targetURL == "" && fetched.URL != "" {
		targetURL = fetched.URL
	}
	target := schema.Target{URL: targetURL, SHA256: fetched.Hash, Size: fetched.Size}
	staticClaims := append([]schema.Claim(nil), analysis.Claims...)
	staticBody := schema.RecordBody{
		Type:      schema.SchemaAuditV1,
		CreatedAt: now,
		Auditor:   k.AuditorID(),
		Target:    target,
		Analyzer:  analyze.AnalyzerInfo,
		Verdict:   verdictFromAnalysis(staticClaims),
		Claims:    staticClaims,
	}
	if len(analysis.SecondStage) > 0 {
		staticBody.SecondStage = append([]schema.SecondStage(nil), analysis.SecondStage...)
	}
	staticRecord, err := schema.Sign(staticBody, k.Private)
	if err != nil {
		return nil, err
	}
	records := []*schema.Record{staticRecord}

	if llmResult != nil && llmResult.Error == "" {
		llmClaims := append([]schema.Claim(nil), llmResult.Claims...)
		verdict := llmResult.Verdict
		if verdict == schema.VerdictDanger && len(llmClaims) == 0 {
			// An advisory danger verdict without machine-verifiable evidence
			// cannot be represented as a scoring signal.
			verdict = schema.VerdictInfo
		}
		if verdict != schema.VerdictOK && verdict != schema.VerdictInfo && verdict != schema.VerdictDanger {
			verdict = verdictFromAnalysis(llmClaims)
		}
		llmBody := schema.RecordBody{
			Type:      schema.SchemaAuditV1,
			CreatedAt: now,
			Auditor:   k.AuditorID(),
			Target:    target,
			Analyzer:  llmResult.AnalyzerMetadata(),
			Verdict:   verdict,
			Claims:    llmClaims,
		}
		llmRecord, err := schema.Sign(llmBody, k.Private)
		if err != nil {
			return nil, err
		}
		records = append(records, llmRecord)
	}
	return records, nil
}

func verdictFromAnalysis(claims []schema.Claim) string {
	for _, c := range claims {
		switch schema.DisplayCategory(c.Category) {
		case "exec.remote_pipe", "exec.eval", "fs.delete_broad", "priv.sudo", "priv.persist", "env.exfil", "obfuscation.base64":
			return schema.VerdictDanger
		}
	}
	if len(claims) > 0 {
		return schema.VerdictInfo
	}
	return schema.VerdictOK
}

func doAudit(args []string) int {
	var useLLM bool
	var llmRuns int
	var delta string
	var sourceURL string
	var positional []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--llm":
			useLLM = true
		case "--llm-runs":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--llm-runs requires a value")
				return exitInternal
			}
			i++
			if _, err := fmt.Sscanf(args[i], "%d", &llmRuns); err != nil || llmRuns <= 0 {
				fmt.Fprintln(os.Stderr, "--llm-runs must be a positive integer")
				return exitInternal
			}
		case "--delta":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--delta requires a value")
				return exitInternal
			}
			i++
			delta = args[i]
		case "--source-url":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--source-url requires a value")
				return exitInternal
			}
			i++
			sourceURL = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "unknown flag: %s\n", args[i])
				return exitInternal
			}
			positional = append(positional, args[i])
		}
	}
	if len(positional) != 1 {
		fmt.Fprintln(os.Stderr, "usage: ebi audit <url|file> [--llm] [--llm-runs N] [--delta <hash>] [--source-url <url>]")
		return exitInternal
	}
	source := positional[0]
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return exitInternal
	}

	var fetched *fetch.Fetched
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		fetched, err = fetch.FetchURL(ctx, source, fetch.DefaultOptions())
	} else {
		fetched, err = fetch.FetchFile(ctx, source, fetch.DefaultOptions())
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch: %v\n", err)
		return exitFetchFail
	}
	defer fetch.RemoveTemp(fetched)

	data, err := os.ReadFile(fetched.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		return exitInternal
	}
	analysis, err := analyze.AnalyzeScript(data, source)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze: %v\n", err)
		return exitInternal
	}
	detector, err := secrets.NewDetector()
	if err != nil {
		fmt.Fprintf(os.Stderr, "secret scan: %v\n", err)
		return exitInternal
	}
	findings, err := detector.ScanBytes(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "secret scan: %v\n", err)
		return exitInternal
	}
	redactClaimExcerpts(analysis.Claims, findings)
	fmt.Printf("target: %s\n", fetched.Hash)
	fmt.Printf("size: %d\n", fetched.Size)
	for _, c := range analysis.Claims {
		fmt.Printf("claim: line %d [%s] %s\n", c.Line, c.Category, c.Excerpt)
	}
	fmt.Printf("second-stage: %d\n", len(analysis.SecondStage))
	for _, finding := range findings {
		fmt.Printf("secret-warning: line %d rule %s (matched value redacted)\n", finding.Line, finding.RuleID)
	}

	var llmResult *llm.Result
	if useLLM {
		runs := cfg.LLM.Runs
		if llmRuns > 0 {
			runs = llmRuns
		}
		client := llm.NewClient(llm.Options{
			Endpoint:     cfg.LLM.Endpoint,
			Model:        cfg.LLM.Model,
			APIKey:       cfg.LLM.APIKey,
			Runs:         runs,
			Timeout:      time.Duration(cfg.LLM.TimeoutSec) * time.Second,
			Backend:      cfg.LLM.Backend,
			Quantization: cfg.LLM.Quantization,
		})
		res, err := client.Analyze(ctx, string(data))
		if err != nil {
			fmt.Fprintf(os.Stderr, "llm: %v\n", err)
		}
		if res != nil {
			if res.Error != "" {
				fmt.Printf("llm: skipped (%s)\n", res.Error)
			} else {
				llmResult = res
				redactClaimExcerpts(res.Claims, findings)
				fmt.Printf("llm verdict: %s (agreement %.2f)\n", res.Verdict, res.Agreement)
				for _, c := range res.Claims {
					fmt.Printf("  llm claim: line %d [%s] %s\n", c.Line, c.Category, c.Excerpt)
				}
			}
		}
	}

	var prevSHA256 string
	if delta != "" {
		prevSHA256, err = resolveDeltaHash(ctx, delta, fetched, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "delta: %v\n", err)
			return exitFetchFail
		}
		if prevSHA256 != "" {
			fmt.Printf("delta: previous %s\n", prevSHA256)
		}
	}

	// A signed audit target requires a retrievable URL. Local-file audits still
	// perform all analysis, but only create records when --source-url is given.
	if fetched.URL == "" && sourceURL == "" {
		fmt.Println("record: not created for a local file (use --source-url with the reviewed HTTPS source)")
		return exitOK
	}

	// Build local records for optional later contribution.
	k, err := key.LoadOrCreate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "key: %v\n", err)
		return exitInternal
	}
	records, err := buildLocalRecords(k, fetched, analysis, llmResult)
	if err != nil {
		fmt.Fprintf(os.Stderr, "record: %v\n", err)
		return exitInternal
	}
	if prevSHA256 != "" {
		for i, record := range records {
			record.Body.PrevSHA256 = prevSHA256
			records[i], err = schema.Sign(record.Body, k.Private)
			if err != nil {
				fmt.Fprintf(os.Stderr, "record: %v\n", err)
				return exitInternal
			}
		}
	}
	if sourceURL != "" {
		normalized, err := normalizeHTTPSURL(sourceURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "record: --source-url: %v\n", err)
			return exitInternal
		}
		for i, record := range records {
			record.Body.Target.URL = normalized
			records[i], err = schema.Sign(record.Body, k.Private)
			if err != nil {
				fmt.Fprintf(os.Stderr, "record: %v\n", err)
				return exitInternal
			}
		}
	}
	for _, record := range records {
		id, _ := schema.RecordID(record.Body)
		fmt.Printf("record-id (%s): %s\n", record.Body.Analyzer.Kind, id)
	}
	return exitOK
}

func resolveDeltaHash(ctx context.Context, delta string, fetched *fetch.Fetched, cfg config.Config) (string, error) {
	if schema.IsHexHash(delta) {
		return delta, nil
	}
	if strings.HasPrefix(delta, "http://") || strings.HasPrefix(delta, "https://") {
		old, err := fetch.FetchURL(ctx, delta, fetch.DefaultOptions())
		if err != nil {
			return "", err
		}
		defer fetch.RemoveTemp(old)
		fmt.Printf("delta-old: %s\n", old.Hash)
		showDiff(old.Path, fetched.Path)
		return old.Hash, nil
	}
	// Try local file.
	old, err := fetch.FetchFile(ctx, delta, fetch.DefaultOptions())
	if err != nil {
		return "", fmt.Errorf("cannot resolve delta %q: %w", delta, err)
	}
	defer fetch.RemoveTemp(old)
	fmt.Printf("delta-old: %s\n", old.Hash)
	showDiff(old.Path, fetched.Path)
	return old.Hash, nil
}

func showDiff(oldPath, newPath string) {
	oldData, _ := os.ReadFile(oldPath)
	newData, _ := os.ReadFile(newPath)
	oldLines := strings.Split(string(oldData), "\n")
	newLines := strings.Split(string(newData), "\n")
	max := len(oldLines)
	if len(newLines) > max {
		max = len(newLines)
	}
	fmt.Println("diff:")
	for i := 0; i < max; i++ {
		oldLine := ""
		if i < len(oldLines) {
			oldLine = oldLines[i]
		}
		newLine := ""
		if i < len(newLines) {
			newLine = newLines[i]
		}
		if oldLine != newLine {
			fmt.Printf("-%d: %s\n", i+1, oldLine)
			fmt.Printf("+%d: %s\n", i+1, newLine)
		}
	}
}

func normalizeHTTPSURL(raw string) (string, error) {
	normalized, err := schema.NormalizeURL(raw)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(normalized, "https://") {
		return "", fmt.Errorf("must use https")
	}
	return normalized, nil
}

func scanAndRedactClaims(data []byte, claims []schema.Claim) ([]secrets.Finding, error) {
	detector, err := secrets.NewDetector()
	if err != nil {
		return nil, err
	}
	findings, err := detector.ScanBytes(data)
	if err != nil {
		return nil, err
	}
	redactClaimExcerpts(claims, findings)
	return findings, nil
}

func redactClaimExcerpts(claims []schema.Claim, findings []secrets.Finding) {
	sensitiveLines := make(map[int]bool, len(findings))
	for _, finding := range findings {
		sensitiveLines[finding.Line] = true
	}
	for i := range claims {
		if sensitiveLines[claims[i].Line] {
			claims[i].Excerpt = "[REDACTED]"
		}
	}
}

type verifyFlags struct {
	PolicyPath     string
	CheckpointPath string
	MirrorURL      string
}

func parseVerifyFlags(args []string) (verifyFlags, []string, error) {
	var f verifyFlags
	var positional []string
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "--policy":
			if i+1 >= len(args) {
				return f, nil, fmt.Errorf("--policy requires a value")
			}
			i++
			f.PolicyPath = args[i]
		case "--checkpoint":
			if i+1 >= len(args) {
				return f, nil, fmt.Errorf("--checkpoint requires a value")
			}
			i++
			f.CheckpointPath = args[i]
		case "--mirror":
			if i+1 >= len(args) {
				return f, nil, fmt.Errorf("--mirror requires a value")
			}
			i++
			f.MirrorURL = args[i]
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "unknown flag: %s\n", a)
				return f, nil, fmt.Errorf("unknown flag")
			}
			positional = append(positional, a)
		}
		i++
	}
	return f, positional, nil
}

func resolveVerifyConfig(f verifyFlags) (config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return cfg, err
	}
	if f.PolicyPath != "" {
		cfg.PolicyPath = f.PolicyPath
	}
	if f.CheckpointPath != "" {
		cfg.CheckpointPath = f.CheckpointPath
	}
	if f.MirrorURL != "" {
		cfg.MirrorURL = f.MirrorURL
	}
	return cfg, nil
}

func doVerify(args []string) int {
	f, positional, err := parseVerifyFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "usage: ebi verify [--policy PATH] [--checkpoint PATH] [--mirror URL] <record-id|snapshot.tar.zst|record.json>\n")
		return exitInternal
	}
	if len(positional) != 1 {
		fmt.Fprintln(os.Stderr, "usage: ebi verify [--policy PATH] [--checkpoint PATH] [--mirror URL] <record-id|snapshot.tar.zst|record.json>")
		return exitInternal
	}
	cfg, err := resolveVerifyConfig(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return exitInternal
	}

	arg := positional[0]
	if strings.HasSuffix(arg, ".tar.zst") {
		policy, err := loadPolicy(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "policy: %v\n", err)
			return exitVerifyFail
		}
		f, err := os.Open(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open: %v\n", err)
			return exitVerifyFail
		}
		defer f.Close()
		if err := snapshot.Verify(f, nil, &policy, storage.CheckpointPath()); err != nil {
			fmt.Fprintf(os.Stderr, "verify: %v\n", err)
			return exitVerifyFail
		}
		fmt.Printf("snapshot: %s\n", arg)
		fmt.Printf("verified: true\n")
		return exitOK
	}
	if schema.IsHexHash(arg) {
		return verifyRemoteRecordID(arg, cfg)
	}
	// Verify a local signed record/envelope JSON.
	data, err := os.ReadFile(arg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		return exitVerifyFail
	}
	rec, err := schema.DecodeRecordStrict(bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode: %v\n", err)
		return exitVerifyFail
	}
	_, auditorID, err := schema.Verify(rec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		return exitVerifyFail
	}
	id, _ := schema.RecordID(rec.Body)
	fmt.Printf("record-id: %s\n", id)
	fmt.Printf("auditor: %s\n", auditorID)
	fmt.Printf("verified: true\n")
	return exitOK
}

func verifyRemoteRecordID(recordID string, cfg config.Config) int {
	if mirrorURL(cfg) == "" {
		fmt.Fprintln(os.Stderr, "no mirror configured for remote verification")
		return exitVerifyFail
	}
	ctx := context.Background()
	if err := verifyRemoteRecordByID(ctx, recordID, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		return exitVerifyFail
	}
	fmt.Printf("record-id: %s\n", recordID)
	fmt.Printf("verified: true\n")
	return exitOK
}

func doKey(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ebi key {init|show|export}")
		return exitInternal
	}
	switch args[0] {
	case "init":
		k, err := key.LoadOrCreate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "key init: %v\n", err)
			return exitInternal
		}
		fmt.Printf("key initialized: %s\n", k.ID())
		return exitOK
	case "show":
		k, err := key.LoadOrCreate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "key show: %v\n", err)
			return exitInternal
		}
		fmt.Printf("auditor: %s\n", k.ID())
		fmt.Printf("public key: %s\n", k.PublicKeyHex())
		return exitOK
	case "export":
		k, err := key.LoadOrCreate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "key export: %v\n", err)
			return exitInternal
		}
		fmt.Println(k.ExportPublicKey())
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown key command: %s\n", args[0])
		return exitInternal
	}
}

func doContribute(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ebi contribute {status|flush}")
		return exitInternal
	}
	q, err := contrib.NewQueue()
	if err != nil {
		fmt.Fprintf(os.Stderr, "queue: %v\n", err)
		return exitInternal
	}
	switch args[0] {
	case "status":
		n, err := q.Status()
		if err != nil {
			fmt.Fprintf(os.Stderr, "status: %v\n", err)
			return exitInternal
		}
		fmt.Printf("pending: %d\n", n)
		return exitOK
	case "flush":
		records, err := q.Flush(time.Now().UTC())
		if err != nil {
			fmt.Fprintf(os.Stderr, "flush: %v\n", err)
			return exitInternal
		}
		fmt.Printf("flushing %d records\n", len(records))
		failures := 0
		for _, rec := range records {
			body, _, err := schema.Verify(rec)
			if err != nil {
				fmt.Fprintf(os.Stderr, "verify: %v\n", err)
				failures++
				continue
			}
			id, _ := schema.RecordID(*body)
			if err := submitRecord(rec); err != nil {
				fmt.Fprintf(os.Stderr, "submit %s: %v\n", id, err)
				failures++
				continue
			}
			if err := q.Ack(rec); err != nil {
				fmt.Fprintf(os.Stderr, "ack %s: %v\n", id, err)
				failures++
				continue
			}
			fmt.Printf("submitted %s (%s)\n", id, contrib.SubmissionNotice())
		}
		if failures > 0 {
			fmt.Printf("failures: %d (retained in queue)\n", failures)
			return exitInternal
		}
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown contribute command: %s\n", args[0])
		return exitInternal
	}
}

func submitRecord(rec *schema.Record) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	urls := cfg.PostingURLs
	if len(urls) == 0 {
		urls = cfg.ServerURLs
	}
	if len(urls) == 0 {
		return fmt.Errorf("no posting server configured")
	}
	if rec == nil {
		return fmt.Errorf("nil record")
	}
	if _, _, err := schema.Verify(rec); err != nil {
		return fmt.Errorf("verify record before submission: %w", err)
	}
	data, err := json.Marshal(map[string]interface{}{
		"record":     rec.Body,
		"public_key": rec.PublicKey,
		"signature":  rec.Signature,
	})
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	var failures []string
	for _, u := range urls {
		base, err := normalizeHTTPSURL(u)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%q: %v", u, err))
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(base, "/")+"/v1/records", bytes.NewReader(data))
		if err != nil {
			cancel()
			failures = append(failures, fmt.Sprintf("%q: %v", u, err))
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", appmeta.UserAgent())
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			failures = append(failures, fmt.Sprintf("%q: %v", u, err))
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
			return nil
		}
		failures = append(failures, fmt.Sprintf("%q: HTTP %d", u, resp.StatusCode))
	}
	return fmt.Errorf("all posting servers failed: %s", strings.Join(failures, "; "))
}
