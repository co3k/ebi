package secrets

import (
	"strings"
	"testing"
)

func TestSecretScanNoLeak(t *testing.T) {
	d, err := NewDetector()
	if err != nil {
		t.Fatal(err)
	}
	const secret = "ghp_1234567890abcdef1234567890abcdef1234"
	findings, err := d.ScanString("export GITHUB_TOKEN=" + secret + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected secret finding")
	}
	for _, f := range findings {
		if f.RuleID == "" {
			t.Fatal("missing rule id")
		}
		if f.Line != 1 {
			t.Fatalf("unexpected line %d", f.Line)
		}
	}
	// Ensure no secret text appears in output.
	out := MaskSecrets("export AWS_ACCESS_KEY_ID="+secret+"\n", findings)
	if strings.Contains(out, secret) {
		t.Fatal("secret text leaked in masked output")
	}
	// Findings must not contain matched text.
	for _, f := range findings {
		formatted := FormatFinding(f)
		if strings.Contains(formatted, secret) {
			t.Fatal("secret text leaked in formatted finding")
		}
	}
}

func TestSecretScanNoFalseLeak(t *testing.T) {
	d, err := NewDetector()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := d.ScanString("echo hello world\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("unexpected findings: %d", len(findings))
	}
}

func TestMaskLine(t *testing.T) {
	if got := MaskLine("secret", ""); got != "[REDACTED]" {
		t.Fatalf("unexpected mask: %q", got)
	}
	if got := MaskLine("secret", "XXX"); got != "XXX" {
		t.Fatalf("unexpected mask: %q", got)
	}
}

func TestRedactedError(t *testing.T) {
	err := RedactedError(Finding{RuleID: "test", Line: 1})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "ghp_") {
		t.Fatal("secret text leaked")
	}
}

func TestFormatFinding(t *testing.T) {
	f := Finding{RuleID: "github", Line: 2}
	if FormatFinding(f) != "github:2" {
		t.Fatalf("unexpected format: %q", FormatFinding(f))
	}
}

func TestSecretFindingNoColumns(t *testing.T) {
	d, err := NewDetector()
	if err != nil {
		t.Fatal(err)
	}
	const secret = "ghp_1234567890abcdef1234567890abcdef1234"
	findings, err := d.ScanString("export GITHUB_TOKEN=" + secret + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding")
	}
	// Findings must only contain rule id and line.
	f := findings[0]
	if f.RuleID == "" || f.Line == 0 {
		t.Fatal("finding missing required fields")
	}
}

func TestSecretScanLineNumber(t *testing.T) {
	d, err := NewDetector()
	if err != nil {
		t.Fatal(err)
	}
	const secret = "ghp_1234567890abcdef1234567890abcdef1234"
	findings, err := d.ScanString("echo safe\nexport GITHUB_TOKEN=" + secret + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding")
	}
	if findings[0].Line != 2 {
		t.Fatalf("expected one-based line 2, got %d", findings[0].Line)
	}
	masked := MaskSecrets("echo safe\nexport GITHUB_TOKEN="+secret+"\n", findings)
	if !strings.Contains(masked, "echo safe\n[REDACTED]\n") || strings.Contains(masked, secret) {
		t.Fatalf("wrong line masked or secret leaked: %q", masked)
	}
}
