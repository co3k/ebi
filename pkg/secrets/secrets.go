// Package secrets scans text for potential secret leaks using the gitleaks v8
// default detector. It never exposes the matched secret text; output contains
// only line number and rule ID. Redaction level is 100%.
package secrets

import (
	"fmt"
	"strings"

	"github.com/zricethezav/gitleaks/v8/detect"
)

// Finding is a secret detection result containing only line and rule ID.
type Finding struct {
	RuleID string
	Line   int
}

// Detector wraps a gitleaks detector configured for 100% redaction.
type Detector struct {
	d *detect.Detector
}

// NewDetector creates a detector with the gitleaks default configuration and
// redaction set to 100%.
func NewDetector() (*Detector, error) {
	d, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("gitleaks default config: %w", err)
	}
	// Defensively set redaction to 100.
	d.Redact = 100
	return &Detector{d: d}, nil
}

// ScanString scans text for potential secrets and returns findings without
// exposing the secret text.
func (d *Detector) ScanString(text string) ([]Finding, error) {
	findings := d.d.DetectString(text)
	out := make([]Finding, 0, len(findings))
	seen := map[string]struct{}{}
	for _, f := range findings {
		// DetectString uses zero-based line offsets.
		line := f.StartLine + 1
		if line < 1 {
			line = 1
		}
		key := f.RuleID + "|" + fmt.Sprintf("%d", line)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Finding{
			RuleID: f.RuleID,
			Line:   line,
		})
	}
	return out, nil
}

// ScanBytes scans bytes for potential secrets.
func (d *Detector) ScanBytes(data []byte) ([]Finding, error) {
	return d.ScanString(string(data))
}

// MaskLine returns a single line with the secret text replaced by a redaction
// marker. This is used for the report gate flow.
func MaskLine(line string, marker string) string {
	if marker == "" {
		marker = "[REDACTED]"
	}
	return marker
}

// MaskSecrets replaces lines containing findings with a redaction marker.
// The secret text is never included in the output.
func MaskSecrets(text string, findings []Finding) string {
	lines := strings.Split(text, "\n")
	for _, f := range findings {
		idx := f.Line - 1
		if idx >= 0 && idx < len(lines) {
			lines[idx] = MaskLine(lines[idx], "")
		}
	}
	return strings.Join(lines, "\n")
}

// RedactedError returns an error that includes the rule ID and line but never
// the secret text.
func RedactedError(f Finding) error {
	return fmt.Errorf("secret detected by rule %s at line %d", f.RuleID, f.Line)
}

// FormatFinding serializes a finding for safe output.
func FormatFinding(f Finding) string {
	return fmt.Sprintf("%s:%d", f.RuleID, f.Line)
}

// FormatError serializes a redacted error.
func FormatError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// FindingLine returns a finding formatted for display with a redacted marker.
func FindingLine(line string) string {
	return MaskLine(line, "")
}
