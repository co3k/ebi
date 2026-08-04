// Package analyze performs static shell analysis using mvdan.cc/sh/v3.
// It returns schema claims and second-stage resources without executing the script.
package analyze

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/co3k/ebi/pkg/schema"
	"mvdan.cc/sh/v3/syntax"
)

// Result is the analysis output for a shell script.
type Result struct {
	Claims        []schema.Claim
	SecondStage   []schema.SecondStage
	ParseError    bool
	ParseErrorMsg string
}

// AnalyzerInfo is the static analyzer metadata.
var AnalyzerInfo = schema.Analyzer{
	Kind: KindStatic,
}

// KindStatic is a local constant mirroring schema.KindStatic to avoid an import
// cycle if needed.
const KindStatic = "static"

// AnalyzeScript parses and analyzes a shell script, returning claims.
func AnalyzeScript(data []byte, filename string) (*Result, error) {
	res := &Result{
		Claims:      []schema.Claim{},
		SecondStage: []schema.SecondStage{},
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return res, nil
	}
	text := string(data)
	parser := syntax.NewParser(syntax.KeepComments(true))
	file, err := parser.Parse(bytes.NewReader(data), filename)
	if err != nil {
		// Bash-only syntax such as process substitution is outside POSIX but is
		// explicitly in scope for v1. Retry using the Bash grammar before
		// classifying the input as unparsable.
		parser = syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
		file, err = parser.Parse(bytes.NewReader(data), filename)
	}
	if err != nil {
		res.ParseError = true
		res.ParseErrorMsg = err.Error()
		line := 1
		lineNo := parseErrorLine(err, data)
		if lineNo > 0 {
			line = lineNo
		}
		lineStr := lineText(text, line)
		res.Claims = append(res.Claims, schema.Claim{
			Category:   "misc.other",
			Line:       line,
			LineSHA256: schema.LineHash(lineStr),
			Note:       "shell parse error: " + truncate(res.ParseErrorMsg, 100),
			Excerpt:    schema.SafeExcerpt(lineStr, 120),
		})
		// Continue with best-effort analysis on the raw text.
		analyzeText(text, res)
		return res, nil
	}
	analyzeFile(file, text, res)
	return res, nil
}

func analyzeFile(file *syntax.File, text string, res *Result) {
	syntax.Walk(file, func(node syntax.Node) bool {
		switch x := node.(type) {
		case *syntax.CallExpr:
			analyzeCall(x, text, res)
		case *syntax.BinaryCmd:
			analyzeBinaryCmd(x, text, res)
		}
		return true
	})
}

func analyzeCall(call *syntax.CallExpr, text string, res *Result) {
	if len(call.Args) == 0 {
		return
	}
	line := posLine(call)
	lineStr := lineText(text, line)
	first := strings.ToLower(literalOf(call.Args[0]))

	// Package manager installations.
	if isPackageManager(first) {
		addClaim(res, "pkg.install", line, lineStr)
	}

	// sudo plus nested command/package manager.
	if first == "sudo" {
		addClaim(res, "priv.sudo", line, lineStr)
		if len(call.Args) > 1 && isPackageManager(strings.ToLower(literalOf(call.Args[1]))) {
			addClaim(res, "pkg.install", line, lineStr)
		}
	}

	// Broad rm.
	if isBroadRm(call, lineStr) {
		addClaim(res, "fs.delete_broad", line, lineStr)
	}

	// Persistence writes.
	if isPersistenceWrite(call, first, lineStr) {
		addClaim(res, "priv.persist", line, lineStr)
	}

	// Exfiltration.
	if isExfil(call, first, lineStr) {
		addClaim(res, "env.exfil", line, lineStr)
	}

	// Network fetch.
	if isNetworkFetch(first) {
		addClaim(res, "net.fetch", line, lineStr)
		extractFetchTarget(call, res, line, lineStr)
	}

	// eval / source / . executing dynamic input.
	if first == "eval" || first == "source" || first == "." {
		addClaim(res, "exec.eval", line, lineStr)
		extractEvalTarget(call, text, res, line, lineStr)
	}

	// Base64 / hex / openssl decode piped/executed.
	if isDecodeExec(call, lineStr) {
		addClaim(res, "obfuscation.base64", line, lineStr)
	}

	// Process substitution fed into a shell.
	if isProcessSubstitutionShell(call, lineStr) {
		addClaim(res, "exec.remote_pipe", line, lineStr)
		extractURLsFromLine(lineStr, res, line, lineStr)
	}
}

func analyzeBinaryCmd(bin *syntax.BinaryCmd, text string, res *Result) {
	if bin.Op != syntax.Pipe {
		return
	}
	line := posLine(bin)
	lineStr := lineText(text, line)
	if stmtContainsFetch(bin.X) && stmtContainsShell(bin.Y) {
		addClaim(res, "exec.remote_pipe", line, lineStr)
		extractURLsFromLine(lineStr, res, line, lineStr)
	}
}

func stmtContainsFetch(stmt *syntax.Stmt) bool {
	found := false
	syntax.Walk(stmt, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return !found
		}
		if isNetworkFetch(strings.ToLower(literalOf(call.Args[0]))) {
			found = true
		}
		return !found
	})
	return found
}

func stmtContainsShell(stmt *syntax.Stmt) bool {
	found := false
	syntax.Walk(stmt, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return !found
		}
		first := strings.ToLower(literalOf(call.Args[0]))
		if isShellName(first) {
			found = true
			return false
		}
		if first == "sudo" && len(call.Args) > 1 && isShellName(strings.ToLower(literalOf(call.Args[1]))) {
			found = true
			return false
		}
		return true
	})
	return found
}

func isShellName(name string) bool {
	return name == "sh" || name == "bash" || name == "zsh" || name == "ksh"
}

func isNetworkFetch(name string) bool {
	return name == "curl" || name == "wget" || name == "fetch"
}

func extractFetchTarget(call *syntax.CallExpr, res *Result, line int, lineStr string) {
	for _, arg := range call.Args[1:] {
		url := literalOf(arg)
		if isURL(url) {
			addSecondStage(res, url, line, lineStr)
		}
	}
	extractURLsFromLine(rawCall(call), res, line, lineStr)
}

func extractEvalTarget(call *syntax.CallExpr, text string, res *Result, line int, lineStr string) {
	for _, arg := range call.Args[1:] {
		url := literalOf(arg)
		if isURL(url) {
			addSecondStage(res, url, line, lineStr)
		}
	}
	extractURLsFromLine(lineStr, res, line, lineStr)
}

func extractURLsFromLine(line string, res *Result, lineNo int, lineStr string) {
	for _, url := range extractURLs(line) {
		addSecondStage(res, url, lineNo, lineStr)
	}
}

func isProcessSubstitutionShell(call *syntax.CallExpr, lineStr string) bool {
	lower := strings.ToLower(lineStr)
	if len(call.Args) == 0 {
		return false
	}
	first := strings.ToLower(literalOf(call.Args[0]))
	isShell := first == "sh" || first == "bash" || first == "zsh" || first == "ksh"
	hasProcessSubstitution := strings.Contains(lower, "<(") || strings.Contains(lower, ">(")
	hasFetch := strings.Contains(lower, "curl") || strings.Contains(lower, "wget") || strings.Contains(lower, "fetch")
	return isShell && hasProcessSubstitution && hasFetch
}

func isDecodeExec(call *syntax.CallExpr, lineStr string) bool {
	first := strings.ToLower(literalOf(call.Args[0]))
	lower := strings.ToLower(lineStr)
	isDecoder := first == "base64" || first == "openssl" || strings.Contains(first, "xxd") || strings.Contains(first, "decode") || strings.Contains(first, "hex") || strings.Contains(first, "unbase64")
	if !isDecoder {
		return false
	}
	execIndicators := []string{"| sh", "| bash", "| sh", "| zsh", "$(", "`", "eval", "exec"}
	for _, ind := range execIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func isBroadRm(call *syntax.CallExpr, lineStr string) bool {
	if len(call.Args) < 2 {
		return false
	}
	name := strings.ToLower(literalOf(call.Args[0]))
	if name != "rm" {
		return false
	}
	lower := strings.ToLower(lineStr)
	recursive := strings.Contains(lower, "--recursive") || optionSet(lower, 'r')
	force := strings.Contains(lower, "--force") || optionSet(lower, 'f')
	if !recursive || !force {
		return false
	}
	for _, arg := range call.Args[1:] {
		lit := literalOf(arg)
		lowerArg := strings.ToLower(lit)
		// Root, near-root, wildcard, or variable expansion.
		if lowerArg == "/" || strings.HasPrefix(lowerArg, "/") && !strings.HasPrefix(lowerArg, "/tmp/") && !strings.HasPrefix(lowerArg, "/home/") && !strings.HasPrefix(lowerArg, "/var/tmp/") {
			return true
		}
		if strings.Contains(lowerArg, "*") || strings.Contains(lowerArg, "?") || strings.Contains(lowerArg, "$") || strings.Contains(lowerArg, "~") {
			return true
		}
	}
	// Quoted or compound words are not always reducible to literals by the AST
	// helper. Retain a conservative check over the exact source line.
	if strings.Contains(lower, "${") || strings.Contains(lower, "$") ||
		strings.Contains(lower, " /*") || strings.HasSuffix(strings.TrimSpace(lower), " /") {
		return true
	}
	return false
}

func optionSet(line string, option byte) bool {
	for _, field := range strings.Fields(line) {
		if len(field) < 2 || field[0] != '-' || strings.HasPrefix(field, "--") {
			continue
		}
		if strings.ContainsRune(field[1:], rune(option)) {
			return true
		}
	}
	return false
}

func isPackageManager(name string) bool {
	managers := []string{"apt", "apt-get", "yum", "dnf", "pacman", "brew", "pkg", "apk", "npm", "yarn", "pnpm", "pip", "gem", "cargo", "go", "snap", "flatpak", "port"}
	for _, m := range managers {
		if name == m || strings.HasPrefix(name, m+" ") {
			return true
		}
	}
	return false
}

func isPersistenceWrite(call *syntax.CallExpr, first, lineStr string) bool {
	lower := strings.ToLower(lineStr)
	if first == "crontab" && (strings.Contains(lower, "crontab -") ||
		!strings.Contains(lower, "crontab -l")) {
		return true
	}
	if first == "launchctl" &&
		(strings.Contains(lower, " load ") || strings.Contains(lower, " bootstrap ") ||
			strings.Contains(lower, " enable ")) {
		return true
	}
	if strings.Contains(lower, "systemctl enable") || strings.Contains(lower, "systemctl reenable") {
		return true
	}
	persistentPath := strings.Contains(lower, ".bashrc") ||
		strings.Contains(lower, ".bash_profile") ||
		strings.Contains(lower, ".zshrc") ||
		strings.Contains(lower, ".profile") ||
		strings.Contains(lower, ".config/systemd") ||
		strings.Contains(lower, "/etc/systemd") ||
		strings.Contains(lower, "launchagents") ||
		strings.Contains(lower, "launchdaemons") ||
		strings.Contains(lower, "/etc/cron")
	if !persistentPath {
		return false
	}
	if strings.Contains(lower, ">>") || strings.Contains(lower, ">") ||
		first == "tee" || first == "install" || first == "cp" || first == "mv" ||
		(first == "sed" && strings.Contains(lower, " -i")) {
		return true
	}
	return false
}

func isExfil(call *syntax.CallExpr, first, lineStr string) bool {
	lower := strings.ToLower(lineStr)
	if (first == "curl" || first == "wget") && (strings.Contains(lower, "env") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "key")) {
		return true
	}
	if strings.Contains(lower, "$github_token") || strings.Contains(lower, "$aws_access_key") || strings.Contains(lower, "$aws_secret") || strings.Contains(lower, "$ssh_private_key") || strings.Contains(lower, "$docker_auth") {
		return true
	}
	if first == "curl" && (strings.Contains(lower, "$(env") || strings.Contains(lower, "`env")) {
		return true
	}
	return false
}

func addClaim(res *Result, category string, line int, lineStr string) {
	cat := schema.DisplayCategory(category)
	note := ""
	if cat == "misc.other" {
		note = "categorized as " + category
	}
	claim := schema.Claim{
		Category:   cat,
		Line:       line,
		LineSHA256: schema.LineHash(lineStr),
		Note:       note,
		Excerpt:    schema.SafeExcerpt(lineStr, 120),
	}
	// Stable dedupe: keep first occurrence.
	key := claimKey(claim)
	for _, c := range res.Claims {
		if claimKey(c) == key {
			return
		}
	}
	res.Claims = append(res.Claims, claim)
}

func claimKey(c schema.Claim) string {
	return c.Category + "|" + fmt.Sprintf("%d", c.Line) + "|" + c.LineSHA256
}

func addSecondStage(res *Result, url string, line int, lineStr string) {
	url = stripTrailingPunct(url)
	if url == "" || !isURL(url) {
		return
	}
	normalized, err := schema.NormalizeURL(url)
	if err != nil || normalized != url {
		return
	}
	// Stable dedupe.
	for _, s := range res.SecondStage {
		if s.URLPattern == url {
			return
		}
	}
	pinned := isPinnedURL(url)
	res.SecondStage = append(res.SecondStage, schema.SecondStage{
		URLPattern: url,
		Pinned:     pinned,
	})
	if !pinned {
		addClaim(res, "download.unpinned", line, lineStr)
	}
}

func stripTrailingPunct(s string) string {
	for s != "" {
		last := s[len(s)-1]
		if last == '.' || last == ',' || last == ';' || last == ':' || last == '!' || last == '?' || last == ')' || last == '}' || last == '>' || last == ']' || last == '"' || last == '\'' {
			s = s[:len(s)-1]
			continue
		}
		break
	}
	return s
}

var semverSegment = regexp.MustCompile(`^v?[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.-]+)?$`)

func isPinnedURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if hashInURLPath(u.Path) {
		return true
	}
	for _, segment := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if semverSegment.MatchString(segment) {
			return true
		}
	}
	query := u.Query()
	for key, values := range query {
		lowerKey := strings.ToLower(key)
		for _, value := range values {
			lowerValue := strings.ToLower(strings.TrimSpace(value))
			if lowerValue == "" || lowerValue == "latest" || lowerValue == "stable" ||
				lowerValue == "main" || lowerValue == "master" || lowerValue == "head" {
				continue
			}
			if lowerKey == "version" || lowerKey == "v" || lowerKey == "tag" || lowerKey == "ref" {
				if semverSegment.MatchString(value) || (len(value) >= 7 && isHex(value)) {
					return true
				}
			}
			if strings.Contains(lowerKey, "sha256") || strings.Contains(lowerKey, "checksum") ||
				strings.Contains(lowerKey, "digest") {
				if len(value) >= 40 && isHex(value) {
					return true
				}
			}
		}
	}
	return false
}

func hashInURLPath(url string) bool {
	parts := strings.Split(url, "/")
	for _, p := range parts {
		if len(p) >= 40 && len(p) <= 64 && isHex(p) {
			return true
		}
	}
	return false
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') && !(r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func literalOf(n syntax.Node) string {
	switch x := n.(type) {
	case *syntax.Lit:
		return x.Value
	case *syntax.Word:
		if len(x.Parts) > 0 {
			return literalOf(x.Parts[0])
		}
	case *syntax.ParamExp:
		return "${" + x.Param.Value + "}"
	}
	return ""
}

func posLine(n syntax.Node) int {
	pos := n.Pos()
	if pos.IsValid() {
		return int(pos.Line())
	}
	return 1
}

func lineText(text string, line int) string {
	lines := strings.Split(text, "\n")
	if line < 1 || line > len(lines) {
		return ""
	}
	return lines[line-1]
}

func rawCall(call *syntax.CallExpr) string {
	var b strings.Builder
	for i, arg := range call.Args {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(literalOf(arg))
	}
	return b.String()
}

func parseErrorLine(err error, data []byte) int {
	var parseErr syntax.ParseError
	if errors.As(err, &parseErr) && parseErr.Pos.IsValid() {
		return int(parseErr.Pos.Line())
	}
	msg := err.Error()
	parts := strings.Split(msg, ":")
	for _, part := range parts {
		var line int
		if _, scanErr := fmt.Sscanf(strings.TrimSpace(part), "%d", &line); scanErr == nil && line > 0 {
			return line
		}
	}
	return 0
}

func analyzeText(text string, res *Result) {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lower := strings.ToLower(line)
		lineNo := i + 1
		if strings.Contains(lower, "curl ") || strings.Contains(lower, "wget ") || strings.Contains(lower, "fetch ") {
			if strings.Contains(lower, "| sh") || strings.Contains(lower, "| bash") || strings.Contains(lower, "| sh") || strings.Contains(lower, "| zsh") {
				addClaim(res, "exec.remote_pipe", lineNo, line)
			} else {
				addClaim(res, "net.fetch", lineNo, line)
			}
			for _, url := range extractURLs(line) {
				addSecondStage(res, url, lineNo, line)
			}
		}
		if strings.Contains(lower, "base64") && (strings.Contains(lower, "| sh") || strings.Contains(lower, "| bash") || strings.Contains(lower, "eval") || strings.Contains(lower, "$(") || strings.Contains(lower, "`")) {
			addClaim(res, "obfuscation.base64", lineNo, line)
		}
		if strings.Contains(lower, "openssl") && (strings.Contains(lower, "| sh") || strings.Contains(lower, "| bash") || strings.Contains(lower, "eval") || strings.Contains(lower, "$(") || strings.Contains(lower, "`")) {
			addClaim(res, "obfuscation.base64", lineNo, line)
		}
		if strings.Contains(lower, "eval ") || strings.Contains(lower, "source ") || strings.Contains(lower, ". ") && strings.Contains(lower, "http") {
			addClaim(res, "exec.eval", lineNo, line)
		}
		if strings.Contains(lower, "rm -rf") || strings.Contains(lower, "rm -fr") {
			addClaim(res, "fs.delete_broad", lineNo, line)
		}
		if strings.Contains(lower, "sudo ") || lower == "sudo" {
			addClaim(res, "priv.sudo", lineNo, line)
		}
		if strings.Contains(lower, ".bashrc") || strings.Contains(lower, "crontab") || strings.Contains(lower, "systemctl enable") || strings.Contains(lower, "launchctl") {
			addClaim(res, "priv.persist", lineNo, line)
		}
		if IsPackageManagerWord(lower) {
			addClaim(res, "pkg.install", lineNo, line)
		}
	}
}

// IsPackageManagerWord reports whether the line contains a package manager invocation.
func IsPackageManagerWord(line string) bool {
	managers := []string{"apt", "apt-get", "yum", "dnf", "pacman", "brew", "pkg", "apk", "npm install", "yarn install", "pnpm install", "pip install", "gem install", "cargo install", "go install", "snap install", "flatpak install", "port install"}
	for _, m := range managers {
		if strings.Contains(line, m) {
			return true
		}
	}
	return false
}

func extractURLs(line string) []string {
	var urls []string
	for _, token := range strings.Fields(line) {
		url := stripLeadingPunct(stripTrailingPunct(token))
		if isURL(url) {
			urls = append(urls, url)
		}
	}
	return urls
}

func stripLeadingPunct(s string) string {
	for s != "" {
		switch s[0] {
		case '\'', '"', '(', '{', '[', '<':
			s = s[1:]
		default:
			return s
		}
	}
	return s
}

func isURL(s string) bool {
	if strings.ContainsFunc(s, unicode.IsControl) {
		return false
	}
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

var _ = io.EOF
