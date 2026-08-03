// Package tui provides terminal interaction and safe script execution for ebi.
package tui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/co3k/ebi/pkg/appmeta"
)

// Confirm asks the user for a yes/no confirmation on the TTY.
// If no TTY is available and defaultYes is false, it returns ErrNoTTY.
// If defaultYes is true, it returns true without asking.
func Confirm(prompt string, defaultYes bool) (bool, error) {
	if defaultYes {
		return true, nil
	}
	tty, err := OpenTTY()
	if err != nil {
		return false, ErrNoTTY
	}
	defer tty.Close()
	reader := bufio.NewReader(tty)
	for {
		fmt.Fprintf(tty, "%s [y/N] ", prompt)
		line, err := reader.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("read tty: %w", err)
		}
		line = strings.TrimSpace(strings.ToLower(line))
		switch line {
		case "y", "yes":
			return true, nil
		case "n", "no", "":
			return false, nil
		default:
			fmt.Fprintln(tty, "Please answer yes or no.")
		}
	}
}

// ErrNoTTY is returned when no TTY is available for confirmation.
var ErrNoTTY = fmt.Errorf("no TTY available")

// OpenTTY opens the controlling terminal for reading and writing.
func OpenTTY() (*os.File, error) {
	if runtime.GOOS == "windows" {
		return os.OpenFile("CONIN$", os.O_RDWR, 0)
	}
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// ExecutionOptions controls how a script is executed.
type ExecutionOptions struct {
	Args         []string
	Yes          bool
	ForceFlagged bool
	KeepTemp     bool
	TtyStdin     bool // reconnect child stdin to TTY where possible
}

// ExecResult is the result of running a script.
type ExecResult struct {
	ExitCode int
}

// RunScript executes a temporary script file using a safe shebang.
// It returns the child's exit code.
func RunScript(ctx context.Context, path string, opts ExecutionOptions) (*ExecResult, error) {
	interpreter, args, err := ParseShebang(path)
	if err != nil {
		return nil, err
	}
	cmdArgs := append(args, path)
	cmdArgs = append(cmdArgs, opts.Args...)

	cmd := exec.CommandContext(ctx, interpreter, cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if opts.TtyStdin {
		if tty, err := OpenTTY(); err == nil {
			cmd.Stdin = tty
			defer tty.Close()
		} else {
			cmd.Stdin = os.Stdin
		}
	} else {
		cmd.Stdin = os.Stdin
	}

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return &ExecResult{ExitCode: exitErr.ExitCode()}, nil
		}
		return nil, err
	}
	return &ExecResult{ExitCode: 0}, nil
}

// ParseShebang reads the first line of a script and returns the interpreter
// and arguments. If there is no shebang, it returns "sh".
// It supports absolute interpreter paths and /usr/bin/env (including -S
// splitting). It rejects malformed/empty/NUL shebang, options pretending to be
// interpreter, and unsupported relative shebang.
func ParseShebang(path string) (string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", nil, err
	}
	if !strings.HasPrefix(line, "#!") {
		return "sh", nil, nil
	}
	line = strings.TrimSpace(line[2:])
	if line == "" {
		return "", nil, fmt.Errorf("empty shebang")
	}
	if strings.ContainsRune(line, '\x00') {
		return "", nil, fmt.Errorf("shebang contains NUL")
	}
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("empty shebang")
	}

	// Handle /usr/bin/env interpreter args...
	if parts[0] == "/usr/bin/env" {
		if len(parts) == 1 {
			return "", nil, fmt.Errorf("env shebang missing interpreter")
		}
		// Support -S splitting.
		args := parts[1:]
		if args[0] == "-S" {
			args = strings.Fields(strings.Join(args[1:], " "))
		}
		if len(args) == 0 || args[0] == "" {
			return "", nil, fmt.Errorf("env shebang missing interpreter")
		}
		interp := args[0]
		// Options pretending to be interpreter are rejected.
		if strings.HasPrefix(interp, "-") {
			return "", nil, fmt.Errorf("env shebang interpreter is an option: %s", interp)
		}
		// If not an absolute path, look it up in PATH.
		if !filepath.IsAbs(interp) {
			resolved, err := exec.LookPath(interp)
			if err != nil {
				return "", nil, fmt.Errorf("shebang interpreter not found in PATH: %s", interp)
			}
			interp = resolved
		}
		if err := validateShellInterpreter(interp, args[1:]); err != nil {
			return "", nil, err
		}
		return interp, args[1:], nil
	}

	interp := parts[0]
	// Reject options pretending to be interpreter.
	if strings.HasPrefix(interp, "-") {
		return "", nil, fmt.Errorf("shebang interpreter is an option: %s", interp)
	}
	// Unsupported relative shebang.
	if !filepath.IsAbs(interp) {
		return "", nil, fmt.Errorf("shebang interpreter must be absolute: %s", interp)
	}
	// Verify interpreter path exists.
	if _, err := os.Stat(interp); err != nil {
		return "", nil, fmt.Errorf("shebang interpreter not found: %s", interp)
	}
	if err := validateShellInterpreter(interp, parts[1:]); err != nil {
		return "", nil, err
	}
	return interp, parts[1:], nil
}

func validateShellInterpreter(interpreter string, args []string) error {
	name := strings.ToLower(filepath.Base(interpreter))
	switch name {
	case "sh", "bash", "dash", "ash", "ksh", "zsh":
	default:
		return fmt.Errorf("unsupported non-shell shebang interpreter %q", name)
	}
	for _, arg := range args {
		switch arg {
		case "-c", "--command", "-s", "--stdin":
			return fmt.Errorf("unsafe shebang interpreter option %q", arg)
		}
	}
	return nil
}

// IsFlaggedBlocked reports whether the CLI should block execution even with --yes.
func IsFlaggedBlocked(flagged, forceFlagged bool) bool {
	return flagged && !forceFlagged
}

// ProductBanner returns a short product banner.
func ProductBanner() string {
	return appmeta.AppName + " " + appmeta.Version
}
