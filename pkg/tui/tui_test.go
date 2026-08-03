package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseShebangNoShebang(t *testing.T) {
	path := writeTemp(t, "echo hello\n")
	interp, args, err := ParseShebang(path)
	if err != nil {
		t.Fatal(err)
	}
	if interp != "sh" {
		t.Fatalf("expected sh, got %s", interp)
	}
	if len(args) != 0 {
		t.Fatalf("expected no args, got %v", args)
	}
}

func TestParseShebangAbsolute(t *testing.T) {
	path := writeTemp(t, "#!/bin/bash -e\necho hello\n")
	interp, args, err := ParseShebang(path)
	if err != nil {
		t.Fatal(err)
	}
	if interp != "/bin/bash" {
		t.Fatalf("expected /bin/bash, got %s", interp)
	}
	if len(args) != 1 || args[0] != "-e" {
		t.Fatalf("expected [-e], got %v", args)
	}
}

func TestParseShebangEnv(t *testing.T) {
	path := writeTemp(t, "#!/usr/bin/env bash -u\necho hello\n")
	interp, args, err := ParseShebang(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(interp, "bash") {
		t.Fatalf("expected bash, got %s", interp)
	}
	if len(args) != 1 || args[0] != "-u" {
		t.Fatalf("expected [-u], got %v", args)
	}
}

func TestParseShebangNUL(t *testing.T) {
	path := writeTemp(t, "#!/bin/sh\x00bad\necho hello\n")
	_, _, err := ParseShebang(path)
	if err == nil {
		t.Fatal("expected NUL error")
	}
}

func TestParseShebangEnvS(t *testing.T) {
	path := writeTemp(t, "#!/usr/bin/env -S bash -u\necho hello\n")
	interp, args, err := ParseShebang(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(interp, "bash") {
		t.Fatalf("expected bash, got %s", interp)
	}
	if len(args) != 1 || args[0] != "-u" {
		t.Fatalf("expected [-u], got %v", args)
	}
}

func TestParseShebangRejectsNonShell(t *testing.T) {
	path := writeTemp(t, "#!/usr/bin/env python3\nprint('hello')\n")
	if _, _, err := ParseShebang(path); err == nil {
		t.Fatal("expected non-shell interpreter rejection")
	}
}

func TestParseShebangRejectsCommandStringOption(t *testing.T) {
	path := writeTemp(t, "#!/bin/sh -c\necho hello\n")
	if _, _, err := ParseShebang(path); err == nil {
		t.Fatal("expected -c shebang rejection")
	}
}

func TestParseShebangOptionInterpreter(t *testing.T) {
	path := writeTemp(t, "#!/usr/bin/env -S\n")
	_, _, err := ParseShebang(path)
	if err == nil {
		t.Fatal("expected option interpreter error")
	}
}

func TestParseShebangRelative(t *testing.T) {
	path := writeTemp(t, "#!/bin/sh\necho hello\n")
	interp, args, err := ParseShebang(path)
	if err != nil {
		t.Fatal(err)
	}
	if interp != "/bin/sh" {
		t.Fatalf("expected /bin/sh, got %s", interp)
	}
	if len(args) != 0 {
		t.Fatalf("expected no args, got %v", args)
	}
}

func TestParseShebangEmpty(t *testing.T) {
	path := writeTemp(t, "#!\n")
	_, _, err := ParseShebang(path)
	if err == nil {
		t.Fatal("expected empty shebang error")
	}
}

func TestParseShebangMalformed(t *testing.T) {
	path := writeTemp(t, "#!/bin/sh\x00bad\necho hello\n")
	_, _, err := ParseShebang(path)
	if err == nil {
		t.Fatal("expected NUL error")
	}
}

func TestIsFlaggedBlocked(t *testing.T) {
	if !IsFlaggedBlocked(true, false) {
		t.Fatal("flagged should block")
	}
	if IsFlaggedBlocked(true, true) {
		t.Fatal("force-flagged should allow")
	}
	if IsFlaggedBlocked(false, false) {
		t.Fatal("not flagged should not block")
	}
}

func TestProductBanner(t *testing.T) {
	if ProductBanner() == "" {
		t.Fatal("empty banner")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
