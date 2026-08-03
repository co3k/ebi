package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/co3k/ebi/pkg/appmeta"
)

func TestLoadDefault(t *testing.T) {
	t.Setenv("EBI_SERVER_URL", "")
	t.Setenv("EBI_MIRROR_URL", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// No fake default production hostname.
	if len(cfg.ServerURLs) != 0 {
		t.Fatalf("expected no default server URLs, got %v", cfg.ServerURLs)
	}
	if cfg.CheckpointPath == "" {
		t.Fatal("expected a default persisted checkpoint path")
	}
}

func TestEnvOverridesWithoutConfigFile(t *testing.T) {
	t.Setenv("EBI_HOME", t.TempDir())
	t.Setenv("EBI_SERVER_URL", "https://one.example, https://two.example")
	t.Setenv("EBI_OPT_IN", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ServerURLs) != 2 || cfg.ServerURLs[1] != "https://two.example" {
		t.Fatalf("environment URLs were not applied: %v", cfg.ServerURLs)
	}
	if !cfg.OptIn {
		t.Fatal("environment opt-in was not applied")
	}
}

func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	os.Unsetenv("XDG_CONFIG_HOME")
	os.Unsetenv("EBI_HOME")
	defer os.Unsetenv("HOME")

	cfg := Config{ServerURLs: []string{"https://x.example.com"}, OptIn: true}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.ServerURLs) != 1 || loaded.ServerURLs[0] != "https://x.example.com" {
		t.Fatalf("server URL mismatch: %v", loaded.ServerURLs)
	}
	if !loaded.OptIn {
		t.Fatal("opt_in mismatch")
	}
	info, err := os.Stat(filepath.Join(dir, ".config", appmeta.ConfigDir(), appmeta.ConfigFile()))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config mode %o", info.Mode().Perm())
	}
}

func TestMergeEnv(t *testing.T) {
	cfg := DefaultConfig()
	os.Setenv(appmeta.EnvPrefix()+"LLM_ENDPOINT", "http://localhost:11434/v1")
	os.Setenv(appmeta.EnvPrefix()+"LLM_MODEL", "mistral")
	os.Setenv(appmeta.EnvPrefix()+"OPT_IN", "1")
	os.Setenv(appmeta.EnvPrefix()+"MIRROR_URL", "https://mirror.example.com")
	os.Setenv(appmeta.EnvPrefix()+"CONTRIBUTION_DELAY_HOURS", "12")
	defer func() {
		os.Unsetenv(appmeta.EnvPrefix() + "LLM_ENDPOINT")
		os.Unsetenv(appmeta.EnvPrefix() + "LLM_MODEL")
		os.Unsetenv(appmeta.EnvPrefix() + "OPT_IN")
		os.Unsetenv(appmeta.EnvPrefix() + "MIRROR_URL")
		os.Unsetenv(appmeta.EnvPrefix() + "CONTRIBUTION_DELAY_HOURS")
	}()
	cfg.MergeEnv()
	if cfg.LLM.Endpoint != "http://localhost:11434/v1" {
		t.Fatalf("endpoint mismatch: %s", cfg.LLM.Endpoint)
	}
	if cfg.LLM.Model != "mistral" {
		t.Fatalf("model mismatch: %s", cfg.LLM.Model)
	}
	if !cfg.OptIn {
		t.Fatal("opt_in mismatch")
	}
	if cfg.MirrorURL != "https://mirror.example.com" {
		t.Fatalf("mirror URL mismatch: %s", cfg.MirrorURL)
	}
	if cfg.ContributionDelayHours != 12 {
		t.Fatalf("delay mismatch: %d", cfg.ContributionDelayHours)
	}
}

func TestEBIHome(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("EBI_HOME", dir)
	os.Unsetenv("XDG_CONFIG_HOME")
	defer os.Unsetenv("EBI_HOME")
	p, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p, dir) {
		t.Fatalf("expected EBI_HOME in path: %s", p)
	}
}

func TestXDGConfig(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("XDG_CONFIG_HOME", dir)
	os.Unsetenv("EBI_HOME")
	defer os.Unsetenv("XDG_CONFIG_HOME")
	p, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, dir) {
		t.Fatalf("expected XDG config dir: %s", p)
	}
}

func TestMalformedConfig(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("HOME", dir)
	os.Unsetenv("EBI_HOME")
	os.Unsetenv("XDG_CONFIG_HOME")
	defer os.Unsetenv("HOME")
	path, _ := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not valid toml"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected malformed config to error")
	}
}

func TestUnknownConfigField(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("EBI_HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	path, _ := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("unknown_field = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected unknown config field to fail")
	}
}
