// Package config provides user configuration loading for ebi.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/co3k/ebi/pkg/appmeta"
	"github.com/pelletier/go-toml/v2"
)

// Config is the user configuration.
type Config struct {
	ServerURLs             []string `toml:"server_urls"`
	StaticURLs             []string `toml:"static_urls"`
	PostingURLs            []string `toml:"posting_urls"`
	PolicyPath             string   `toml:"policy_path"`
	CheckpointPath         string   `toml:"checkpoint_path"`
	OptIn                  bool     `toml:"opt_in"`
	ContributionDelayHours int      `toml:"contribution_delay_hours"`
	LLM                    LLM      `toml:"llm"`
	MirrorURL              string   `toml:"mirror_url"`
}

// LLM is the LLM configuration section.
type LLM struct {
	Endpoint     string `toml:"endpoint"`
	Model        string `toml:"model"`
	APIKey       string `toml:"api_key"`
	Runs         int    `toml:"runs"`
	TimeoutSec   int    `toml:"timeout_sec"`
	Backend      string `toml:"backend"`
	Quantization string `toml:"quantization"`
}

// DefaultConfig returns a default configuration.
func DefaultConfig() Config {
	return Config{
		ServerURLs:             []string{},
		StaticURLs:             []string{},
		PostingURLs:            []string{},
		OptIn:                  false,
		ContributionDelayHours: 0,
		LLM: LLM{
			Runs:       5,
			TimeoutSec: 30,
		},
	}
}

// HomeDir returns the configured home directory (EBI_HOME or user home).
func HomeDir() (string, error) {
	if v := os.Getenv(appmeta.EnvPrefix() + "HOME"); v != "" {
		return v, nil
	}
	return os.UserHomeDir()
}

// Path returns the path to the config file.
func Path() (string, error) {
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Join(base, appmeta.ConfigDir(), appmeta.ConfigFile()), nil
	}
	home, err := HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", appmeta.ConfigDir(), appmeta.ConfigFile()), nil
}

// Dir returns the configuration directory path.
func Dir() (string, error) {
	path, err := Path()
	if err != nil {
		return "", err
	}
	return filepath.Dir(path), nil
}

// Load reads the configuration file or returns defaults.
func Load() (Config, error) {
	cfg := DefaultConfig()
	path, err := Path()
	if err != nil {
		return cfg, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg.MergeEnv()
			applyDerivedDefaults(&cfg, filepath.Dir(path))
			return cfg, nil
		}
		return cfg, err
	}
	dec := toml.NewDecoder(strings.NewReader(string(data))).DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	cfg.MergeEnv()
	applyDerivedDefaults(&cfg, filepath.Dir(path))
	return cfg, nil
}

func applyDerivedDefaults(cfg *Config, dir string) {
	if cfg.CheckpointPath == "" {
		cfg.CheckpointPath = filepath.Join(dir, "checkpoint-state.toml")
	}
}

// Save writes the configuration file atomically.
func Save(cfg Config) error {
	path, err := Path()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0600)
}

// MergeEnv overrides config values from environment variables.
func (c *Config) MergeEnv() {
	if v := os.Getenv(appmeta.EnvPrefix() + "SERVER_URL"); v != "" {
		c.ServerURLs = splitEnvList(v)
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "MIRROR_URL"); v != "" {
		c.MirrorURL = v
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "STATIC_URL"); v != "" {
		c.StaticURLs = splitEnvList(v)
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "POSTING_URL"); v != "" {
		c.PostingURLs = splitEnvList(v)
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "POLICY"); v != "" {
		c.PolicyPath = v
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "POLICY_PATH"); v != "" {
		c.PolicyPath = v
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "CHECKPOINT_PATH"); v != "" {
		c.CheckpointPath = v
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "LLM_ENDPOINT"); v != "" {
		c.LLM.Endpoint = v
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "LLM_MODEL"); v != "" {
		c.LLM.Model = v
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "LLM_API_KEY"); v != "" {
		c.LLM.APIKey = v
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "LLM_BACKEND"); v != "" {
		c.LLM.Backend = v
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "LLM_QUANTIZATION"); v != "" {
		c.LLM.Quantization = v
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "LLM_RUNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.LLM.Runs = n
		}
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "LLM_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.LLM.TimeoutSec = n
		}
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "OPT_IN"); v != "" {
		c.OptIn = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}
	if v := os.Getenv(appmeta.EnvPrefix() + "CONTRIBUTION_DELAY_HOURS"); v != "" {
		var h int
		if _, err := fmt.Sscanf(v, "%d", &h); err == nil {
			c.ContributionDelayHours = h
		}
	}
}

func splitEnvList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
