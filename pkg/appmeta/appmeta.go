// Package appmeta holds central product metadata for the ebi project.
// All user-visible names and config/env prefixes derive from AppName so that
// a future rename only needs to change this single constant.
package appmeta

const (
	AppName = "ebi"
	Version = "0.1.0"
)

// UserAgent returns the HTTP user-agent string used by ebi tools.
func UserAgent() string {
	return AppName + "/" + Version
}

// EnvPrefix returns the prefix used for environment variable configuration.
func EnvPrefix() string {
	return "EBI_"
}

// ConfigDir returns the application configuration directory name under the
// user's configuration root.
func ConfigDir() string {
	return AppName
}

// ConfigFile returns the primary configuration file name.
func ConfigFile() string {
	return "config.toml"
}

// KeyFile returns the Ed25519 private key file name.
func KeyFile() string {
	return "key"
}
