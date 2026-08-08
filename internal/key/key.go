// Package key manages the Ed25519 user key for ebi.
package key

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/co3k/ebi/internal/config"
)

// Key is the user's Ed25519 key pair.
type Key struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// Path returns the key file path.
func Path() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "key"), nil
}

// LoadOrCreate loads an existing key or creates one if missing.
// It is idempotent: if a key exists it is reused.
// A malformed existing key returns an error rather than silently replacing.
func LoadOrCreate() (*Key, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		if len(data) == 0 {
			return nil, fmt.Errorf("key file is empty")
		}
		var b []byte
		// Accept hex-encoded or raw binary key.
		if len(data) == ed25519.PrivateKeySize*2 {
			dec, err := hex.DecodeString(string(data))
			if err != nil {
				return nil, fmt.Errorf("decode key: %w", err)
			}
			b = dec
		} else if len(data) == ed25519.PrivateKeySize {
			b = data
		} else {
			return nil, fmt.Errorf("malformed key file size %d", len(data))
		}
		if len(b) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("malformed key size %d", len(b))
		}
		return fromBytes(b)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := atomicWriteFile(path, []byte(hex.EncodeToString(priv)), 0600); err != nil {
		return nil, err
	}
	return fromBytes(priv)
}

func fromBytes(priv []byte) (*Key, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key size %d", len(priv))
	}
	return &Key{Private: ed25519.PrivateKey(priv), Public: ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)}, nil
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

// PublicKeyHex returns the public key as hex.
func (k *Key) PublicKeyHex() string {
	return hex.EncodeToString(k.Public)
}

// AuditorID returns the SHA-256 hex of the public key.
func (k *Key) AuditorID() string {
	h := sha256.Sum256(k.Public)
	return hex.EncodeToString(h[:])
}

// Sign signs data with the private key.
func (k *Key) Sign(data []byte) []byte {
	return ed25519.Sign(k.Private, data)
}

// ExportPublicKey returns the public key hex string, never the private key.
func (k *Key) ExportPublicKey() string {
	return k.PublicKeyHex()
}

// ID returns the auditor ID (SHA-256 of public key).
func (k *Key) ID() string {
	return k.AuditorID()
}
