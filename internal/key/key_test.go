package key

import (
	"os"
	"testing"

	"github.com/co3k/ebi/pkg/schema"
)

func TestLoadOrCreate(t *testing.T) {
	os.Setenv("HOME", t.TempDir())
	defer os.Unsetenv("HOME")
	k1, err := LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if len(k1.Private) == 0 || len(k1.Public) == 0 {
		t.Fatal("empty key")
	}
	k2, err := LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if k1.PublicKeyHex() != k2.PublicKeyHex() {
		t.Fatal("idempotency failed")
	}
	info, err := os.Stat(mustPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key mode %o", info.Mode().Perm())
	}
}

func TestAuditorID(t *testing.T) {
	os.Setenv("HOME", t.TempDir())
	defer os.Unsetenv("HOME")
	k, err := LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if k.AuditorID() != schema.AuditorHash(k.PublicKeyHex()) {
		t.Fatal("auditor id mismatch")
	}
}

func mustPath(t *testing.T) string {
	t.Helper()
	p, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	return p
}
