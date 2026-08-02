package appmeta

import "testing"

func TestAppName(t *testing.T) {
	if AppName != "ebi" {
		t.Fatalf("AppName must be ebi, got %q", AppName)
	}
	if UserAgent() != "ebi/0.1.0" {
		t.Fatalf("unexpected user agent: %q", UserAgent())
	}
	if EnvPrefix() != "EBI_" {
		t.Fatalf("unexpected env prefix: %q", EnvPrefix())
	}
}
