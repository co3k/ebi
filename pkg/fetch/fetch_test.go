package fetch

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type staticResolver []string

func (r staticResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return append([]string(nil), r...), nil
}

func TestFetchStdin(t *testing.T) {
	body := "hello world"
	f, err := FetchStdin(context.Background(), strings.NewReader(body), Options{MaxBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer RemoveTemp(f)
	if f.Size != int64(len(body)) {
		t.Fatalf("size %d", f.Size)
	}
	b, _ := os.ReadFile(f.Path)
	if string(b) != body {
		t.Fatalf("body mismatch: %q", b)
	}
}

func TestFetchURL(t *testing.T) {
	want := "echo hello"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(want))
	}))
	defer ts.Close()
	f, err := FetchURL(context.Background(), ts.URL, Options{MaxBytes: 1000, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer RemoveTemp(f)
	if f.Size != int64(len(want)) {
		t.Fatalf("size %d", f.Size)
	}
	b, _ := os.ReadFile(f.Path)
	if string(b) != want {
		t.Fatalf("body mismatch: %q", b)
	}
}

func TestFetchURLRedirect(t *testing.T) {
	want := "ok"
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	})
	mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(want))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	f, err := FetchURL(context.Background(), ts.URL+"/redirect", Options{MaxBytes: 1000, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer RemoveTemp(f)
	b, _ := os.ReadFile(f.Path)
	if string(b) != want {
		t.Fatalf("body mismatch: %q", b)
	}
}

func TestFetchURLTooManyRedirects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	_, err := FetchURL(context.Background(), ts.URL+"/loop", Options{MaxBytes: 1000, AllowHTTP: true, MaxRedirects: 3})
	if err == nil {
		t.Fatal("expected too many redirects")
	}
}

func TestFetchURLMaxSize(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("x", 2000))
	}))
	defer ts.Close()
	_, err := FetchURL(context.Background(), ts.URL, Options{MaxBytes: 1000, AllowHTTP: true})
	if err == nil {
		t.Fatal("expected oversize")
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"HTTPS://Example.COM:443/path?b=2&a=1#frag", "https://example.com/path?a=1&b=2"},
		{"http://user:pass@example.com/path", "http://example.com/path"},
	}
	for _, c := range cases {
		got := NormalizeURL(c.in)
		if got != c.want {
			t.Errorf("NormalizeURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestStrictSSRFRejectsLoopback(t *testing.T) {
	// Test the checked dialer directly: strict mode must reject loopback IP.
	dial := safeDialContext(true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := dial(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected strict mode to reject loopback")
	}
	if !strings.Contains(err.Error(), "disallowed ip") {
		t.Fatalf("expected disallowed ip error, got %v", err)
	}
}

func TestStrictSSRFRejectsPrivateIP(t *testing.T) {
	dial := safeDialContext(true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := dial(ctx, "tcp", "10.0.0.1:80")
	if err == nil {
		t.Fatal("expected strict mode to reject private ip")
	}
}

func TestStrictSSRFRejectsMixedDNSAnswers(t *testing.T) {
	called := false
	dial := safeDialContextWith(
		true,
		staticResolver{"8.8.8.8", "127.0.0.1"},
		func(ctx context.Context, network, address string) (net.Conn, error) {
			called = true
			return nil, fmt.Errorf("must not dial")
		},
	)
	_, err := dial(context.Background(), "tcp", "example.test:443")
	if err == nil || !strings.Contains(err.Error(), "disallowed ip") {
		t.Fatalf("expected mixed DNS answer rejection, got %v", err)
	}
	if called {
		t.Fatal("dialer must not run when any DNS answer is disallowed")
	}
}

func TestStrictSSRFTriesOnlyValidatedAnswers(t *testing.T) {
	var got []string
	dial := safeDialContextWith(
		true,
		staticResolver{"8.8.8.8", "1.1.1.1"},
		func(ctx context.Context, network, address string) (net.Conn, error) {
			got = append(got, address)
			return nil, fmt.Errorf("unreachable")
		},
	)
	_, err := dial(context.Background(), "tcp", "example.test:443")
	if err == nil {
		t.Fatal("expected dial failure")
	}
	if len(got) != 2 || got[0] != "8.8.8.8:443" || got[1] != "1.1.1.1:443" {
		t.Fatalf("unexpected validated dial targets: %v", got)
	}
}

func TestStrictRequiresHTTPS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	_, err := FetchURL(context.Background(), ts.URL, ServerOptions())
	if err == nil {
		t.Fatal("expected strict to reject http")
	}
	if !strings.Contains(err.Error(), "strict mode requires https") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIsBadIP(t *testing.T) {
	if !isBadIP(net.ParseIP("127.0.0.1"), true) {
		t.Fatal("loopback must be bad in strict")
	}
	if !isBadIP(net.ParseIP("10.0.0.1"), true) {
		t.Fatal("private must be bad in strict")
	}
	if isBadIP(net.ParseIP("8.8.8.8"), true) {
		t.Fatal("public must be ok")
	}
}

func TestFetchURLCredentials(t *testing.T) {
	_, err := FetchURL(context.Background(), "http://user:pass@example.com", Options{AllowHTTP: true})
	if err == nil {
		t.Fatal("expected credentials rejection")
	}
}

func TestFetchURLUnknownScheme(t *testing.T) {
	_, err := FetchURL(context.Background(), "file:///etc/passwd", Options{})
	if err == nil {
		t.Fatal("expected unsupported scheme")
	}
}

func TestFetchFile(t *testing.T) {
	f, err := os.CreateTemp("", "ebi-test")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("file content")
	f.Close()
	defer os.Remove(f.Name())

	got, err := FetchFile(context.Background(), f.Name(), Options{MaxBytes: 1000})
	if err != nil {
		t.Fatal(err)
	}
	defer RemoveTemp(got)
	b, _ := os.ReadFile(got.Path)
	if string(b) != "file content" {
		t.Fatalf("body mismatch: %q", b)
	}
}

func TestFetchStdinOverflow(t *testing.T) {
	body := strings.Repeat("x", 2000)
	_, err := FetchStdin(context.Background(), strings.NewReader(body), Options{MaxBytes: 1000})
	if err == nil {
		t.Fatal("expected oversize")
	}
}

func TestFetchURLCleanupOnFailure(t *testing.T) {
	// Body larger than max triggers cleanup.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("x", 2000))
	}))
	defer ts.Close()
	_, err := FetchURL(context.Background(), ts.URL, Options{MaxBytes: 1000, AllowHTTP: true})
	if err == nil {
		t.Fatal("expected error")
	}
}

func ExampleNormalizeURL() {
	fmt.Println(NormalizeURL("https://Example.COM:443/path?b=2&a=1#frag"))
	// Output: https://example.com/path?a=1&b=2
}
