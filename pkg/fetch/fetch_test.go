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
)

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
	// httptest server binds to loopback, so strict mode should reject it.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer ts.Close()
	_, err := FetchURL(context.Background(), ts.URL, ServerOptions())
	if err == nil {
		t.Fatal("expected strict mode to reject loopback")
	}
	if !strings.Contains(err.Error(), "disallowed ip") {
		t.Fatalf("expected disallowed ip error, got %v", err)
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
