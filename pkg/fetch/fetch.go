// Package fetch streams stdin or a URL to a private temporary file before any
// further analysis or execution. It hashes exact bytes and implements SSRF-safe
// URL fetching in strict mode.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/co3k/ebi/pkg/appmeta"
)

// Default size cap: 10 MiB.
const DefaultMaxBytes = 10 << 20

// Fetched holds the result of a fetch operation.
type Fetched struct {
	Path          string
	Size          int64
	Hash          string // SHA-256 hex of exact bytes
	URL           string // original URL
	NormalizedURL string // canonical form used for records/lookups
	Local         bool   // true for stdin or local file source
}

// Options controls fetch behavior.
type Options struct {
	MaxBytes      int64
	Timeout       time.Duration
	AllowHTTP     bool // non-strict mode
	StrictHTTPS   bool // server-side strict mode
	MaxRedirects  int
	UserAgent     string
	Header        http.Header
	TempDir       string
}

// DefaultOptions returns a conservative default configuration.
func DefaultOptions() Options {
	return Options{
		MaxBytes:     DefaultMaxBytes,
		Timeout:      30 * time.Second,
		AllowHTTP:    true,
		MaxRedirects: 3,
		UserAgent:    appmeta.UserAgent(),
	}
}

// ServerOptions returns strict mode options suitable for the server.
func ServerOptions() Options {
	o := DefaultOptions()
	o.AllowHTTP = false
	o.StrictHTTPS = true
	return o
}

// FetchStdin reads up to MaxBytes from r into a 0600 temp file.
func FetchStdin(ctx context.Context, r io.Reader, opts Options) (*Fetched, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	f, err := tempFile(opts.TempDir)
	if err != nil {
		return nil, err
	}
	path := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(path)
		}
	}()

	h := sha256.New()
	w := io.MultiWriter(f, h)
	lr := io.LimitedReader{R: r, N: opts.MaxBytes + 1}
	n, err := io.Copy(w, &lr)
	if err != nil && !errors.Is(err, io.EOF) {
		f.Close()
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if n > opts.MaxBytes {
		f.Close()
		return nil, fmt.Errorf("stdin exceeds max size %d", opts.MaxBytes)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	cleanup = false
	return &Fetched{
		Path:          path,
		Size:          n,
		Hash:          hex.EncodeToString(h.Sum(nil)),
		URL:           "",
		NormalizedURL: "",
		Local:         true,
	}, nil
}

// FetchURL fetches a URL into a 0600 temp file, verifying size and hash.
func FetchURL(ctx context.Context, rawURL string, opts Options) (*Fetched, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 3
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	if err := validateURL(u, opts.StrictHTTPS, opts.AllowHTTP); err != nil {
		return nil, fmt.Errorf("validate url: %w", err)
	}

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			DialContext: safeDialContext(opts.StrictHTTPS),
		},
	}
	redirects := 0
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		redirects++
		if redirects > opts.MaxRedirects {
			return fmt.Errorf("too many redirects")
		}
		if err := validateURL(req.URL, opts.StrictHTTPS, opts.AllowHTTP); err != nil {
			return fmt.Errorf("redirect validation: %w", err)
		}
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	}
	for k, v := range opts.Header {
		if len(v) > 0 {
			req.Header.Set(k, v[0])
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	f, err := tempFile(opts.TempDir)
	if err != nil {
		return nil, err
	}
	path := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(path)
		}
	}()

	h := sha256.New()
	w := io.MultiWriter(f, h)
	lr := io.LimitedReader{R: resp.Body, N: opts.MaxBytes + 1}
	n, err := io.Copy(w, &lr)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("read body: %w", err)
	}
	if n > opts.MaxBytes {
		f.Close()
		return nil, fmt.Errorf("body exceeds max size %d", opts.MaxBytes)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	cleanURL := NormalizeURL(rawURL)
	cleanup = false
	return &Fetched{
		Path:          path,
		Size:          n,
		Hash:          hex.EncodeToString(h.Sum(nil)),
		URL:           rawURL,
		NormalizedURL: cleanURL,
		Local:         false,
	}, nil
}

// FetchFile copies an existing local file into a 0600 temp file.
func FetchFile(ctx context.Context, path string, opts Options) (*Fetched, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	in, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > opts.MaxBytes {
		return nil, fmt.Errorf("file exceeds max size %d", opts.MaxBytes)
	}
	return FetchStdin(ctx, in, opts)
}

// NormalizeURL returns a canonical form for the URL without leaking credentials.
// It lowercases the scheme and host, removes the default port, strips the user
// info and fragment, and sorts query parameters.
func NormalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.User = nil
	u.Fragment = ""
	u.RawFragment = ""
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port != "" {
		if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
			port = ""
		}
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
	}
	if u.RawQuery != "" {
		q, _ := url.ParseQuery(u.RawQuery)
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := []string{}
		for _, k := range keys {
			vals := q[k]
			sort.Strings(vals)
			for _, v := range vals {
				parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
			}
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	return u.String()
}

func tempFile(dir string) (*os.File, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.CreateTemp(dir, "ebi-fetch-*")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(f.Name(), 0600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	return f, nil
}

func validateURL(u *url.URL, strict, allowHTTP bool) error {
	scheme := strings.ToLower(u.Scheme)
	if strict && scheme != "https" {
		return fmt.Errorf("strict mode requires https, got %s", scheme)
	}
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported scheme %s", scheme)
	}
	if !allowHTTP && scheme == "http" {
		return fmt.Errorf("http not allowed in strict mode")
	}
	if u.User != nil {
		return fmt.Errorf("credentials in url are not allowed")
	}
	return nil
}

func safeDialContext(strict bool) func(ctx context.Context, network, address string) (net.Conn, error) {
	resolver := net.DefaultResolver
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		ips, err := resolver.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no ips for %s", host)
		}
		for _, ipStr := range ips {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			if isBadIP(ip, strict) {
				return nil, fmt.Errorf("disallowed ip %s for host %s", ipStr, host)
			}
		}
		d := net.Dialer{Timeout: 10 * time.Second}
		return d.DialContext(ctx, network, address)
	}
}

func isBadIP(ip net.IP, strict bool) bool {
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return strict
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return strict
	}
	if ip.IsPrivate() {
		return strict
	}
	if strict {
		// IPv4 reserved / documentation ranges.
		if ones, _ := ip.DefaultMask().Size(); ones == 8 && ip[0] == 0 {
			return true
		}
		if ip4 := ip.To4(); ip4 != nil {
			if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0 { // 192.0.0.0/24
				return true
			}
			if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 { // 192.0.2.0/24 TEST-NET
				return true
			}
			if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 { // 198.51.100.0/24
				return true
			}
			if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 { // 203.0.113.0/24
				return true
			}
			if ip4[0] >= 240 && ip4[0] < 255 { // IPv4 reserved class E
				return true
			}
			if ip4[0] == 255 { // limited broadcast
				return true
			}
		}
		if ip.IsIPv4MappedIPv6() {
			ip4 := ip.To4()
			return isBadIP(ip4, strict)
		}
	}
	return false
}

// RemoveTemp removes the temporary fetched file.
func RemoveTemp(f *Fetched) {
	if f != nil && f.Path != "" && filepath.Dir(f.Path) != "" {
		os.Remove(f.Path)
	}
}

// FormatSize returns a human-readable size string.
func FormatSize(n int64) string {
	if n < 1024 {
		return strconv.FormatInt(n, 10)
	}
	return fmt.Sprintf("%d bytes", n)
}
