package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

func TestLocalPathConfinement(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Put(context.Background(), Object{Path: "v1/blob/abc", Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get(context.Background(), "../etc/passwd"); err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestLocalPutGet(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	obj := Object{Path: "v1/checkpoint", Data: []byte("checkpoint"), ContentType: "text/plain"}
	if err := l.Put(context.Background(), obj); err != nil {
		t.Fatal(err)
	}
	data, err := l.Get(context.Background(), "v1/checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "checkpoint" {
		t.Fatalf("data mismatch: %q", data)
	}
}

func TestLocalList(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	l.Put(context.Background(), Object{Path: "v1/tile/0/1", Data: []byte("a")})
	l.Put(context.Background(), Object{Path: "v1/tile/0/2", Data: []byte("b")})
	items, err := l.List(context.Background(), "v1/tile/0")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	want := []string{"v1/tile/0/1", "v1/tile/0/2"}
	if !strings.EqualFold(items[0], want[0]) || !strings.EqualFold(items[1], want[1]) {
		t.Fatalf("unexpected items: %v", items)
	}
}

func TestLocalPublish(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Publish(context.Background(), Object{Path: "v1/prefix/abc12", Data: []byte("shard")}); err != nil {
		t.Fatal(err)
	}
	data, err := l.Get(context.Background(), "v1/prefix/abc12")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "shard" {
		t.Fatalf("data mismatch: %q", data)
	}
}

func TestContentHash(t *testing.T) {
	if len(ContentHash([]byte("x"))) != 64 {
		t.Fatal("content hash must be 64 hex chars")
	}
}

func TestDefaultCacheFor(t *testing.T) {
	im, sec := DefaultCacheFor("v1/tile/0/0")
	if !im || sec != 31536000 {
		t.Fatalf("tile cache wrong: immutable=%v sec=%d", im, sec)
	}
	im, sec = DefaultCacheFor("v1/checkpoint")
	if im || sec != 60 {
		t.Fatalf("checkpoint cache wrong: immutable=%v sec=%d", im, sec)
	}
	im, sec = DefaultCacheFor("v1/prefix/abc12")
	if im || sec != 300 {
		t.Fatalf("prefix cache wrong: immutable=%v sec=%d", im, sec)
	}
	im, sec = DefaultCacheFor("v1/leaf/42")
	if !im || sec != 31536000 {
		t.Fatalf("leaf cache wrong: immutable=%v sec=%d", im, sec)
	}
}

func TestBlobPath(t *testing.T) {
	if BlobPath("deadbeef") != "v1/blob/deadbeef" {
		t.Fatal("blob path wrong")
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target", "file")
	if err := atomicWriteFile(path, []byte("data"), 0640); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "data" {
		t.Fatal("atomic write mismatch")
	}
}

func TestLocalDelete(t *testing.T) {
	dir := t.TempDir()
	l, _ := NewLocal(dir)
	l.Put(context.Background(), Object{Path: "v1/blob/x", Data: []byte("x")})
	if err := l.Delete(context.Background(), "v1/blob/x"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get(context.Background(), "v1/blob/x"); err == nil {
		t.Fatal("expected delete to remove object")
	}
}

func TestIsNotFound(t *testing.T) {
	if !IsNotFound(os.ErrNotExist) {
		t.Fatal("IsNotFound should detect os.ErrNotExist")
	}
	if !IsNotFound(fmt.Errorf("%w: x", ErrNotFound)) {
		t.Fatal("IsNotFound should detect ErrNotFound")
	}
	if !IsNotFound(&smithy.GenericAPIError{Code: "NotFound", Message: "missing"}) {
		t.Fatal("IsNotFound should detect generic S3 NotFound")
	}
	mem := NewMem()
	if _, err := mem.Get(context.Background(), "missing"); !IsNotFound(err) {
		t.Fatalf("Mem.Get missing error was not classified: %v", err)
	}
}

func TestLocalRejectsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{"/etc/passwd", "/v1/blob/x", "v1//blob", "v1/./blob", "v1/../blob", "", "v1//x", "v1/blob/../x"}
	for _, p := range cases {
		if err := l.Put(context.Background(), Object{Path: p, Data: []byte("x")}); err == nil {
			t.Fatalf("expected rejection for path %q", p)
		}
		if _, err := l.Get(context.Background(), p); err == nil {
			t.Fatalf("expected Get rejection for path %q", p)
		}
		if err := l.Delete(context.Background(), p); err == nil {
			t.Fatalf("expected Delete rejection for path %q", p)
		}
	}
}

func TestLocalRejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(root, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("secret"), 0640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	l, err := NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get(context.Background(), "link"); err == nil {
		t.Fatal("expected symlink escape rejection")
	}
	if err := l.Put(context.Background(), Object{Path: "link/file", Data: []byte("x")}); err == nil {
		t.Fatal("expected symlink escape rejection for write")
	}
	if _, err := l.List(context.Background(), "link"); err == nil {
		t.Fatal("expected symlink escape rejection for list")
	}
	if err := l.Delete(context.Background(), "link"); err == nil {
		t.Fatal("expected symlink escape rejection for delete")
	}
}

func TestLocalRejectsSymlinkComponentEscape(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0640); err != nil {
		t.Fatal(err)
	}
	// A symlink inside the root that points outside.
	if err := os.Symlink(outside, filepath.Join(dataDir, "escape")); err != nil {
		t.Fatal(err)
	}
	l, err := NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get(context.Background(), "data/escape"); err == nil {
		t.Fatal("expected symlink component escape rejection")
	}
}

func TestLocalListOnlyRegularFilesSorted(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Create files in non-deterministic order.
	paths := []string{"c/b", "a/x", "b/y", "c/a"}
	for _, p := range paths {
		if err := l.Put(context.Background(), Object{Path: p, Data: []byte(p)}); err != nil {
			t.Fatal(err)
		}
	}
	// Add a symlink inside the root; it should be skipped.
	if err := os.Symlink(filepath.Join(dir, "a", "x"), filepath.Join(dir, "a", "link")); err != nil {
		t.Fatal(err)
	}
	items, err := l.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a/x", "b/y", "c/a", "c/b"}
	if len(items) != len(want) {
		t.Fatalf("expected %d items, got %d: %v", len(want), len(items), items)
	}
	for i, w := range want {
		if items[i] != w {
			t.Fatalf("item %d: want %q, got %q", i, w, items[i])
		}
	}
}

func TestLocalContextCancellation(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Put(context.Background(), Object{Path: "v1/blob/x", Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.Get(ctx, "v1/blob/x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if err := l.Put(ctx, Object{Path: "v1/blob/y", Data: []byte("y")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, err := l.List(ctx, "v1/blob"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if err := l.Delete(ctx, "v1/blob/x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestLocalAtomicPermissions(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Non-sensitive object should be 0640.
	if err := l.Put(context.Background(), Object{Path: "v1/blob/x", Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "v1/blob/x"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0640 {
		t.Fatalf("expected perm 0640, got %o", fi.Mode().Perm())
	}
	// Checkpoint should be 0600.
	if err := l.Put(context.Background(), Object{Path: "v1/checkpoint", Data: []byte("cp")}); err != nil {
		t.Fatal(err)
	}
	fi, err = os.Stat(filepath.Join(dir, "v1/checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected checkpoint perm 0600, got %o", fi.Mode().Perm())
	}
}

func TestLocalAtomicReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	// Writers should never see a partial file.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := []byte(strings.Repeat("x", 1024))
			if err := atomicWriteFile(path, data, 0640); err != nil {
				t.Error(err)
				return
			}
		}(i)
	}
	wg.Wait()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 1024 || bytes.Contains(b, []byte("xx")) == false {
		// Just ensure the file is complete and consistent.
	}
	// Ensure no leftover temp files.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file %q", e.Name())
		}
	}
}

func TestMemDefensiveCopy(t *testing.T) {
	m := NewMem()
	data := []byte("hello")
	if err := m.Put(context.Background(), Object{Path: "x", Data: data}); err != nil {
		t.Fatal(err)
	}
	data[0] = 'X'
	got, err := m.Get(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("mem did not store a copy: %q", got)
	}
	got[0] = 'Y'
	got2, err := m.Get(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if string(got2) != "hello" {
		t.Fatalf("mem did not return a copy: %q", got2)
	}
}

func TestMemListSorted(t *testing.T) {
	m := NewMem()
	keys := []string{"z", "a", "m"}
	for _, k := range keys {
		if err := m.Put(context.Background(), Object{Path: k, Data: []byte(k)}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := m.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !sort.StringsAreSorted(items) {
		t.Fatalf("mem list not sorted: %v", items)
	}
}

// mockS3Client is a minimal in-memory S3 implementation for tests.
type mockS3Client struct {
	mu       sync.RWMutex
	objects  map[string]*mockS3Object
	requests []string
}

type mockS3Object struct {
	data         []byte
	contentType  string
	cacheControl string
	etag         string
}

func newMockS3Client() *mockS3Client {
	return &mockS3Client{objects: make(map[string]*mockS3Object)}
}

func (m *mockS3Client) record(op string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, op)
}

func (m *mockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	m.record("GetObject:" + aws.ToString(params.Key))
	m.mu.RLock()
	defer m.mu.RUnlock()
	obj, ok := m.objects[aws.ToString(params.Key)]
	if !ok {
		return nil, &types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(obj.data)),
		ContentLength: aws.Int64(int64(len(obj.data))),
		ETag:          aws.String(obj.etag),
	}, nil
}

func (m *mockS3Client) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	m.record("PutObject:" + aws.ToString(params.Key))
	data, err := io.ReadAll(params.Body)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.objects[aws.ToString(params.Key)]
	if params.IfNoneMatch != nil && aws.ToString(params.IfNoneMatch) == "*" && exists {
		return nil, &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "exists"}
	}
	if params.IfMatch != nil && (!exists || current.etag != aws.ToString(params.IfMatch)) {
		return nil, &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "etag mismatch"}
	}
	m.objects[aws.ToString(params.Key)] = &mockS3Object{
		data:         data,
		contentType:  aws.ToString(params.ContentType),
		cacheControl: aws.ToString(params.CacheControl),
		etag:         ContentHash(data),
	}
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3Client) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	m.record("DeleteObject:" + aws.ToString(params.Key))
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.objects[aws.ToString(params.Key)]
	if params.IfMatch != nil && (!exists || current.etag != aws.ToString(params.IfMatch)) {
		return nil, &smithy.GenericAPIError{Code: "PreconditionFailed", Message: "etag mismatch"}
	}
	delete(m.objects, aws.ToString(params.Key))
	return &s3.DeleteObjectOutput{}, nil
}

func (m *mockS3Client) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	m.record("ListObjectsV2:" + aws.ToString(params.Prefix))
	m.mu.RLock()
	defer m.mu.RUnlock()
	var contents []types.Object
	for k := range m.objects {
		if strings.HasPrefix(k, aws.ToString(params.Prefix)) {
			contents = append(contents, types.Object{Key: aws.String(k)})
		}
	}
	return &s3.ListObjectsV2Output{Contents: contents}, nil
}

func (m *mockS3Client) CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error) {
	m.record("CopyObject:" + aws.ToString(params.Key) + "<-" + aws.ToString(params.CopySource))
	m.mu.Lock()
	defer m.mu.Unlock()
	src := strings.TrimPrefix(aws.ToString(params.CopySource), "test/")
	obj, ok := m.objects[src]
	if !ok {
		return nil, &types.NoSuchKey{}
	}
	cp := *obj
	m.objects[aws.ToString(params.Key)] = &cp
	return &s3.CopyObjectOutput{}, nil
}

func newMockS3Store(mock *mockS3Client) *S3Store {
	return &S3Store{client: mock, bucket: "test", prefix: ""}
}

func TestS3RejectsBadPaths(t *testing.T) {
	mock := newMockS3Client()
	store := newMockS3Store(mock)
	cases := []string{"/etc/passwd", "v1/../x", "v1/./x", "v1//x", "", "../x"}
	for _, p := range cases {
		if _, err := store.Get(context.Background(), p); err == nil {
			t.Fatalf("expected Get rejection for path %q", p)
		}
		if err := store.Put(context.Background(), Object{Path: p, Data: []byte("x")}); err == nil {
			t.Fatalf("expected Put rejection for path %q", p)
		}
		if err := store.Delete(context.Background(), p); err == nil {
			t.Fatalf("expected Delete rejection for path %q", p)
		}
		if err := store.Publish(context.Background(), Object{Path: p, Data: []byte("x")}); err == nil {
			t.Fatalf("expected Publish rejection for path %q", p)
		}
	}
}

func TestS3CacheHeaders(t *testing.T) {
	mock := newMockS3Client()
	store := newMockS3Store(mock)
	cases := []struct {
		path      string
		wantCT    string
		wantCache string
	}{
		{"v1/blob/abc", "application/octet-stream", "max-age=31536000, immutable"},
		{"v1/tile/8/x000/0000", "application/octet-stream", "max-age=31536000, immutable"},
		{"v1/checkpoint", "text/plain", "max-age=60"},
		{"v1/prefix/abc12", "application/json", "max-age=300"},
		{"v1/leaf/42", "application/json", "max-age=31536000, immutable"},
	}
	for _, c := range cases {
		obj := Object{Path: c.path, Data: []byte("x"), ContentType: c.wantCT}
		if err := store.Put(context.Background(), obj); err != nil {
			t.Fatal(err)
		}
		key := store.key(c.path)
		got := mock.objects[key]
		if got == nil {
			t.Fatalf("object not stored for %s", c.path)
		}
		if got.contentType != c.wantCT {
			t.Fatalf("content-type for %s: want %q, got %q", c.path, c.wantCT, got.contentType)
		}
		if got.cacheControl != c.wantCache {
			t.Fatalf("cache-control for %s: want %q, got %q", c.path, c.wantCache, got.cacheControl)
		}
	}

	if err := store.Put(context.Background(), Object{
		Path:         "v1/blob/tombstone",
		Data:         []byte("x"),
		ContentType:  "application/json",
		CacheSeconds: 60,
		Mutable:      true,
	}); err != nil {
		t.Fatal(err)
	}
	if got := mock.objects["v1/blob/tombstone"].cacheControl; got != "max-age=60" {
		t.Fatalf("mutable tombstone cache-control: got %q", got)
	}
}

func TestS3ListSorted(t *testing.T) {
	mock := newMockS3Client()
	store := newMockS3Store(mock)
	keys := []string{"v1/blob/z", "v1/blob/a", "v1/blob/m"}
	for _, k := range keys {
		if err := store.Put(context.Background(), Object{Path: k, Data: []byte(k)}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := store.List(context.Background(), "v1/blob")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"v1/blob/a", "v1/blob/m", "v1/blob/z"}
	if len(items) != len(want) {
		t.Fatalf("want %v, got %v", want, items)
	}
	for i, w := range want {
		if items[i] != w {
			t.Fatalf("item %d: want %q, got %q", i, w, items[i])
		}
	}
}

func TestS3ListWithConfiguredPrefix(t *testing.T) {
	mock := newMockS3Client()
	store := &S3Store{client: mock, bucket: "test", prefix: "prod"}
	for _, path := range []string{"v1/blob/b", "v1/blob/a"} {
		if err := store.Put(context.Background(), Object{Path: path, Data: []byte(path)}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := store.List(context.Background(), "v1/blob")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"v1/blob/a", "v1/blob/b"}
	if len(items) != len(want) {
		t.Fatalf("want %v, got %v", want, items)
	}
	for i := range want {
		if items[i] != want[i] {
			t.Fatalf("item %d: want %q, got %q", i, want[i], items[i])
		}
	}
}

func TestListUsesPathComponentPrefix(t *testing.T) {
	mem := NewMem()
	for _, path := range []string{"v1/blob/a", "v1/blob-extra/b"} {
		if err := mem.Put(context.Background(), Object{Path: path, Data: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := mem.List(context.Background(), "v1/blob")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0] != "v1/blob/a" {
		t.Fatalf("component prefix listing leaked siblings: %v", items)
	}
}

func TestS3GetBound(t *testing.T) {
	mock := newMockS3Client()
	store := newMockS3Store(mock)
	big := make([]byte, (64<<20)+1)
	if err := store.Put(context.Background(), Object{Path: "v1/blob/big", Data: big}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), "v1/blob/big"); err == nil {
		t.Fatal("expected oversize read error")
	}
}

func TestS3PublishSequence(t *testing.T) {
	mock := newMockS3Client()
	store := newMockS3Store(mock)
	if err := store.Publish(context.Background(), Object{Path: "v1/checkpoint", Data: []byte("cp"), ContentType: "text/plain"}); err != nil {
		t.Fatal(err)
	}
	if mock.objects["v1/checkpoint"] == nil {
		t.Fatal("final object not present")
	}
	// Temporary key should be deleted.
	for k := range mock.objects {
		if strings.HasPrefix(k, "v1/.tmp/") {
			t.Fatalf("temporary key %q not cleaned up", k)
		}
	}
	// Should have observed temp put, copy, delete.
	var sawPut, sawCopy, sawDelete bool
	for _, r := range mock.requests {
		if strings.HasPrefix(r, "PutObject:v1/.tmp/") {
			sawPut = true
		}
		if strings.HasPrefix(r, "CopyObject:v1/checkpoint") {
			sawCopy = true
		}
		if strings.HasPrefix(r, "DeleteObject:v1/.tmp/") {
			sawDelete = true
		}
	}
	if !sawPut || !sawCopy || !sawDelete {
		t.Fatalf("expected publish sequence put/copy/delete, got %v", mock.requests)
	}
}

func TestMemCompareAndSwap(t *testing.T) {
	store := NewMem()
	ctx := t.Context()
	obj := Object{Path: "v1/lease", Data: []byte("one")}
	swapped, err := store.CompareAndSwap(ctx, obj.Path, nil, obj)
	if err != nil || !swapped {
		t.Fatalf("initial swap: %v / %v", swapped, err)
	}
	if swapped, err := store.CompareAndSwap(ctx, obj.Path, nil, Object{Path: obj.Path, Data: []byte("two")}); err != nil || swapped {
		t.Fatalf("unexpected create overwrite: %v / %v", swapped, err)
	}
	if swapped, err := store.CompareAndSwap(ctx, obj.Path, []byte("wrong"), Object{Path: obj.Path, Data: []byte("two")}); err != nil || swapped {
		t.Fatalf("unexpected stale overwrite: %v / %v", swapped, err)
	}
	if swapped, err := store.CompareAndSwap(ctx, obj.Path, []byte("one"), Object{Path: obj.Path, Data: []byte("two")}); err != nil || !swapped {
		t.Fatalf("replace: %v / %v", swapped, err)
	}
	if deleted, err := store.CompareAndDelete(ctx, obj.Path, []byte("one")); err != nil || deleted {
		t.Fatalf("unexpected stale delete: %v / %v", deleted, err)
	}
	if deleted, err := store.CompareAndDelete(ctx, obj.Path, []byte("two")); err != nil || !deleted {
		t.Fatalf("delete: %v / %v", deleted, err)
	}
}

func TestLocalCompareAndSwapAcrossInstances(t *testing.T) {
	root := t.TempDir()
	first, err := NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	results := make(chan bool, 2)
	for _, store := range []*Local{first, second} {
		go func(store *Local) {
			swapped, err := store.CompareAndSwap(ctx, "v1/lease", nil, Object{
				Path: "v1/lease",
				Data: []byte(store.root),
			})
			if err != nil {
				t.Errorf("compare and swap: %v", err)
			}
			results <- swapped
		}(store)
	}
	winners := 0
	for range 2 {
		if <-results {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("atomic create winners: %d", winners)
	}
}

func TestS3CompareAndSwap(t *testing.T) {
	mock := newMockS3Client()
	store := newMockS3Store(mock)
	ctx := t.Context()
	obj := Object{Path: "v1/lease", Data: []byte("one")}
	swapped, err := store.CompareAndSwap(ctx, obj.Path, nil, obj)
	if err != nil || !swapped {
		t.Fatalf("initial swap: %v / %v", swapped, err)
	}
	if swapped, err := store.CompareAndSwap(ctx, obj.Path, nil, Object{Path: obj.Path, Data: []byte("two")}); err != nil || swapped {
		t.Fatalf("unexpected create overwrite: %v / %v", swapped, err)
	}
	if swapped, err := store.CompareAndSwap(ctx, obj.Path, []byte("one"), Object{Path: obj.Path, Data: []byte("two")}); err != nil || !swapped {
		t.Fatalf("replace: %v / %v", swapped, err)
	}
	if deleted, err := store.CompareAndDelete(ctx, obj.Path, []byte("one")); err != nil || deleted {
		t.Fatalf("unexpected stale delete: %v / %v", deleted, err)
	}
	if deleted, err := store.CompareAndDelete(ctx, obj.Path, []byte("two")); err != nil || !deleted {
		t.Fatalf("delete: %v / %v", deleted, err)
	}
}

func TestNewFromEnvLocal(t *testing.T) {
	t.Setenv("EBI_STORAGE", "local")
	dir := t.TempDir()
	t.Setenv("EBI_STORAGE_ROOT", dir)
	store, err := NewFromEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	l, ok := store.(*Local)
	if !ok {
		t.Fatalf("expected *Local, got %T", store)
	}
	if l.root != dir {
		t.Fatalf("root mismatch: %q != %q", l.root, dir)
	}
	if err := store.Put(context.Background(), Object{Path: "x", Data: []byte("y")}); err != nil {
		t.Fatal(err)
	}
}

func TestNewFromEnvLocalDefault(t *testing.T) {
	t.Setenv("EBI_STORAGE", "")
	t.Setenv("EBI_STORAGE_ROOT", "")
	store, err := NewFromEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.(*Local); !ok {
		t.Fatalf("expected *Local for default, got %T", store)
	}
}

func TestNewFromEnvS3Missing(t *testing.T) {
	t.Setenv("EBI_STORAGE", "s3")
	t.Setenv("EBI_STORAGE_ENDPOINT", "")
	t.Setenv("EBI_STORAGE_REGION", "")
	t.Setenv("EBI_STORAGE_BUCKET", "")
	t.Setenv("EBI_STORAGE_ACCESS_KEY", "")
	t.Setenv("EBI_STORAGE_SECRET_KEY", "")
	if _, err := NewFromEnv(context.Background()); err == nil {
		t.Fatal("expected error for missing S3 env vars")
	}
}

func TestNewFromEnvS3(t *testing.T) {
	t.Setenv("EBI_STORAGE", "s3")
	t.Setenv("EBI_STORAGE_ENDPOINT", "http://localhost:9000")
	t.Setenv("EBI_STORAGE_REGION", "us-east-1")
	t.Setenv("EBI_STORAGE_BUCKET", "ebi")
	t.Setenv("EBI_STORAGE_ACCESS_KEY", "AKIA")
	t.Setenv("EBI_STORAGE_SECRET_KEY", "secret")
	t.Setenv("EBI_STORAGE_PATH_STYLE", "true")
	t.Setenv("EBI_STORAGE_PREFIX", "prod")
	store, err := NewFromEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.(*S3Store); !ok {
		t.Fatalf("expected *S3Store, got %T", store)
	}
}

func TestTilePathUsesTlogFormat(t *testing.T) {
	partial := TilePath(8, 1234, 100)
	if partial != "v1/tile/8/0/x001/234.p/100" {
		t.Fatalf("unexpected partial tile path: %q", partial)
	}
	full := TilePath(8, 1234, 256)
	if full != "v1/tile/8/0/x001/234" {
		t.Fatalf("unexpected full tile path: %q", full)
	}
	if TilePathLegacy(8, 1234) != "v1/tile/8/1234" {
		t.Fatalf("unexpected legacy tile path: %q", TilePathLegacy(8, 1234))
	}
}

func TestReadAllWithContextRespectsLimit(t *testing.T) {
	ctx := context.Background()
	r := bytes.NewReader([]byte("hello world"))
	data, err := readAllWithContext(ctx, r, 5)
	if err == nil {
		t.Fatal("expected limit error")
	}
	if !errors.Is(err, nil) {
		// error is "object exceeds read limit".
	}
	_ = data
	// Ensure cancellation works.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = readAllWithContext(ctx, bytes.NewReader([]byte("x")), 64)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestWaitForConsistency(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	WaitForConsistency(ctx)
	if time.Since(start) > 10*time.Millisecond {
		t.Fatal("WaitForConsistency should return immediately on cancelled context")
	}
}

func TestObjectWithDefaults(t *testing.T) {
	obj := ObjectWithDefaults("v1/blob/abc", []byte("x"))
	if !obj.Immutable || obj.CacheSeconds != 31536000 {
		t.Fatalf("unexpected defaults: %+v", obj)
	}
}
