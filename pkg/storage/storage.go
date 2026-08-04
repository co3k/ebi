// Package storage provides a content-addressable object store used by the ebi
// transparency server and snapshot tooling.
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
	"golang.org/x/mod/sumdb/tlog"
)

// Object stores raw bytes keyed by logical path.
type Object struct {
	Path         string
	Data         []byte
	ContentType  string
	CacheSeconds int
	Immutable    bool
	// Mutable overrides immutable cache defaults for replacement documents
	// such as privacy tombstones stored at a content-addressed blob path.
	Mutable bool
}

// ErrNotFound is returned when a logical object does not exist.
var ErrNotFound = errors.New("storage object not found")

// AtomicStore adds conditional mutation primitives for singleton leases and
// other coordination records. CompareAndSwap treats a nil old value as
// "object must not exist"; CompareAndDelete removes only an unchanged object.
type AtomicStore interface {
	Store
	CompareAndSwap(ctx context.Context, path string, old []byte, obj Object) (bool, error)
	CompareAndDelete(ctx context.Context, path string, old []byte) (bool, error)
}

// Mem is an in-memory Store for testing.
type Mem struct {
	mu   sync.RWMutex
	objs map[string]Object
}

// NewMem returns a new in-memory Store.
func NewMem() *Mem {
	return &Mem{objs: make(map[string]Object)}
}

func (m *Mem) Get(ctx context.Context, path string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	obj, ok := m.objs[path]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	out := make([]byte, len(obj.Data))
	copy(out, obj.Data)
	return out, nil
}

func (m *Mem) Put(ctx context.Context, obj Object) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data := make([]byte, len(obj.Data))
	copy(data, obj.Data)
	m.objs[obj.Path] = Object{
		Path:         obj.Path,
		Data:         data,
		ContentType:  obj.ContentType,
		CacheSeconds: obj.CacheSeconds,
		Immutable:    obj.Immutable,
		Mutable:      obj.Mutable,
	}
	return nil
}

func (m *Mem) Delete(ctx context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objs, path)
	return nil
}

func (m *Mem) List(ctx context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	for k := range m.objs {
		if hasPathPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *Mem) Publish(ctx context.Context, obj Object) error {
	return m.Put(ctx, obj)
}

func (m *Mem) CompareAndSwap(ctx context.Context, path string, old []byte, obj Object) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if path != obj.Path {
		return false, fmt.Errorf("conditional path %q does not match object path %q", path, obj.Path)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.objs[path]
	if old == nil {
		if exists {
			return false, nil
		}
	} else if !exists || !bytes.Equal(current.Data, old) {
		return false, nil
	}
	data := append([]byte(nil), obj.Data...)
	m.objs[path] = Object{
		Path:         obj.Path,
		Data:         data,
		ContentType:  obj.ContentType,
		CacheSeconds: obj.CacheSeconds,
		Immutable:    obj.Immutable,
		Mutable:      obj.Mutable,
	}
	return true, nil
}

func (m *Mem) CompareAndDelete(ctx context.Context, path string, old []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.objs[path]
	if !exists || old == nil || !bytes.Equal(current.Data, old) {
		return false, nil
	}
	delete(m.objs, path)
	return true, nil
}

func (m *Mem) Close() error { return nil }

// Store is the storage abstraction.
type Store interface {
	Get(ctx context.Context, path string) ([]byte, error)
	Put(ctx context.Context, obj Object) error
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, prefix string) ([]string, error)
	Publish(ctx context.Context, obj Object) error
	Close() error
}

// Local is a root-confined filesystem store.
type Local struct {
	root string
}

// NewLocal creates a local filesystem store under root.
func NewLocal(root string) (*Local, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0750); err != nil {
		return nil, err
	}
	return &Local{root: abs}, nil
}

// validatePath rejects absolute paths and path components ., .., or empty.
func validatePath(path string) error {
	if path == "" {
		return fmt.Errorf("path is empty")
	}
	if strings.HasPrefix(path, "/") {
		return fmt.Errorf("path is absolute: %s", path)
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" {
			return fmt.Errorf("path contains empty component: %s", path)
		}
		if part == "." || part == ".." {
			return fmt.Errorf("path contains invalid component %q: %s", part, path)
		}
	}
	return nil
}

// safePath returns an OS path that is guaranteed to stay inside the root.
// Empty path is allowed and resolves to the root itself.
func (l *Local) safePath(path string) (string, error) {
	if path != "" {
		if err := validatePath(path); err != nil {
			return "", err
		}
	}
	parts := strings.Split(path, "/")
	if path == "" {
		parts = nil
	}
	current := l.root
	for _, part := range parts {
		candidate := filepath.Join(current, part)
		info, err := os.Lstat(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				current = candidate
				continue
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(candidate)
			if err != nil {
				return "", err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(current, target)
			}
			target = filepath.Clean(target)
			rel, err := filepath.Rel(l.root, target)
			if err != nil {
				return "", fmt.Errorf("symlink escapes root: %s", path)
			}
			if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
				return "", fmt.Errorf("symlink escapes root: %s", path)
			}
			current = target
			continue
		}
		current = candidate
	}
	// Final resolution for existing paths.
	if real, err := filepath.EvalSymlinks(current); err == nil {
		rel, err := filepath.Rel(l.root, real)
		if err != nil {
			return "", fmt.Errorf("path traversal: %s", path)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return "", fmt.Errorf("path traversal: %s", path)
		}
		return real, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return current, nil
}

func (l *Local) checkContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (l *Local) Get(ctx context.Context, path string) ([]byte, error) {
	if err := l.checkContext(ctx); err != nil {
		return nil, err
	}
	if err := validatePath(path); err != nil {
		return nil, err
	}
	p, err := l.safePath(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	const max = int64(64 << 20) // 64 MiB
	if fi.Size() > max {
		return nil, fmt.Errorf("object exceeds read limit")
	}
	data, err := readAllWithContext(ctx, f, max)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (l *Local) Put(ctx context.Context, obj Object) error {
	if err := l.checkContext(ctx); err != nil {
		return err
	}
	if err := validatePath(obj.Path); err != nil {
		return err
	}
	p, err := l.safePath(obj.Path)
	if err != nil {
		return err
	}
	perm := os.FileMode(0640)
	if isSensitivePath(obj.Path) {
		perm = 0600
	}
	return atomicWriteFile(p, obj.Data, perm)
}

func (l *Local) Delete(ctx context.Context, path string) error {
	if err := l.checkContext(ctx); err != nil {
		return err
	}
	if err := validatePath(path); err != nil {
		return err
	}
	p, err := l.safePath(path)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

func (l *Local) List(ctx context.Context, prefix string) ([]string, error) {
	if err := l.checkContext(ctx); err != nil {
		return nil, err
	}
	base, err := l.safePath(prefix)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(base)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []string{}, nil
		}
		return nil, err
	}
	var root string
	if info.IsDir() {
		root = base
	} else {
		root = filepath.Dir(base)
	}
	var out []string
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(l.root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !hasPathPrefix(rel, prefix) {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func (l *Local) Publish(ctx context.Context, obj Object) error {
	return l.Put(ctx, obj)
}

func (l *Local) CompareAndSwap(ctx context.Context, path string, old []byte, obj Object) (bool, error) {
	if err := l.checkContext(ctx); err != nil {
		return false, err
	}
	if path != obj.Path {
		return false, fmt.Errorf("conditional path %q does not match object path %q", path, obj.Path)
	}
	if err := validatePath(path); err != nil {
		return false, err
	}
	p, err := l.safePath(path)
	if err != nil {
		return false, err
	}
	var swapped bool
	err = withExclusiveFileLock(filepath.Join(l.root, ".storage-cas.lock"), func() error {
		current, readErr := os.ReadFile(p)
		switch {
		case readErr == nil:
			if old == nil || !bytes.Equal(current, old) {
				return nil
			}
		case os.IsNotExist(readErr):
			if old != nil {
				return nil
			}
		default:
			return readErr
		}
		perm := os.FileMode(0640)
		if isSensitivePath(path) {
			perm = 0600
		}
		if err := atomicWriteFile(p, obj.Data, perm); err != nil {
			return err
		}
		swapped = true
		return nil
	})
	return swapped, err
}

func (l *Local) CompareAndDelete(ctx context.Context, path string, old []byte) (bool, error) {
	if err := l.checkContext(ctx); err != nil {
		return false, err
	}
	if err := validatePath(path); err != nil {
		return false, err
	}
	p, err := l.safePath(path)
	if err != nil {
		return false, err
	}
	var deleted bool
	err = withExclusiveFileLock(filepath.Join(l.root, ".storage-cas.lock"), func() error {
		current, readErr := os.ReadFile(p)
		if os.IsNotExist(readErr) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		if old == nil || !bytes.Equal(current, old) {
			return nil
		}
		if err := os.Remove(p); err != nil {
			return err
		}
		deleted = true
		return nil
	})
	return deleted, err
}

func (l *Local) Close() error { return nil }

func isSensitivePath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return strings.Contains(base, "checkpoint") ||
		strings.Contains(base, "policy") ||
		strings.Contains(base, "state") ||
		strings.Contains(base, "leafindex") ||
		strings.Contains(base, "leaf_index") ||
		strings.Contains(base, "report") ||
		strings.Contains(base, "lease")
}

func readAllWithContext(ctx context.Context, r io.Reader, limit int64) ([]byte, error) {
	const chunk = 64 * 1024
	buf := make([]byte, 0, limit)
	tmp := make([]byte, chunk)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if int64(len(buf)) > limit {
				return nil, fmt.Errorf("object exceeds read limit")
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	return buf, nil
}

// atomicWriteFile writes data to a temp file and renames it to path.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { os.Remove(tmp) }
	if _, err := f.Write(data); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return err
	}
	return nil
}

// s3Client is a minimal interface over *s3.Client for testability.
type s3Client interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error)
}

// S3Store implements Store on an S3-compatible backend (R2/MinIO).
type S3Store struct {
	client s3Client
	bucket string
	prefix string
}

// S3Options is used to configure the S3 store.
type S3Options struct {
	Bucket       string
	Endpoint     string
	Region       string
	AccessKey    string
	SecretKey    string
	Prefix       string
	UsePathStyle bool
}

// NewS3 creates an S3 store from environment defaults or explicit options.
func NewS3(ctx context.Context, opts S3Options) (*S3Store, error) {
	cfg, err := buildAWSConfig(ctx, opts)
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if opts.UsePathStyle {
			o.UsePathStyle = true
		}
	})
	if opts.Bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}
	return &S3Store{client: client, bucket: opts.Bucket, prefix: strings.TrimPrefix(opts.Prefix, "/")}, nil
}

func buildAWSConfig(ctx context.Context, opts S3Options) (aws.Config, error) {
	var optFns []func(*awsconfig.LoadOptions) error
	if opts.Region != "" {
		optFns = append(optFns, awsconfig.WithRegion(opts.Region))
	}
	if opts.Endpoint != "" {
		optFns = append(optFns, awsconfig.WithBaseEndpoint(opts.Endpoint))
	}
	if opts.AccessKey != "" && opts.SecretKey != "" {
		optFns = append(optFns, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(opts.AccessKey, opts.SecretKey, "")))
	}
	return awsconfig.LoadDefaultConfig(ctx, optFns...)
}

func (s *S3Store) key(path string) string {
	if s.prefix == "" {
		return path
	}
	return s.prefix + "/" + path
}

func (s *S3Store) Get(ctx context.Context, path string) ([]byte, error) {
	if err := validatePath(path); err != nil {
		return nil, err
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key(path)),
	})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	const max = int64(64 << 20) // 64 MiB
	if out.ContentLength != nil && *out.ContentLength > max {
		return nil, fmt.Errorf("object exceeds read limit")
	}
	data, err := readAllWithContext(ctx, io.LimitReader(out.Body, max+1), max)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s *S3Store) Put(ctx context.Context, obj Object) error {
	if err := validatePath(obj.Path); err != nil {
		return err
	}
	ct, cc := objectHeaders(obj)
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:       aws.String(s.bucket),
		Key:          aws.String(s.key(obj.Path)),
		Body:         bytes.NewReader(obj.Data),
		ContentType:  aws.String(ct),
		CacheControl: aws.String(cc),
	})
	return err
}

func (s *S3Store) CompareAndSwap(ctx context.Context, path string, old []byte, obj Object) (bool, error) {
	if path != obj.Path {
		return false, fmt.Errorf("conditional path %q does not match object path %q", path, obj.Path)
	}
	if err := validatePath(path); err != nil {
		return false, err
	}
	ct, cc := objectHeaders(obj)
	input := &s3.PutObjectInput{
		Bucket:       aws.String(s.bucket),
		Key:          aws.String(s.key(path)),
		Body:         bytes.NewReader(obj.Data),
		ContentType:  aws.String(ct),
		CacheControl: aws.String(cc),
	}
	if old == nil {
		input.IfNoneMatch = aws.String("*")
	} else {
		current, etag, err := s.getObjectWithETag(ctx, path)
		if err != nil {
			if IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		if !bytes.Equal(current, old) {
			return false, nil
		}
		if etag == "" {
			return false, fmt.Errorf("conditional object %s has no ETag", path)
		}
		input.IfMatch = aws.String(etag)
	}
	if _, err := s.client.PutObject(ctx, input); err != nil {
		if isConditionalConflict(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *S3Store) CompareAndDelete(ctx context.Context, path string, old []byte) (bool, error) {
	if err := validatePath(path); err != nil {
		return false, err
	}
	if old == nil {
		return false, nil
	}
	current, etag, err := s.getObjectWithETag(ctx, path)
	if err != nil {
		if IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	if !bytes.Equal(current, old) {
		return false, nil
	}
	if etag == "" {
		return false, fmt.Errorf("conditional object %s has no ETag", path)
	}
	if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:  aws.String(s.bucket),
		Key:     aws.String(s.key(path)),
		IfMatch: aws.String(etag),
	}); err != nil {
		if isConditionalConflict(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *S3Store) getObjectWithETag(ctx context.Context, path string) ([]byte, string, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key(path)),
	})
	if err != nil {
		return nil, "", err
	}
	defer out.Body.Close()
	const max = int64(64 << 20)
	if out.ContentLength != nil && *out.ContentLength > max {
		return nil, "", fmt.Errorf("object exceeds read limit")
	}
	data, err := readAllWithContext(ctx, io.LimitReader(out.Body, max+1), max)
	if err != nil {
		return nil, "", err
	}
	return data, aws.ToString(out.ETag), nil
}

func isConditionalConflict(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "PreconditionFailed", "ConditionalRequestConflict", "412", "409":
		return true
	}
	return false
}

func objectHeaders(obj Object) (string, string) {
	ct := obj.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	im, sec := DefaultCacheFor(obj.Path)
	if obj.Immutable {
		im = true
	}
	if obj.Mutable {
		im = false
	}
	if obj.CacheSeconds > 0 {
		sec = obj.CacheSeconds
	}
	cc := ""
	if im {
		cc = "max-age=31536000, immutable"
	} else if sec > 0 {
		cc = fmt.Sprintf("max-age=%d", sec)
	}
	return ct, cc
}

func (s *S3Store) Delete(ctx context.Context, path string) error {
	if err := validatePath(path); err != nil {
		return err
	}
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key(path)),
	})
	return err
}

func (s *S3Store) List(ctx context.Context, prefix string) ([]string, error) {
	if prefix != "" {
		if err := validatePath(prefix); err != nil {
			return nil, err
		}
	}
	var out []string
	var marker *string
	requestPrefix := s.key(prefix)
	if s.prefix != "" && prefix == "" {
		requestPrefix = strings.TrimSuffix(s.prefix, "/") + "/"
	}
	for {
		resp, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(s.bucket),
			Prefix:            aws.String(requestPrefix),
			ContinuationToken: marker,
		})
		if err != nil {
			return nil, err
		}
		for _, obj := range resp.Contents {
			key := aws.ToString(obj.Key)
			if s.prefix != "" {
				want := strings.TrimSuffix(s.prefix, "/") + "/"
				if !strings.HasPrefix(key, want) {
					return nil, fmt.Errorf("listed key %q is outside configured prefix %q", key, s.prefix)
				}
				key = strings.TrimPrefix(key, want)
			}
			if hasPathPrefix(key, prefix) {
				out = append(out, key)
			}
		}
		if !aws.ToBool(resp.IsTruncated) {
			break
		}
		marker = resp.NextContinuationToken
	}
	sort.Strings(out)
	return out, nil
}

// Publish writes obj to a temporary key, copies it to the final key, and removes
// the temporary key. Callers should publish the checkpoint object last so that
// readers never see a new checkpoint before its supporting tiles/blobs are
// available.
func (s *S3Store) Publish(ctx context.Context, obj Object) error {
	if err := validatePath(obj.Path); err != nil {
		return err
	}
	tmp := "v1/.tmp/" + uuid.NewString()
	if err := s.Put(ctx, Object{
		Path:         tmp,
		Data:         obj.Data,
		ContentType:  obj.ContentType,
		CacheSeconds: obj.CacheSeconds,
		Immutable:    obj.Immutable,
		Mutable:      obj.Mutable,
	}); err != nil {
		_ = s.Delete(ctx, tmp)
		return err
	}
	copySource := aws.String(s.bucket + "/" + s.key(tmp))
	_, err := s.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(s.bucket),
		CopySource: copySource,
		Key:        aws.String(s.key(obj.Path)),
	})
	if err != nil {
		_ = s.Delete(ctx, tmp)
		return err
	}
	if err := s.Delete(ctx, tmp); err != nil {
		return err
	}
	return nil
}

func (s *S3Store) Close() error { return nil }

// IsNotFound reports whether err is a missing object error.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	var nsk *types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	if errors.Is(err, ErrNotFound) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NotFound", "404":
			return true
		}
	}
	if os.IsNotExist(err) {
		return true
	}
	return false
}

// BlobPath returns the content path for a SHA-256 blob.
func BlobPath(sha256Hex string) string {
	return "v1/blob/" + sha256Hex
}

// TilePath returns a C2SP-compatible tile storage path using tlog.Tile.Path.
func TilePath(level, index, width int) string {
	return "v1/" + tlog.Tile{H: level, N: int64(index), W: width}.Path()
}

// TilePathLegacy returns the old two-argument tile path for compatibility.
func TilePathLegacy(level, tile int) string {
	return fmt.Sprintf("v1/tile/%d/%d", level, tile)
}

// PrefixPath returns the prefix shard path.
func PrefixPath(prefix string) string {
	return "v1/prefix/" + prefix
}

// SnapshotPath returns the path for a snapshot by tree size.
func SnapshotPath(tree int64) string {
	return fmt.Sprintf("v1/snapshot/%d.tar.zst", tree)
}

// CheckpointPath returns the current checkpoint path.
func CheckpointPath() string {
	return "v1/checkpoint"
}

// ContentHash returns the SHA-256 hex of data.
func ContentHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// DefaultCacheFor returns recommended cache metadata for a path.
func DefaultCacheFor(path string) (immutable bool, seconds int) {
	switch {
	case strings.HasPrefix(path, "v1/tile/"),
		strings.HasPrefix(path, "v1/blob/"),
		strings.HasPrefix(path, "v1/leaf/"),
		strings.HasPrefix(path, "v1/snapshot/") && strings.HasSuffix(path, ".tar.zst"):
		return true, 31536000
	case strings.HasPrefix(path, "v1/checkpoint"):
		return false, 60
	case strings.HasPrefix(path, "v1/prefix/"):
		return false, 300
	case strings.HasPrefix(path, "v1/snapshot/"):
		return false, 300
	}
	return false, 0
}

func hasPathPrefix(path, prefix string) bool {
	if prefix == "" {
		return true
	}
	prefix = strings.TrimSuffix(prefix, "/")
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// ObjectWithDefaults returns an Object with cache settings derived from path.
func ObjectWithDefaults(path string, data []byte) Object {
	im, sec := DefaultCacheFor(path)
	return Object{Path: path, Data: data, CacheSeconds: sec, Immutable: im}
}

// WaitForConsistency sleeps briefly to allow S3 eventual consistency tests to settle.
func WaitForConsistency(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(50 * time.Millisecond):
	}
}

// NewFromEnv creates a Store from environment variables.
//
//	EBI_STORAGE=local|s3
//	For local: EBI_STORAGE_ROOT (default ./data)
//	For S3:    EBI_STORAGE_ENDPOINT, EBI_STORAGE_REGION, EBI_STORAGE_BUCKET,
//	           EBI_STORAGE_ACCESS_KEY, EBI_STORAGE_SECRET_KEY,
//	           EBI_STORAGE_PATH_STYLE (true/false), EBI_STORAGE_PREFIX
//
// Credentials are never logged. Required values are validated before use.
func NewFromEnv(ctx context.Context) (Store, error) {
	typ := os.Getenv("EBI_STORAGE")
	switch typ {
	case "", "local":
		root := os.Getenv("EBI_STORAGE_ROOT")
		if root == "" {
			root = "./data"
		}
		return NewLocal(root)
	case "s3":
		opts := S3Options{
			Endpoint:  os.Getenv("EBI_STORAGE_ENDPOINT"),
			Region:    os.Getenv("EBI_STORAGE_REGION"),
			Bucket:    os.Getenv("EBI_STORAGE_BUCKET"),
			AccessKey: os.Getenv("EBI_STORAGE_ACCESS_KEY"),
			SecretKey: os.Getenv("EBI_STORAGE_SECRET_KEY"),
			Prefix:    os.Getenv("EBI_STORAGE_PREFIX"),
		}
		if v := os.Getenv("EBI_STORAGE_PATH_STYLE"); v != "" {
			opts.UsePathStyle = v == "true" || v == "1" || v == "yes"
		}
		var missing []string
		for _, kv := range []struct {
			name  string
			value string
		}{
			{"EBI_STORAGE_ENDPOINT", opts.Endpoint},
			{"EBI_STORAGE_REGION", opts.Region},
			{"EBI_STORAGE_BUCKET", opts.Bucket},
			{"EBI_STORAGE_ACCESS_KEY", opts.AccessKey},
			{"EBI_STORAGE_SECRET_KEY", opts.SecretKey},
		} {
			if kv.value == "" {
				missing = append(missing, kv.name)
			}
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("EBI_STORAGE=s3 requires %s", strings.Join(missing, ", "))
		}
		return NewS3(ctx, opts)
	default:
		return nil, fmt.Errorf("unsupported EBI_STORAGE value: %s", typ)
	}
}
