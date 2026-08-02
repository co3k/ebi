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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Object stores raw bytes keyed by logical path.
type Object struct {
	Path        string
	Data        []byte
	ContentType string
	CacheSeconds int
	Immutable   bool
}

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

func (l *Local) safePath(path string) (string, error) {
	path = filepath.Clean("/" + path)
	full := filepath.Join(l.root, path)
	abs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	// Ensure path is inside root.
	rel, err := filepath.Rel(l.root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal: %s", path)
	}
	return abs, nil
}

func (l *Local) Get(ctx context.Context, path string) ([]byte, error) {
	p, err := l.safePath(path)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

func (l *Local) Put(ctx context.Context, obj Object) error {
	p, err := l.safePath(obj.Path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0750); err != nil {
		return err
	}
	return atomicWriteFile(p, obj.Data)
}

func (l *Local) Delete(ctx context.Context, path string) error {
	p, err := l.safePath(path)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

func (l *Local) List(ctx context.Context, prefix string) ([]string, error) {
	p, err := l.safePath(prefix)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []string{}, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		out = append(out, filepath.Join(prefix, name))
	}
	return out, nil
}

func (l *Local) Publish(ctx context.Context, obj Object) error {
	return l.Put(ctx, obj)
}

func (l *Local) Close() error { return nil }

// atomicWriteFile writes data to a temp file and renames it to path.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
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
	if err := os.Chmod(tmp, 0640); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// S3Store implements Store on an S3-compatible backend (R2/MinIO).
type S3Store struct {
	client *s3.Client
	bucket string
	prefix string
}

// S3Options is used to configure the S3 store.
type S3Options struct {
	Bucket   string
	Endpoint string
	Region   string
	AccessKey string
	SecretKey string
	Prefix   string
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
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key(path)),
	})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

func (s *S3Store) Put(ctx context.Context, obj Object) error {
	ct := obj.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	cache := ""
	if obj.CacheSeconds > 0 {
		cache = fmt.Sprintf("max-age=%d", obj.CacheSeconds)
	}
	if obj.Immutable {
		cache = "max-age=31536000, immutable"
	}
	metadata := map[string]string{}
	if obj.CacheSeconds > 0 {
		metadata["cache-control"] = cache
	}
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(s.key(obj.Path)),
		Body:        bytes.NewReader(obj.Data),
		ContentType: aws.String(ct),
		Metadata:    metadata,
	})
	return err
}

func (s *S3Store) Delete(ctx context.Context, path string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key(path)),
	})
	return err
}

func (s *S3Store) List(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	var marker *string
	for {
		resp, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(s.bucket),
			Prefix:            aws.String(s.key(prefix)),
			ContinuationToken: marker,
		})
		if err != nil {
			return nil, err
		}
		for _, obj := range resp.Contents {
			key := aws.ToString(obj.Key)
			key = strings.TrimPrefix(key, s.key("")+"/")
			out = append(out, key)
		}
		if !aws.ToBool(resp.IsTruncated) {
			break
		}
		marker = resp.NextContinuationToken
	}
	return out, nil
}

func (s *S3Store) Publish(ctx context.Context, obj Object) error {
	return s.Put(ctx, obj)
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
	if os.IsNotExist(err) {
		return true
	}
	return false
}

// BlobPath returns the content path for a SHA-256 blob.
func BlobPath(sha256Hex string) string {
	return "v1/blob/" + sha256Hex
}

// TilePath returns a tile path at the given level and index.
func TilePath(level, tile int) string {
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
	case strings.HasPrefix(path, "v1/tile/"), strings.HasPrefix(path, "v1/blob/"):
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
