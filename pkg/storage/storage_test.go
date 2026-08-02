package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
}

func TestBlobPath(t *testing.T) {
	if BlobPath("deadbeef") != "v1/blob/deadbeef" {
		t.Fatal("blob path wrong")
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target", "file")
	if err := atomicWriteFile(path, []byte("data")); err != nil {
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
}
