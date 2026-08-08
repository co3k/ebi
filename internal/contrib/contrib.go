// Package contrib implements the local opt-in contribution queue for ebi.
// Records are queued locally with 0600 files and can be flushed later.
package contrib

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/co3k/ebi/internal/config"
	"github.com/co3k/ebi/pkg/schema"
)

// Queue is a local contribution queue.
type Queue struct {
	dir string
}

// NewQueue opens the contribution queue directory.
func NewQueue() (*Queue, error) {
	dir, err := config.Dir()
	if err != nil {
		return nil, err
	}
	qdir := filepath.Join(dir, "queue")
	if err := os.MkdirAll(qdir, 0700); err != nil {
		return nil, err
	}
	return &Queue{dir: qdir}, nil
}

// Entry is a queued record with metadata.
type Entry struct {
	Record     *schema.Record
	FlushAfter time.Time
	Path       string
}

// List returns all pending queued records.
func (q *Queue) List() ([]Entry, error) {
	names, err := q.listJSON()
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for _, name := range names {
		path := filepath.Join(q.dir, name)
		entry, err := readQueuedEntry(path)
		if err != nil {
			return nil, err
		}
		entries = append(entries, Entry{
			Record:     entry.Record,
			FlushAfter: entry.FlushAfter,
			Path:       path,
		})
	}
	return entries, nil
}

// Status reports the number of pending records.
func (q *Queue) Status() (int, error) {
	entries, err := q.List()
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

// Enqueue adds a record to the queue. If delayHours is positive, it schedules
// a cryptographically randomized future flush time in [0, delayHours). The
// queue uses atomic writes.
func (q *Queue) Enqueue(record *schema.Record, delayHours int) error {
	if record == nil {
		return fmt.Errorf("cannot enqueue nil record")
	}
	if delayHours < 0 || delayHours > 24 {
		return fmt.Errorf("delay hours must be between 0 and 24")
	}
	if _, _, err := schema.Verify(record); err != nil {
		return fmt.Errorf("verify queued record: %w", err)
	}
	entry := queuedEntry{Record: record}
	if delayHours > 0 {
		delay, err := rand.Int(rand.Reader, big.NewInt(int64(delayHours)*60*60))
		if err != nil {
			return err
		}
		entry.FlushAfter = time.Now().UTC().Add(time.Duration(delay.Int64()) * time.Second)
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	id, err := schema.RecordID(record.Body)
	if err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	name := time.Now().UTC().Format("20060102T150405.000000000") +
		"-" + id[:16] + "-" + hex.EncodeToString(suffix) + ".json"
	path := filepath.Join(q.dir, name)
	return atomicWriteFile(path, data, 0600)
}

// Flush returns all queued records that are eligible for submission. If until
// is non-zero, only records whose scheduled time has passed are returned.
// Failed records remain in the queue; callers must Ack successful ones.
func (q *Queue) Flush(until time.Time) ([]*schema.Record, error) {
	names, err := q.listJSON()
	if err != nil {
		return nil, err
	}
	var records []*schema.Record
	for _, name := range names {
		path := filepath.Join(q.dir, name)
		entry, err := readQueuedEntry(path)
		if err != nil {
			return nil, err
		}
		if !until.IsZero() && entry.FlushAfter.After(until) {
			continue
		}
		records = append(records, entry.Record)
	}
	return records, nil
}

// Ack removes a queued record after confirmed successful submission.
func (q *Queue) Ack(record *schema.Record) error {
	id, err := schema.RecordID(record.Body)
	if err != nil {
		return err
	}
	names, err := q.listJSON()
	if err != nil {
		return err
	}
	for _, name := range names {
		path := filepath.Join(q.dir, name)
		entry, err := readQueuedEntry(path)
		if err != nil {
			return err
		}
		entryID, err := schema.RecordID(entry.Record.Body)
		if err != nil {
			continue
		}
		if entryID == id {
			return os.Remove(path)
		}
	}
	return fmt.Errorf("record not found in queue")
}

// Remove removes a queued record by path.
func (q *Queue) Remove(path string) error {
	absDir, err := filepath.Abs(q.dir)
	if err != nil {
		return err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absDir, absPath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path outside queue")
	}
	return os.Remove(absPath)
}

type queuedEntry struct {
	Record     *schema.Record `json:"record"`
	FlushAfter time.Time      `json:"flush_after,omitempty"`
}

func readQueuedEntry(path string) (queuedEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return queuedEntry{}, fmt.Errorf("read queue entry %s: %w", filepath.Base(path), err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var entry queuedEntry
	if err := dec.Decode(&entry); err != nil {
		return queuedEntry{}, fmt.Errorf("decode queue entry %s: %w", filepath.Base(path), err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return queuedEntry{}, fmt.Errorf("decode queue entry %s: trailing data", filepath.Base(path))
	}
	if entry.Record == nil {
		return queuedEntry{}, fmt.Errorf("queue entry %s has no record", filepath.Base(path))
	}
	if _, _, err := schema.Verify(entry.Record); err != nil {
		return queuedEntry{}, fmt.Errorf("verify queue entry %s: %w", filepath.Base(path), err)
	}
	return entry, nil
}

func (q *Queue) listJSON() ([]string, error) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
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

// LicenseNotice returns the contribution license notice.
func LicenseNotice() string {
	return "Contributions are dedicated to the public domain under CC0-1.0."
}

// SubmissionNotice returns a notice for each submission.
func SubmissionNotice() string {
	return "This submission is dedicated to the public domain under CC0-1.0."
}
