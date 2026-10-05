// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package checkpoint

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Steward-GRC/steward-audit/internal/anchor"
	"github.com/Steward-GRC/steward-audit/internal/merkle"
)

type fakeAnchor struct {
	calls atomic.Int32
	err   error
}

func (f *fakeAnchor) Anchor(_ context.Context, _ string) (*anchor.AnchorResult, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return &anchor.AnchorResult{RawToken: []byte("tok"), AnchoredAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
}
func (f *fakeAnchor) Type() string { return "fake" }
func (f *fakeAnchor) URL() string  { return "http://fake.example.org" }

type fakeRecordReader struct {
	mu   sync.Mutex
	seen []int64
}

func (f *fakeRecordReader) HashesSince(_ context.Context, lastID int64) ([]string, int64, error) {
	f.mu.Lock()
	f.seen = append(f.seen, lastID)
	f.mu.Unlock()
	return []string{"hash1", "hash2", "hash3"}, lastID + 3, nil
}

type fakeCheckpointWriter struct {
	mu    sync.Mutex
	saved []SaveInput
}

func (f *fakeCheckpointWriter) SaveCheckpoint(_ context.Context, in SaveInput) error {
	f.mu.Lock()
	f.saved = append(f.saved, in)
	f.mu.Unlock()
	return nil
}

func TestSchedulerCheckpointsOnInterval(t *testing.T) {
	anc := &fakeAnchor{}
	writer := &fakeCheckpointWriter{}
	s := New(&fakeRecordReader{}, writer, anc, 50*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	s.Run(ctx)

	if anc.calls.Load() == 0 {
		t.Fatal("expected at least one anchor call")
	}
	if len(writer.saved) == 0 {
		t.Fatal("expected at least one checkpoint saved")
	}
}

func TestSchedulerSkipsWhenNoNewRecords(t *testing.T) {
	anc := &fakeAnchor{}
	s := New(&emptyRecordReader{}, &fakeCheckpointWriter{}, anc, 30*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	s.Run(ctx)

	if anc.calls.Load() != 0 {
		t.Fatal("expected zero anchor calls when no new records")
	}
}

type emptyRecordReader struct{}

func (e *emptyRecordReader) HashesSince(_ context.Context, _ int64) ([]string, int64, error) {
	return nil, 0, nil
}

func TestRunOnceSavesTheAnchoredRoot(t *testing.T) {
	writer := &fakeCheckpointWriter{}
	s := New(&fakeRecordReader{}, writer, &fakeAnchor{}, time.Hour)
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	root, _ := merkle.BuildTree([]string{"hash1", "hash2", "hash3"})
	got := writer.saved[0]
	if got.FromID != 1 || got.ToID != 3 || got.MerkleRoot != root || got.AnchorType != "fake" || string(got.RawToken) != "tok" {
		t.Fatalf("unexpected checkpoint: %+v", got)
	}
}

// After a restart the scheduler picks up after the last saved checkpoint
// instead of anchoring the whole chain again.
func TestSchedulerResumesAfterTheLastCheckpoint(t *testing.T) {
	reader := &fakeRecordReader{}
	writer := &fakeCheckpointWriter{}
	s := New(reader, writer, &fakeAnchor{}, time.Hour).ResumeAfter(40)
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if reader.seen[0] != 40 {
		t.Fatalf("read from %d, want 40", reader.seen[0])
	}
	if writer.saved[0].FromID != 41 || writer.saved[0].ToID != 43 {
		t.Fatalf("range %d-%d, want 41-43", writer.saved[0].FromID, writer.saved[0].ToID)
	}
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if reader.seen[1] != 43 {
		t.Fatalf("second tick read from %d, want 43", reader.seen[1])
	}
}

// A failed anchor saves nothing, and the same records are tried again.
func TestRunOnceAnchorFailureRetriesTheSameRange(t *testing.T) {
	reader := &fakeRecordReader{}
	writer := &fakeCheckpointWriter{}
	anc := &fakeAnchor{err: errors.New("tsa down")}
	s := New(reader, writer, anc, time.Hour)
	if err := s.RunOnce(context.Background()); err == nil {
		t.Fatal("expected the anchor error")
	}
	if len(writer.saved) != 0 {
		t.Fatal("nothing may be saved when anchoring fails")
	}
	anc.err = nil
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if reader.seen[1] != 0 || writer.saved[0].FromID != 1 {
		t.Fatalf("expected the retry to cover the same range, read from %d", reader.seen[1])
	}
}
