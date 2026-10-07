// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package purge

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-audit/internal/store"
)

type fakeRetention struct {
	mu      sync.Mutex
	results []store.PurgeResult
	err     error
	calls   []time.Time
}

func (f *fakeRetention) PurgeExpired(_ context.Context, now time.Time) (store.PurgeResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, now)
	if f.err != nil {
		return store.PurgeResult{}, f.err
	}
	if len(f.results) == 0 {
		return store.PurgeResult{}, nil
	}
	r := f.results[0]
	f.results = f.results[1:]
	return r, nil
}

func (f *fakeRetention) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type fakeAppender struct{ records []store.RecordInput }

func (f *fakeAppender) AppendRecord(_ context.Context, in store.RecordInput) (*store.Record, error) {
	f.records = append(f.records, in)
	return &store.Record{ID: 7, RecordInput: in}, nil
}

var fixedNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func TestRunOnceRecordsAPurgeThatTombstonedRecords(t *testing.T) {
	ret := &fakeRetention{results: []store.PurgeResult{{Purged: 4}}}
	app := &fakeAppender{}
	p := New(ret, app, time.Hour)
	p.now = func() time.Time { return fixedNow }

	res, err := p.RunOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(4), res.Purged)
	require.Equal(t, []time.Time{fixedNow}, ret.calls)
	require.Len(t, app.records, 1)
	rec := app.records[0]
	require.Equal(t, "audit", rec.Tier)
	require.Equal(t, "audit_log.purged", rec.Action)
	require.True(t, rec.LegalBasisExempt)
	require.Empty(t, rec.ActorUserID, "the purge is a system event")
	require.Equal(t, map[string]string{"records_purged": "4"}, rec.Attributes)
	require.Equal(t, fixedNow, rec.OccurredAt)
}

func TestRunOnceRecordsNothingWhenNothingWasPurged(t *testing.T) {
	for _, r := range []store.PurgeResult{{}, {Skipped: true}} {
		app := &fakeAppender{}
		_, err := New(&fakeRetention{results: []store.PurgeResult{r}}, app, time.Hour).RunOnce(context.Background())
		require.NoError(t, err)
		require.Empty(t, app.records)
	}
}

func TestRunOnceReturnsAFailedPurge(t *testing.T) {
	app := &fakeAppender{}
	_, err := New(&fakeRetention{err: errors.New("db down")}, app, time.Hour).RunOnce(context.Background())
	require.Error(t, err)
	require.Empty(t, app.records)
}

func TestRunPurgesAtOnceThenOnEachTick(t *testing.T) {
	ret := &fakeRetention{}
	p := New(ret, &fakeAppender{}, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	require.Eventually(t, func() bool { return ret.callCount() == 1 }, time.Second, time.Millisecond,
		"the first run starts straight away, not an hour later")
	cancel()
	<-done

	ret = &fakeRetention{err: errors.New("db down")}
	p = New(ret, &fakeAppender{}, 5*time.Millisecond)
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	require.Eventually(t, func() bool { return ret.callCount() >= 3 }, time.Second, time.Millisecond,
		"a failed run is retried on the next tick")
	cancel()
	<-done
}
