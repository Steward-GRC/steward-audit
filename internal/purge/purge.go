// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package purge runs the activity-tier retention purge on a schedule. Every
// replica runs the schedule, and the store's advisory lock lets only one of
// them purge at a time. A run that tombstoned records is itself recorded as
// "audit_log.purged".
package purge

import (
	"context"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Steward-GRC/steward-audit/internal/store"
)

// Retention runs one purge.
type Retention interface {
	PurgeExpired(ctx context.Context, now time.Time) (store.PurgeResult, error)
}

// Appender stores a record in the chain.
type Appender interface {
	AppendRecord(ctx context.Context, in store.RecordInput) (*store.Record, error)
}

// Purger runs the purge every interval.
type Purger struct {
	retention Retention
	records   Appender
	interval  time.Duration
	logger    log.Logger
	now       func() time.Time
}

// New returns a Purger.
func New(r Retention, a Appender, interval time.Duration) *Purger {
	return &Purger{retention: r, records: a, interval: interval, logger: log.Nop(), now: func() time.Time { return time.Now().UTC() }}
}

// WithLogger sets the logger runs report to.
func (p *Purger) WithLogger(l log.Logger) *Purger {
	p.logger = l
	return p
}

// Run purges once straight away, then on every tick, until ctx is cancelled.
// A failed run is logged and retried on the next tick.
func (p *Purger) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		if _, err := p.RunOnce(ctx); err != nil && ctx.Err() == nil {
			p.logger.Ctx(ctx).Error(err, "retention purge failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunOnce purges once and records the purge when it tombstoned anything.
func (p *Purger) RunOnce(ctx context.Context) (store.PurgeResult, error) {
	start := p.now()
	res, err := p.retention.PurgeExpired(ctx, start)
	if err != nil {
		return store.PurgeResult{}, err
	}
	if res.Skipped {
		p.logger.Ctx(ctx).Debug("retention purge skipped: another replica holds the lock")
		return res, nil
	}
	p.logger.Ctx(ctx).Info("retention purge ran", log.F("records_purged", res.Purged),
		log.F("duration_ms", p.now().Sub(start).Milliseconds()))
	if res.Purged == 0 {
		return res, nil
	}
	if _, err := p.records.AppendRecord(ctx, store.RecordInput{
		Tier: "audit", Action: "audit_log.purged", Subject: "retention:activity", OccurredAt: start,
		LegalBasisExempt: true, Attributes: map[string]string{"records_purged": strconv.FormatInt(res.Purged, 10)},
	}); err != nil {
		p.logger.Ctx(ctx).Error(err, "recording the retention purge failed", log.F("records_purged", res.Purged))
	}
	return res, nil
}
