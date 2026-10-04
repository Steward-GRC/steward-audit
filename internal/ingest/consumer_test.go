// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Bugs5382/go-rabbitmq"

	"github.com/Steward-GRC/steward-audit/internal/fixture"
	"github.com/Steward-GRC/steward-audit/internal/store"
)

type fakeStore struct {
	appended []store.RecordInput
	err      error
}

func (f *fakeStore) AppendRecord(_ context.Context, in store.RecordInput) (*store.Record, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.appended = append(f.appended, in)
	return &store.Record{ID: int64(len(f.appended)), RecordInput: in, RecordHash: "fakehash"}, nil
}

func body(t *testing.T, ev Event) []byte {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return b
}

func TestHandleMessageAuditTier(t *testing.T) {
	fs := &fakeStore{}
	ev := Event{Tier: "audit", Action: fixture.PolicyPublished, ActorUserID: fixture.Bob, Subject: fixture.DeskBookingPolicy,
		GroupID: fixture.FacilitiesTeam, OccurredAt: time.Now().UTC(), Attributes: map[string]string{"version": "v1"}, LegalBasisExempt: true}
	if err := NewHandler(fs).Handle(context.Background(), RoutingKeyAudit, body(t, ev)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(fs.appended) != 1 {
		t.Fatalf("expected 1 appended record, got %d", len(fs.appended))
	}
	got := fs.appended[0]
	if !got.LegalBasisExempt || got.Action != ev.Action || got.ActorUserID != ev.ActorUserID || got.Subject != ev.Subject ||
		got.GroupID != ev.GroupID || !got.OccurredAt.Equal(ev.OccurredAt) || got.Attributes["version"] != "v1" {
		t.Fatalf("event not carried over: %+v", got)
	}
}

func TestHandleMessageActivityTier(t *testing.T) {
	fs := &fakeStore{}
	ev := Event{Tier: "activity", Action: fixture.PolicyViewed, ActorUserID: fixture.Erin, Subject: fixture.TravelProcedure,
		GroupID: fixture.FacilitiesTeam, OccurredAt: time.Now().UTC()}
	if err := NewHandler(fs).Handle(context.Background(), RoutingKeyActivity, body(t, ev)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if fs.appended[0].LegalBasisExempt {
		t.Fatal("activity-tier must not be legal-basis exempt by default")
	}
}

// A message that can never be stored is dead-lettered, not retried.
func TestHandleRejectsPoisonMessages(t *testing.T) {
	for name, b := range map[string][]byte{
		"not json":     []byte("not-json"),
		"missing tier": body(t, Event{Action: fixture.PolicyViewed, OccurredAt: time.Now().UTC()}),
		"unknown tier": body(t, Event{Tier: "debug", Action: fixture.PolicyViewed, OccurredAt: time.Now().UTC()}),
		"no action":    body(t, Event{Tier: "audit", OccurredAt: time.Now().UTC()}),
		"no time":      body(t, Event{Tier: "audit", Action: fixture.PolicyPublished}),
	} {
		fs := &fakeStore{}
		err := NewHandler(fs).Handle(context.Background(), RoutingKeyAudit, b)
		if !errors.Is(err, rabbitmq.ErrDeadLetter) {
			t.Errorf("%s: expected a dead-letter error, got %v", name, err)
		}
		if len(fs.appended) != 0 {
			t.Errorf("%s: nothing may be stored", name)
		}
	}
}

// A store failure goes back to the consumer, which drops the message to the
// dead-letter exchange rather than looping on it.
func TestHandleSurfacesStoreErrors(t *testing.T) {
	fs := &fakeStore{err: errors.New("db: connection reset")}
	ev := Event{Tier: "audit", Action: fixture.PolicyPublished, OccurredAt: time.Now().UTC()}
	if err := NewHandler(fs).Handle(context.Background(), RoutingKeyAudit, body(t, ev)); err == nil {
		t.Fatal("expected the store error")
	}
}

func TestConsumerConfigBindsBothTiers(t *testing.T) {
	cfg := ConsumerConfig()
	if cfg.Exchange.Name != Exchange || cfg.Exchange.Kind != "topic" || !cfg.Exchange.Durable {
		t.Fatalf("exchange: %+v", cfg.Exchange)
	}
	if cfg.Queue.Name != Queue || cfg.RequeueOnError {
		t.Fatalf("queue %q requeue %v", cfg.Queue.Name, cfg.RequeueOnError)
	}
	keys := map[string]bool{}
	for _, b := range cfg.Bindings {
		keys[b.RoutingKey] = b.Exchange == Exchange && b.Queue == Queue
	}
	if !keys[RoutingKeyAudit] || !keys[RoutingKeyActivity] || len(keys) != 2 {
		t.Fatalf("bindings: %+v", cfg.Bindings)
	}
}
