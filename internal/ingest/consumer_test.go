// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Bugs5382/go-rabbitmq"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/Steward-GRC/steward-audit/gen/go/steward/audit/v1"
	"github.com/Steward-GRC/steward-audit/internal/fixture"
	"github.com/Steward-GRC/steward-audit/internal/store"
)

type fakeStore struct {
	mu       sync.Mutex
	appended []store.RecordInput
	err      error
}

func (f *fakeStore) AppendRecord(_ context.Context, in store.RecordInput) (*store.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.appended = append(f.appended, in)
	return &store.Record{ID: int64(len(f.appended)), RecordInput: in, RecordHash: "fakehash"}, nil
}

func body(t *testing.T, ev *auditv1.AuditEvent) []byte {
	t.Helper()
	b, err := proto.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return b
}

func delivery(t *testing.T, routingKey string, ev *auditv1.AuditEvent) rabbitmq.Delivery {
	t.Helper()
	return rabbitmq.Delivery{RoutingKey: routingKey, ContentType: ContentType, Body: body(t, ev)}
}

func TestHandleMessageAuditTier(t *testing.T) {
	fs := &fakeStore{}
	ev := &auditv1.AuditEvent{Tier: auditv1.Tier_TIER_AUDIT, Action: fixture.PolicyPublished, ActorUserId: fixture.Bob, Subject: fixture.DeskBookingPolicy,
		GroupId: fixture.FacilitiesTeam, OccurredAt: timestamppb.Now(), Attributes: map[string]string{"version": "v1"}, LegalBasisExempt: true}
	if err := NewHandler(fs).Handle(context.Background(), delivery(t, RoutingKeyAudit, ev)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(fs.appended) != 1 {
		t.Fatalf("expected 1 appended record, got %d", len(fs.appended))
	}
	got := fs.appended[0]
	if got.Tier != "audit" || !got.LegalBasisExempt || got.Action != ev.Action || got.ActorUserID != ev.ActorUserId || got.Subject != ev.Subject ||
		got.GroupID != ev.GroupId || !got.OccurredAt.Equal(ev.OccurredAt.AsTime()) || got.Attributes["version"] != "v1" {
		t.Fatalf("event not carried over: %+v", got)
	}
}

func TestHandleMessageActivityTier(t *testing.T) {
	fs := &fakeStore{}
	ev := &auditv1.AuditEvent{Tier: auditv1.Tier_TIER_ACTIVITY, Action: fixture.PolicyViewed, ActorUserId: fixture.Erin, Subject: fixture.TravelProcedure,
		GroupId: fixture.FacilitiesTeam, OccurredAt: timestamppb.Now()}
	if err := NewHandler(fs).Handle(context.Background(), delivery(t, RoutingKeyActivity, ev)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if fs.appended[0].Tier != "activity" {
		t.Fatalf("tier: %q", fs.appended[0].Tier)
	}
	if fs.appended[0].LegalBasisExempt {
		t.Fatal("activity-tier must not be legal-basis exempt by default")
	}
}

// A message that can never be stored is dead-lettered, not retried.
func TestHandleRejectsPoisonMessages(t *testing.T) {
	now := timestamppb.Now()
	valid := &auditv1.AuditEvent{Tier: auditv1.Tier_TIER_AUDIT, Action: fixture.PolicyPublished, OccurredAt: now}
	legacyJSON, err := json.Marshal(map[string]any{"tier": "audit", "action": fixture.PolicyPublished, "occurred_at": time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	withType := func(ct string, b []byte) rabbitmq.Delivery {
		return rabbitmq.Delivery{RoutingKey: RoutingKeyAudit, ContentType: ct, Body: b}
	}
	for name, d := range map[string]rabbitmq.Delivery{
		"not protobuf":      withType(ContentType, []byte("not-protobuf")),
		"legacy json":       withType("application/json", legacyJSON),
		"no content type":   withType("", body(t, valid)),
		"other message":     withType("application/protobuf; proto=steward.audit.v1.AuditRecord", body(t, valid)),
		"bad content type":  withType("application/protobuf; proto", body(t, valid)),
		"missing tier":      delivery(t, RoutingKeyAudit, &auditv1.AuditEvent{Action: fixture.PolicyViewed, OccurredAt: now}),
		"unknown tier":      delivery(t, RoutingKeyAudit, &auditv1.AuditEvent{Tier: auditv1.Tier(99), Action: fixture.PolicyViewed, OccurredAt: now}),
		"no action":         delivery(t, RoutingKeyAudit, &auditv1.AuditEvent{Tier: auditv1.Tier_TIER_AUDIT, OccurredAt: now}),
		"no time":           delivery(t, RoutingKeyAudit, &auditv1.AuditEvent{Tier: auditv1.Tier_TIER_AUDIT, Action: fixture.PolicyPublished}),
		"out of range time": delivery(t, RoutingKeyAudit, &auditv1.AuditEvent{Tier: auditv1.Tier_TIER_AUDIT, Action: fixture.PolicyPublished, OccurredAt: &timestamppb.Timestamp{Nanos: -1}}),
	} {
		fs := &fakeStore{}
		err := NewHandler(fs).Handle(context.Background(), d)
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
	ev := &auditv1.AuditEvent{Tier: auditv1.Tier_TIER_AUDIT, Action: fixture.PolicyPublished, OccurredAt: timestamppb.Now()}
	if err := NewHandler(fs).Handle(context.Background(), delivery(t, RoutingKeyAudit, ev)); err == nil {
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
