// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package ingest turns events from the broker into chained records. Services
// publish a steward.audit.v1.AuditEvent, as protobuf binary with the
// ContentType content type, to the "audit" topic exchange with routing key
// audit.audit (the audit tier) or audit.activity (the activity tier). The tier
// in the body is the one stored.
package ingest

import (
	"context"
	"fmt"
	"mime"

	"github.com/Bugs5382/go-rabbitmq"
	"google.golang.org/protobuf/proto"

	auditv1 "github.com/Steward-GRC/steward-audit/gen/go/steward/audit/v1"
	"github.com/Steward-GRC/steward-audit/internal/store"
)

// The broker topology the consumer declares.
const (
	Exchange           = "audit"
	Queue              = "audit.service.queue"
	RoutingKeyAudit    = "audit.audit"
	RoutingKeyActivity = "audit.activity"
	consumerTag        = "audit-service"
)

// ContentType is the AMQP content type every event is published with.
const ContentType = "application/protobuf; proto=steward.audit.v1.AuditEvent"

const mediaType = "application/protobuf"

var eventName = string((&auditv1.AuditEvent{}).ProtoReflect().Descriptor().FullName())

var tierNames = map[auditv1.Tier]string{
	auditv1.Tier_TIER_AUDIT:    "audit",
	auditv1.Tier_TIER_ACTIVITY: "activity",
}

// Appender stores a record.
type Appender interface {
	AppendRecord(ctx context.Context, in store.RecordInput) (*store.Record, error)
}

// Handler stores each delivered event.
type Handler struct{ store Appender }

// NewHandler returns a Handler that appends to s.
func NewHandler(s Appender) *Handler { return &Handler{store: s} }

// Handle stores one event. A message that can never be stored is
// dead-lettered; any other error is returned for the consumer to settle.
func (h *Handler) Handle(ctx context.Context, d rabbitmq.Delivery) error {
	in, err := decode(d)
	if err != nil {
		return fmt.Errorf("ingest: %v: %w", err, rabbitmq.ErrDeadLetter)
	}
	_, err = h.store.AppendRecord(ctx, in)
	return err
}

func decode(d rabbitmq.Delivery) (store.RecordInput, error) {
	mt, params, err := mime.ParseMediaType(d.ContentType)
	if err != nil {
		return store.RecordInput{}, fmt.Errorf("content type %q: %v", d.ContentType, err)
	}
	if mt != mediaType || params["proto"] != eventName {
		return store.RecordInput{}, fmt.Errorf("content type %q is not %q", d.ContentType, ContentType)
	}
	var ev auditv1.AuditEvent
	if err := proto.Unmarshal(d.Body, &ev); err != nil {
		return store.RecordInput{}, fmt.Errorf("decode event: %v", err)
	}
	tier, ok := tierNames[ev.GetTier()]
	switch {
	case !ok:
		return store.RecordInput{}, fmt.Errorf("tier %v is not audit or activity", ev.GetTier())
	case ev.GetAction() == "":
		return store.RecordInput{}, fmt.Errorf("event has no action")
	case ev.GetOccurredAt() == nil:
		return store.RecordInput{}, fmt.Errorf("event has no occurred_at")
	}
	if err := ev.GetOccurredAt().CheckValid(); err != nil {
		return store.RecordInput{}, fmt.Errorf("occurred_at: %v", err)
	}
	return store.RecordInput{
		Tier: tier, Action: ev.GetAction(), ActorUserID: ev.GetActorUserId(), Subject: ev.GetSubject(),
		GroupID: ev.GetGroupId(), OccurredAt: ev.GetOccurredAt().AsTime(), Attributes: ev.GetAttributes(),
		LegalBasisExempt: ev.GetLegalBasisExempt(),
	}, nil
}

// ConsumerConfig is the topology and settlement the consumer runs with. A
// failed message is not requeued: it goes to the queue's dead-letter exchange
// instead of looping.
func ConsumerConfig() rabbitmq.ConsumerConfig {
	return rabbitmq.ConsumerConfig{
		Exchange: rabbitmq.ExchangeConfig{Name: Exchange, Kind: "topic", Durable: true},
		Queue:    rabbitmq.QueueConfig{Name: Queue, Durable: true},
		Bindings: []rabbitmq.BindingConfig{
			{Queue: Queue, Exchange: Exchange, RoutingKey: RoutingKeyAudit},
			{Queue: Queue, Exchange: Exchange, RoutingKey: RoutingKeyActivity},
		},
		ConsumerTag: consumerTag,
	}.NoRequeue()
}

// Consume runs the consumer on conn until ctx is cancelled.
func (h *Handler) Consume(ctx context.Context, conn *rabbitmq.Conn) error {
	return h.Consumer(conn).Run(ctx)
}

// Consumer returns the consumer Consume runs, for a caller that needs to know
// when it is ready.
func (h *Handler) Consumer(conn *rabbitmq.Conn) *rabbitmq.Consumer {
	return conn.NewConsumer(ConsumerConfig(), h.Handle)
}
