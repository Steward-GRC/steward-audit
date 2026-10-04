// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package ingest turns events from the broker into chained records. Services
// publish to the "audit" topic exchange with routing key audit.audit (the
// audit tier) or audit.activity (the activity tier); the body is an Event in
// JSON. The tier in the body is the one stored.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Bugs5382/go-rabbitmq"

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

// Event is the message body publishers send.
type Event struct {
	Tier             string            `json:"tier"`
	Action           string            `json:"action"`
	ActorUserID      string            `json:"actor_user_id,omitempty"`
	Subject          string            `json:"subject,omitempty"`
	GroupID          string            `json:"group_id,omitempty"`
	OccurredAt       time.Time         `json:"occurred_at"`
	Attributes       map[string]string `json:"attributes,omitempty"`
	LegalBasisExempt bool              `json:"legal_basis_exempt,omitempty"`
}

// Appender stores a record.
type Appender interface {
	AppendRecord(ctx context.Context, in store.RecordInput) (*store.Record, error)
}

// Handler stores each delivered event.
type Handler struct{ store Appender }

// NewHandler returns a Handler that appends to s.
func NewHandler(s Appender) *Handler { return &Handler{store: s} }

// Handle stores one event. A body that can never be stored is dead-lettered;
// any other error is returned for the consumer to settle.
func (h *Handler) Handle(ctx context.Context, _ string, body []byte) error {
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		return fmt.Errorf("ingest: decode event: %v: %w", err, rabbitmq.ErrDeadLetter)
	}
	if err := ev.validate(); err != nil {
		return fmt.Errorf("ingest: %v: %w", err, rabbitmq.ErrDeadLetter)
	}
	_, err := h.store.AppendRecord(ctx, store.RecordInput{
		Tier: ev.Tier, Action: ev.Action, ActorUserID: ev.ActorUserID, Subject: ev.Subject, GroupID: ev.GroupID,
		OccurredAt: ev.OccurredAt, Attributes: ev.Attributes, LegalBasisExempt: ev.LegalBasisExempt,
	})
	return err
}

func (ev Event) validate() error {
	switch {
	case ev.Tier != "audit" && ev.Tier != "activity":
		return fmt.Errorf("tier %q is not audit or activity", ev.Tier)
	case ev.Action == "":
		return fmt.Errorf("event has no action")
	case ev.OccurredAt.IsZero():
		return fmt.Errorf("event has no occurred_at")
	}
	return nil
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
		ConsumerTag:    consumerTag,
		RequeueOnError: false,
	}
}

// Consume runs the consumer on conn until ctx is cancelled.
func (h *Handler) Consume(ctx context.Context, conn *rabbitmq.Conn) error {
	return conn.Consume(ctx, ConsumerConfig(), func(ctx context.Context, d rabbitmq.Delivery) error {
		return h.Handle(ctx, d.RoutingKey, d.Body)
	})
}
