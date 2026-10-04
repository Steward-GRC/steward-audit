// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Bugs5382/go-rabbitmq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/Steward-GRC/steward-audit/gen/go/steward/audit/v1"
	"github.com/Steward-GRC/steward-audit/internal/fixture"
	"github.com/Steward-GRC/steward-audit/internal/store"
)

var (
	brokerOnce sync.Once
	brokerURL  string
	brokerErr  error
)

// testBroker returns a broker URL: RABBITMQ_TEST_URL when set, otherwise one
// RabbitMQ container shared by the package's tests, which run one at a time
// on the service's own queue.
func testBroker(t *testing.T) string {
	t.Helper()
	if u := os.Getenv("RABBITMQ_TEST_URL"); u != "" {
		return u
	}
	brokerOnce.Do(startBroker)
	if brokerErr != nil {
		t.Fatalf("start rabbitmq container: %v", brokerErr)
	}
	return brokerURL
}

func startBroker() {
	ctx := context.Background()
	c, err := testcontainers.Run(ctx, "rabbitmq:4-management-alpine",
		testcontainers.WithExposedPorts("5672/tcp"),
		testcontainers.WithEnv(map[string]string{"RABBITMQ_DEFAULT_USER": "audit", "RABBITMQ_DEFAULT_PASS": "audit"}),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Server startup complete").WithStartupTimeout(90*time.Second),
			wait.ForListeningPort("5672/tcp"),
		),
	)
	if err != nil {
		brokerErr = err
		return
	}
	host, err := c.Host(ctx)
	if err != nil {
		brokerErr = err
		return
	}
	port, err := c.MappedPort(ctx, "5672/tcp")
	if err != nil {
		brokerErr = err
		return
	}
	brokerURL = fmt.Sprintf("amqp://audit:audit@%s:%s/", host, port.Port())
}

// recordingStore stores every event except those whose action is in fail,
// and counts every attempt per action.
type recordingStore struct {
	mu       sync.Mutex
	fail     map[string]bool
	attempts map[string]int
	stored   chan store.RecordInput
}

func newRecordingStore(failActions ...string) *recordingStore {
	s := &recordingStore{fail: map[string]bool{}, attempts: map[string]int{}, stored: make(chan store.RecordInput, 16)}
	for _, a := range failActions {
		s.fail[a] = true
	}
	return s
}

func (s *recordingStore) AppendRecord(_ context.Context, in store.RecordInput) (*store.Record, error) {
	s.mu.Lock()
	s.attempts[in.Action]++
	failing := s.fail[in.Action]
	s.mu.Unlock()
	if failing {
		return nil, errors.New("db: connection reset")
	}
	s.stored <- in
	return &store.Record{ID: 1, RecordInput: in, RecordHash: "fakehash"}, nil
}

// runConsumer starts the handler's consumer on a broker and waits until it is
// consuming, so nothing published afterwards is unroutable.
func runConsumer(t *testing.T, s Appender) *rabbitmq.Publisher {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := rabbitmq.Connect(ctx, testBroker(t))
	if err != nil {
		cancel()
		t.Fatalf("connect: %v", err)
	}
	cons := NewHandler(s).Consumer(conn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = cons.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = conn.Close()
	})
	deadline := time.Now().Add(30 * time.Second)
	for !cons.Ready() {
		if time.Now().After(deadline) {
			t.Fatalf("consumer not ready: %+v", cons.Status())
		}
		time.Sleep(20 * time.Millisecond)
	}
	pub := conn.NewPublisher(Exchange, rabbitmq.WithConfirms())
	t.Cleanup(func() { _ = pub.Close() })
	return pub
}

func publish(t *testing.T, pub *rabbitmq.Publisher, routingKey, contentType string, b []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pub.Publish(ctx, routingKey, b, rabbitmq.WithContentType(contentType)); err != nil {
		t.Fatalf("publish: %v", err)
	}
}

func waitStored(t *testing.T, s *recordingStore) store.RecordInput {
	t.Helper()
	select {
	case in := <-s.stored:
		return in
	case <-time.After(15 * time.Second):
		t.Fatal("no record stored")
		return store.RecordInput{}
	}
}

// An event published as protobuf through the broker is stored as sent, and a
// malformed message ahead of it neither blocks it nor is stored.
func TestBrokerRoundTrip(t *testing.T) {
	s := newRecordingStore()
	pub := runConsumer(t, s)

	ev := &auditv1.AuditEvent{
		Tier: auditv1.Tier_TIER_AUDIT, Action: fixture.PolicyPublished, ActorUserId: fixture.Bob,
		Subject: fixture.DeskBookingPolicy, GroupId: fixture.FacilitiesTeam, OccurredAt: timestamppb.Now(),
		Attributes: map[string]string{"version": "v1"}, LegalBasisExempt: true,
	}
	publish(t, pub, RoutingKeyAudit, ContentType, []byte("not-protobuf"))
	publish(t, pub, RoutingKeyAudit, "application/json", []byte(`{"tier":"audit"}`))
	publish(t, pub, RoutingKeyAudit, ContentType, body(t, ev))

	got := waitStored(t, s)
	if got.Tier != "audit" || got.Action != ev.Action || got.ActorUserID != ev.ActorUserId || got.Subject != ev.Subject ||
		got.GroupID != ev.GroupId || !got.OccurredAt.Equal(ev.OccurredAt.AsTime()) || got.Attributes["version"] != "v1" ||
		!got.LegalBasisExempt {
		t.Fatalf("event not carried over: %+v", got)
	}
	select {
	case extra := <-s.stored:
		t.Fatalf("a malformed message was stored: %+v", extra)
	default:
	}
}
