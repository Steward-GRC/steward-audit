// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	auditv1 "github.com/Steward-GRC/steward-audit/gen/go/steward/audit/v1"
)

type panicky struct {
	auditv1.UnimplementedAuditServiceServer
}

func (panicky) VerifyAuditChain(context.Context, *auditv1.VerifyAuditChainRequest) (*auditv1.VerifyAuditChainResponse, error) {
	panic("boom: secret detail")
}

func TestRunServesHealthRecoversPanicsAndStops(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, lis, log.Nop(), Options{}, func(s *grpc.Server) { auditv1.RegisterAuditServiceServer(s, panicky{}) })
	}()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()

	hc, err := healthpb.NewHealthClient(conn).Check(callCtx, &healthpb.HealthCheckRequest{})
	if err != nil || hc.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("health: %v %v", hc, err)
	}
	_, err = auditv1.NewAuditServiceClient(conn).VerifyAuditChain(callCtx, &auditv1.VerifyAuditChainRequest{})
	if st := status.Convert(err); st.Code() != codes.Internal || st.Message() != "internal error" {
		t.Fatalf("a panic must surface as a bare Internal, got %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v after shutdown", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not stop")
	}
}
