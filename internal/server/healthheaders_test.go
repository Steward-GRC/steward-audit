// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"

	auditv1 "github.com/Steward-GRC/steward-audit/gen/go/steward/audit/v1"
)

func TestHealthCheckCarriesTheBuildAndDependencyHeaders(t *testing.T) {
	checker := health.New(health.WithTTL(time.Millisecond))
	require.NoError(t, checker.Register(
		health.Dependency{Name: "postgres", Required: true,
			Check:   func(context.Context) error { return nil },
			Version: func(context.Context) (string, error) { return "16.4", nil }},
		health.Dependency{Name: "rabbitmq", Required: true, Check: func(context.Context) error { return nil }},
	))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, lis, log.Nop(), Options{Checker: checker}, func(s *grpc.Server) {
			auditv1.RegisterAuditServiceServer(s, auditv1.UnimplementedAuditServiceServer{})
		})
	}()
	defer func() {
		cancel()
		require.NoError(t, <-done)
	}()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	var md metadata.MD
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	_, err = healthpb.NewHealthClient(conn).Check(callCtx, &healthpb.HealthCheckRequest{}, grpc.Header(&md))
	require.NoError(t, err)
	require.Equal(t, []string{"dev"}, md.Get("steward-version"), "an unstamped build")
	require.NotEmpty(t, md.Get("steward-commit"))
	require.Equal(t, []string{"16.4"}, md.Get("steward-dep-postgres"))
	require.Equal(t, []string{"ok"}, md.Get("steward-depstate-postgres"))
	require.Equal(t, []string{"ok"}, md.Get("steward-depstate-rabbitmq"))

	md = nil
	_, err = auditv1.NewAuditServiceClient(conn).VerifyAuditChain(callCtx, &auditv1.VerifyAuditChainRequest{}, grpc.Header(&md))
	require.Error(t, err)
	require.Empty(t, md.Get("steward-version"), "only Health/Check carries the build headers")
}
