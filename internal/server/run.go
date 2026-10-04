// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net"
	"runtime/debug"
	"time"

	log "github.com/Bugs5382/go-log"
	gootel "github.com/Bugs5382/go-otel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// gracefulStopTimeout bounds the drain of in-flight RPCs on shutdown, so a
// hung peer can't hold the process.
const gracefulStopTimeout = 10 * time.Second

// Serve runs a gRPC server on lis with go-otel tracing, panic recovery,
// grpc.health.v1 and reflection, plus the services register adds. It returns
// nil once ctx is cancelled and the server has stopped.
func Serve(ctx context.Context, lis net.Listener, lg log.Logger, register func(*grpc.Server)) error {
	s := grpc.NewServer(
		grpc.StatsHandler(gootel.GRPCServerStatsHandler()),
		grpc.ChainUnaryInterceptor(recoverUnary(lg)),
		grpc.ChainStreamInterceptor(recoverStream(lg)),
	)
	healthpb.RegisterHealthServer(s, health.NewServer())
	reflection.Register(s)
	register(s)

	errCh := make(chan error, 1)
	go func() { errCh <- s.Serve(lis) }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		stopped := make(chan struct{})
		go func() {
			s.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(gracefulStopTimeout):
			s.Stop()
		}
		<-errCh
		return nil
	}
}

// The panic value and stack go to the log only; the caller gets a bare
// Internal.
func recoverUnary(lg log.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				resp, err = nil, recovered(ctx, lg, r, info.FullMethod)
			}
		}()
		return handler(ctx, req)
	}
}

func recoverStream(lg log.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = recovered(ss.Context(), lg, r, info.FullMethod)
			}
		}()
		return handler(srv, ss)
	}
}

func recovered(ctx context.Context, lg log.Logger, r any, method string) error {
	lg.Ctx(ctx).Error(nil, "recovered from a panic in a gRPC handler",
		log.F("method", method), log.F("panic", r), log.F("stack", string(debug.Stack())))
	return status.Error(codes.Internal, "internal error")
}
