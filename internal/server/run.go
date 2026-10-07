// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/Bugs5382/go-buildinfo/grpcbuildinfo"
	"github.com/Bugs5382/go-buildinfo/health"
	"github.com/Bugs5382/go-buildinfo/httpbuildinfo"
	log "github.com/Bugs5382/go-log"
	gootel "github.com/Bugs5382/go-otel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpchealth "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/Steward-GRC/steward-audit/internal/workloadauth"
)

// gracefulStopTimeout bounds the drain of in-flight RPCs on shutdown, so a
// hung peer can't hold the process.
const gracefulStopTimeout = 10 * time.Second

// HealthPrefix starts the build and dependency headers: steward-version,
// steward-commit, steward-dep-<name> and steward-depstate-<name>.
const HealthPrefix = "steward"

// grpc.health.v1 service names. The empty name and ReadinessService follow
// readiness; LivenessService reports the process only, so a dependency outage
// never gets audit restarted.
const (
	ReadinessService = "readiness"
	LivenessService  = "liveness"
)

// reflectionServices stay open with health, so grpcurl and probes need no
// token.
var reflectionServices = []string{"/grpc.reflection.v1.ServerReflection/", "/grpc.reflection.v1alpha.ServerReflection/"}

// Auth authenticates callers by their workload token (see
// internal/workloadauth).
type Auth struct {
	Verifier workloadauth.TokenVerifier
	// Policy is the per-method caller allow-list.
	Policy workloadauth.Policy
	// Options tune the interceptors, typically a deny hook that audits.
	Options []workloadauth.Option
}

// Options are the probe and authentication settings. Zero serves every call
// with no caller authentication (WORKLOAD_AUTH=disabled) and is always ready.
type Options struct {
	// Auth authenticates every call except health and reflection. Nil only
	// when WORKLOAD_AUTH=disabled.
	Auth *Auth
	// Checker holds the dependencies readiness follows.
	Checker *health.Checker
	// CheckInterval is how often Health/Watch subscribers are brought up to
	// date (go-buildinfo's default when zero).
	CheckInterval time.Duration
}

// Serve runs a gRPC server on lis with go-otel tracing, panic recovery,
// workload authentication, grpc.health.v1 following readiness and reflection,
// plus the services register adds. It returns nil once ctx is cancelled and
// the server has stopped.
func Serve(ctx context.Context, lis net.Listener, lg log.Logger, opts Options, register func(*grpc.Server)) error {
	checker := opts.Checker
	if checker == nil {
		checker = health.New()
	}
	hs := grpchealth.NewServer()
	biOpts := []grpcbuildinfo.Option{
		grpcbuildinfo.WithPrefix(HealthPrefix), grpcbuildinfo.WithChecker(checker), grpcbuildinfo.WithHealthServer(hs),
		grpcbuildinfo.WithServices(ReadinessService), grpcbuildinfo.WithLivenessService(LivenessService),
	}
	if opts.CheckInterval > 0 {
		biOpts = append(biOpts, grpcbuildinfo.WithInterval(opts.CheckInterval))
	}
	bi, err := grpcbuildinfo.New(biOpts...)
	if err != nil {
		return fmt.Errorf("server: health: %w", err)
	}
	unary := []grpc.UnaryServerInterceptor{bi.UnaryServerInterceptor(), recoverUnary(lg)}
	stream := []grpc.StreamServerInterceptor{bi.StreamServerInterceptor(), recoverStream(lg)}
	if a := opts.Auth; a != nil {
		waOpts := append([]workloadauth.Option{workloadauth.WithExempt(reflectionServices...)}, a.Options...)
		unary = append(unary, workloadauth.UnaryServerInterceptor(a.Verifier, a.Policy, lg, waOpts...))
		stream = append(stream, workloadauth.StreamServerInterceptor(a.Verifier, a.Policy, lg, waOpts...))
	}
	s := grpc.NewServer(
		grpc.StatsHandler(gootel.GRPCServerStatsHandler()),
		grpc.ChainUnaryInterceptor(unary...),
		grpc.ChainStreamInterceptor(stream...),
	)
	healthpb.RegisterHealthServer(s, hs)
	bi.Update(ctx)
	go bi.Run(ctx)
	reflection.Register(s)
	register(s)

	errCh := make(chan error, 1)
	go func() { errCh <- s.Serve(lis) }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		hs.Shutdown()
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

// ServeProbes serves /livez and /readyz over plain HTTP on lis, for probes
// that can't speak gRPC. It returns nil once ctx is cancelled.
func ServeProbes(ctx context.Context, lis net.Listener, checker *health.Checker) error {
	h, err := httpbuildinfo.New(httpbuildinfo.WithPrefix(HealthPrefix), httpbuildinfo.WithChecker(checker))
	if err != nil {
		return fmt.Errorf("server: probes: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /livez", h.Livez())
	mux.Handle("GET /readyz", h.Readyz())
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(lis) }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), gracefulStopTimeout)
		defer cancel()
		_ = srv.Shutdown(sctx)
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
