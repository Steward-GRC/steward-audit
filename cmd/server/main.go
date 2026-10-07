// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Command server runs the audit service: it consumes audit events into the
// hash chain, anchors Merkle checkpoints with an RFC 3161 time-stamp
// authority, and serves the AuditService API.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	buildinfo "github.com/Bugs5382/go-buildinfo"
	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	gootel "github.com/Bugs5382/go-otel"
	postgres "github.com/Bugs5382/go-postgres"
	pgotel "github.com/Bugs5382/go-postgres/otel"
	"github.com/Bugs5382/go-rabbitmq"
	rmqotel "github.com/Bugs5382/go-rabbitmq/otel"
	"google.golang.org/grpc"

	auditv1 "github.com/Steward-GRC/steward-audit/gen/go/steward/audit/v1"
	"github.com/Steward-GRC/steward-audit/internal/anchor"
	"github.com/Steward-GRC/steward-audit/internal/checkpoint"
	"github.com/Steward-GRC/steward-audit/internal/config"
	"github.com/Steward-GRC/steward-audit/internal/ingest"
	"github.com/Steward-GRC/steward-audit/internal/readiness"
	"github.com/Steward-GRC/steward-audit/internal/server"
	"github.com/Steward-GRC/steward-audit/internal/store"
	"github.com/Steward-GRC/steward-audit/internal/workloadauth"
)

const serviceName = "audit"

// jwksRecheck is how long a good JWKS fetch keeps readiness up before the
// next probe fetches the key set again.
const jwksRecheck = time.Minute

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger := log.NewLogger(serviceName)
	if err := run(ctx, logger); err != nil {
		logger.Fatal(err, "audit service stopped")
	}
}

func run(ctx context.Context, logger log.Logger) error {
	bi := buildinfo.Get()
	logger.Info("starting", log.F("version", bi.Version), log.F("commit", bi.Commit), log.F("go_version", bi.GoVersion))
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	otelShutdown, err := gootel.Init(ctx, serviceName, cfg.OTLPEndpoint)
	if err != nil {
		return fmt.Errorf("otel: %w", err)
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Warn("otel shutdown", log.F("error", err.Error()))
		}
	}()

	if err := pgotel.InstrumentMigrate(ctx, serviceName, func() error {
		return postgres.Migrate(cfg.MigrateDSN, cfg.MigrationsDir)
	}); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	db, err := postgres.New(ctx, cfg.DatabaseDSN, pgotel.WithTracing())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer db.Close()
	records := store.NewRecordStore(db)
	checkpoints := store.NewCheckpointStore(db)

	if cfg.TSAURL == "" {
		logger.Warn("AUDIT_TSA_URL is not set: checkpoints are not anchored")
	} else {
		last, err := checkpoints.LastCheckpointedID(ctx)
		if err != nil {
			return err
		}
		sched := checkpoint.New(
			hashReader{records, cfg.CheckpointBatchSize}, checkpointWriter{checkpoints},
			anchor.NewTSAClient(cfg.TSAURL), cfg.CheckpointInterval,
		).ResumeAfter(last).WithLogger(logger)
		logger.Info("checkpointing", log.F("after_record_id", last), log.F("interval", cfg.CheckpointInterval.String()))
		go sched.Run(ctx)
	}

	conn, err := rabbitmq.Connect(ctx, cfg.RabbitURL, append(rmqotel.Instrument(), rabbitmq.WithLogger(rabbitLogger{logger}))...)
	if err != nil {
		return fmt.Errorf("rabbitmq: %w", err)
	}
	defer func() { _ = conn.Close() }()
	go func() {
		if err := ingest.NewHandler(records).Consume(ctx, conn); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error(err, "audit event consumer stopped")
		}
	}()

	deps := readiness.Deps{Postgres: readiness.PostgresDB(db), Broker: conn}
	var auth *server.Auth
	if cfg.WorkloadAuthEnabled {
		v, err := workloadauth.NewVerifier(cfg.WorkloadAuth, logger)
		if err != nil {
			return fmt.Errorf("workload auth: %w", err)
		}
		go v.Run(ctx)
		deps.JWKS = readiness.RecheckEvery(v.Refresh, jwksRecheck, time.Now)
		auth = &server.Auth{Verifier: v, Policy: server.CallerPolicy(), Options: []workloadauth.Option{
			workloadauth.WithDenyHook(server.AuditDenial(records, logger)),
		}}
		logger.Info("service-to-service authentication on",
			log.F("issuer", cfg.WorkloadAuth.Issuer), log.F("audience", cfg.WorkloadAuth.Audience),
			log.F("jwks_override", cfg.WorkloadAuth.JWKSURL != ""), log.F("ca_file", cfg.WorkloadAuth.CAFile != ""),
			log.F("bearer_file", cfg.WorkloadAuth.BearerFile != ""),
			log.F("allowed_serviceaccounts", strings.Join(cfg.WorkloadAuth.AllowedServiceAccounts, ",")))
	} else {
		deps.WorkloadAuthDisabled = true
		go workloadauth.WarnDisabled(ctx, logger, workloadauth.DisabledWarnInterval)
	}
	checker, err := readiness.New(deps, health.WithTTL(5*time.Second), health.WithTimeout(2*time.Second), health.WithLogger(logger))
	if err != nil {
		return fmt.Errorf("readiness: %w", err)
	}

	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", ":"+cfg.GRPCPort)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	probeLis, err := lc.Listen(ctx, "tcp", ":"+cfg.ProbePort)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	api := server.NewAuditServer(auditStore{records, checkpoints}).WithLogger(logger)
	logger.Info("serving", log.F("port", cfg.GRPCPort), log.F("probe_port", cfg.ProbePort))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	probesDone := make(chan error, 1)
	go func() {
		probesDone <- server.ServeProbes(ctx, probeLis, checker)
		cancel()
	}()
	err = server.Serve(ctx, lis, logger, server.Options{Auth: auth, Checker: checker},
		func(s *grpc.Server) { auditv1.RegisterAuditServiceServer(s, api) })
	cancel()
	if perr := <-probesDone; err == nil {
		err = perr
	}
	return err
}

type hashReader struct {
	rs    *store.RecordStore
	batch int
}

func (r hashReader) HashesSince(ctx context.Context, lastID int64) ([]string, int64, error) {
	return r.rs.HashesAfter(ctx, lastID, r.batch)
}

type checkpointWriter struct{ cs *store.CheckpointStore }

// The anchor's token carries the authoritative time; AnchoredAt is local and
// informational.
func (w checkpointWriter) SaveCheckpoint(ctx context.Context, in checkpoint.SaveInput) error {
	_, err := w.cs.SaveCheckpoint(ctx, store.CheckpointInput{
		FromRecordID: in.FromID, ToRecordID: in.ToID, MerkleRoot: in.MerkleRoot, AnchorType: in.AnchorType,
		AnchorURL: in.AnchorURL, TSAToken: in.RawToken, AnchoredAt: time.Now().UTC(), AnchorStatus: "anchored",
	})
	return err
}

type auditStore struct {
	*store.RecordStore
	cs *store.CheckpointStore
}

func (a auditStore) CheckpointsInRange(ctx context.Context, fromID, toID int64) ([]store.Checkpoint, error) {
	return a.cs.CheckpointsInRange(ctx, fromID, toID)
}

type rabbitLogger struct{ l log.Logger }

func (r rabbitLogger) Debugf(f string, a ...any) { r.l.Debug(fmt.Sprintf(f, a...)) }
func (r rabbitLogger) Infof(f string, a ...any)  { r.l.Info(fmt.Sprintf(f, a...)) }
func (r rabbitLogger) Warnf(f string, a ...any)  { r.l.Warn(fmt.Sprintf(f, a...)) }
func (r rabbitLogger) Errorf(f string, a ...any) { r.l.Error(nil, fmt.Sprintf(f, a...)) }
