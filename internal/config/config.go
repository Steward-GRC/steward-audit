// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package config reads the audit service's settings from the environment.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/Steward-GRC/steward-audit/internal/workloadauth"
)

// Config is every setting the service runs with.
type Config struct {
	DatabaseDSN   string
	MigrateDSN    string // a direct connection for migrations; defaults to DatabaseDSN
	MigrationsDir string
	RabbitURL     string
	GRPCPort      string
	// ProbePort serves /livez and /readyz over plain HTTP.
	ProbePort    string
	OTLPEndpoint string

	// WorkloadAuth verifies the callers' workload tokens. It is set when
	// WorkloadAuthEnabled; WORKLOAD_AUTH=disabled is the only way to turn it
	// off.
	WorkloadAuth        workloadauth.Config
	WorkloadAuthEnabled bool

	// TSAURL is the RFC 3161 time-stamp authority. Empty turns checkpoint
	// anchoring off: the adopter chooses the authority.
	TSAURL              string
	CheckpointInterval  time.Duration
	CheckpointBatchSize int
	// PurgeInterval is how often the activity-tier retention purge runs.
	PurgeInterval time.Duration
}

// Load reads the settings through getenv (os.Getenv in production).
func Load(getenv func(string) string) (Config, error) {
	or := func(k, d string) string {
		if v := getenv(k); v != "" {
			return v
		}
		return d
	}
	c := Config{
		DatabaseDSN:   getenv("DATABASE_DSN"),
		MigrationsDir: or("MIGRATIONS_DIR", "migrations"),
		RabbitURL:     getenv("RABBITMQ_URL"),
		GRPCPort:      or("GRPC_PORT", "9090"),
		ProbePort:     or("PROBE_PORT", "8080"),
		OTLPEndpoint:  or("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"),
		TSAURL:        getenv("AUDIT_TSA_URL"),
	}
	c.MigrateDSN = or("MIGRATE_DSN", c.DatabaseDSN)

	var errs []error
	if c.DatabaseDSN == "" {
		errs = append(errs, errors.New("DATABASE_DSN is required"))
	}
	if c.RabbitURL == "" {
		errs = append(errs, errors.New("RABBITMQ_URL is required"))
	}
	if c.TSAURL != "" {
		if u, err := url.Parse(c.TSAURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, fmt.Errorf("AUDIT_TSA_URL %q is not an http or https URL", c.TSAURL))
		}
	}
	var err error
	if c.WorkloadAuth, c.WorkloadAuthEnabled, err = workloadauth.ServerConfigFromEnv(getenv); err != nil {
		errs = append(errs, err)
	}
	if c.CheckpointInterval, err = time.ParseDuration(or("AUDIT_CHECKPOINT_INTERVAL", "15m")); err != nil || c.CheckpointInterval <= 0 {
		errs = append(errs, errors.New("AUDIT_CHECKPOINT_INTERVAL must be a positive duration"))
	}
	if c.CheckpointBatchSize, err = strconv.Atoi(or("AUDIT_CHECKPOINT_BATCH_SIZE", "10000")); err != nil || c.CheckpointBatchSize <= 0 {
		errs = append(errs, errors.New("AUDIT_CHECKPOINT_BATCH_SIZE must be a positive integer"))
	}
	if c.PurgeInterval, err = time.ParseDuration(or("AUDIT_PURGE_INTERVAL", "1h")); err != nil || c.PurgeInterval <= 0 {
		errs = append(errs, errors.New("AUDIT_PURGE_INTERVAL must be a positive duration"))
	}
	return c, errors.Join(errs...)
}
