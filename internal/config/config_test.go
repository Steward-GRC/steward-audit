// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"

	"github.com/Steward-GRC/steward-audit/internal/fixture"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

const dsn = "postgres://audit@db.example.org/audit"

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(map[string]string{"DATABASE_DSN": dsn, "RABBITMQ_URL": "amqp://mq.example.org"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.GRPCPort != "9090" || c.OTLPEndpoint != "localhost:4317" || c.MigrationsDir != "migrations" || c.MigrateDSN != dsn {
		t.Fatalf("defaults: %+v", c)
	}
	if c.TSAURL != "" || c.CheckpointInterval != 15*time.Minute || c.CheckpointBatchSize != 10_000 {
		t.Fatalf("checkpoint defaults: %+v", c)
	}
}

func TestLoadReadsEverySetting(t *testing.T) {
	c, err := Load(env(map[string]string{
		"DATABASE_DSN": dsn, "MIGRATE_DSN": "postgres://migrate@db.example.org/audit", "MIGRATIONS_DIR": "/migrations",
		"RABBITMQ_URL": "amqp://mq.example.org", "GRPC_PORT": "9443", "OTEL_EXPORTER_OTLP_ENDPOINT": "otel.example.org:4317",
		"AUDIT_TSA_URL": fixture.TSAURL, "AUDIT_CHECKPOINT_INTERVAL": "1m", "AUDIT_CHECKPOINT_BATCH_SIZE": "500",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.MigrateDSN != "postgres://migrate@db.example.org/audit" || c.MigrationsDir != "/migrations" || c.GRPCPort != "9443" ||
		c.OTLPEndpoint != "otel.example.org:4317" || c.TSAURL != fixture.TSAURL || c.CheckpointInterval != time.Minute || c.CheckpointBatchSize != 500 {
		t.Fatalf("settings: %+v", c)
	}
}

// A bad value stops the boot instead of quietly falling back to a default.
func TestLoadRejectsBadSettings(t *testing.T) {
	base := map[string]string{"DATABASE_DSN": dsn, "RABBITMQ_URL": "amqp://mq.example.org"}
	for name, kv := range map[string][2]string{
		"no dsn":           {"DATABASE_DSN", ""},
		"no broker":        {"RABBITMQ_URL", ""},
		"bad interval":     {"AUDIT_CHECKPOINT_INTERVAL", "soon"},
		"zero interval":    {"AUDIT_CHECKPOINT_INTERVAL", "0s"},
		"bad batch":        {"AUDIT_CHECKPOINT_BATCH_SIZE", "many"},
		"zero batch":       {"AUDIT_CHECKPOINT_BATCH_SIZE", "0"},
		"tsa not http":     {"AUDIT_TSA_URL", "ftp://tsa.example.org"},
		"tsa not absolute": {"AUDIT_TSA_URL", "tsa.example.org"},
	} {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		m[kv[0]] = kv[1]
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
