// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Steward-GRC/steward-audit/internal/fixture"
	"github.com/Steward-GRC/steward-audit/internal/workloadauth"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

const dsn = "postgres://audit@db.example.org/audit"

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(map[string]string{"DATABASE_DSN": dsn, "RABBITMQ_URL": "amqp://mq.example.org", "WORKLOAD_AUTH": "disabled"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ProbePort != "8080" || c.WorkloadAuthEnabled {
		t.Fatalf("probe and workload auth defaults: %+v", c)
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
		"PROBE_PORT": "8081", "WORKLOAD_OIDC_ISSUER": "https://issuer.example.org",
		"WORKLOAD_OIDC_JWKS_URL": "https://issuer.example.org/openid/v1/jwks", "WORKLOAD_OIDC_CA_FILE": "/oidc/ca.crt",
		"WORKLOAD_OIDC_BEARER_FILE": "/oidc/token", "WORKLOAD_AUDIENCE": "steward",
		"WORKLOAD_ALLOWED_SERVICEACCOUNTS": "steward/steward-gateway, steward/steward-reporting",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.MigrateDSN != "postgres://migrate@db.example.org/audit" || c.MigrationsDir != "/migrations" || c.GRPCPort != "9443" ||
		c.OTLPEndpoint != "otel.example.org:4317" || c.TSAURL != fixture.TSAURL || c.CheckpointInterval != time.Minute || c.CheckpointBatchSize != 500 {
		t.Fatalf("settings: %+v", c)
	}
	want := workloadauth.Config{
		Issuer: "https://issuer.example.org", JWKSURL: "https://issuer.example.org/openid/v1/jwks", CAFile: "/oidc/ca.crt",
		BearerFile: "/oidc/token", Audience: "steward", AllowedServiceAccounts: []string{"steward/steward-gateway", "steward/steward-reporting"},
	}
	if c.ProbePort != "8081" || !c.WorkloadAuthEnabled || !reflect.DeepEqual(c.WorkloadAuth, want) {
		t.Fatalf("probe and workload auth: %+v", c)
	}
}

func base() map[string]string {
	return map[string]string{"DATABASE_DSN": dsn, "RABBITMQ_URL": "amqp://mq.example.org"}
}

// Unset WORKLOAD_AUTH means on: with no issuer the boot stops instead of
// serving every caller unauthenticated.
func TestLoadFailsClosedWithoutWorkloadAuth(t *testing.T) {
	if _, err := Load(env(base())); !errors.Is(err, workloadauth.ErrNotConfigured) {
		t.Fatalf("no issuer and no explicit off switch must stop the boot, got %v", err)
	}
}

func TestLoadTurnsWorkloadAuthOffOnlyWhenDisabled(t *testing.T) {
	m := base()
	m["WORKLOAD_AUTH"] = "disabled"
	c, err := Load(env(m))
	if err != nil || c.WorkloadAuthEnabled {
		t.Fatalf("WORKLOAD_AUTH=disabled: %+v %v", c, err)
	}
	for _, v := range []string{"enabled", "off", "false", "Disabled"} {
		m["WORKLOAD_AUTH"] = v
		if _, err := Load(env(m)); err == nil {
			t.Errorf("WORKLOAD_AUTH=%q must be refused", v)
		}
	}
	m["WORKLOAD_AUTH"] = "disabled"
	m["WORKLOAD_OIDC_ISSUER"] = "https://issuer.example.org"
	m["WORKLOAD_ALLOWED_SERVICEACCOUNTS"] = "steward/steward-gateway"
	if _, err := Load(env(m)); err == nil {
		t.Error("an issuer together with WORKLOAD_AUTH=disabled must be refused")
	}
}

// A bad value stops the boot instead of quietly falling back to a default.
func TestLoadRejectsBadSettings(t *testing.T) {
	base := map[string]string{"DATABASE_DSN": dsn, "RABBITMQ_URL": "amqp://mq.example.org", "WORKLOAD_AUTH": "disabled"}
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
