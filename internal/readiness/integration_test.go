// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package readiness_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Bugs5382/go-rabbitmq"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Steward-GRC/steward-audit/internal/readiness"
)

func startPostgres(t *testing.T) (testcontainers.Container, *postgres.DB) {
	t.Helper()
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("audit"), tcpostgres.WithUsername("audit"), tcpostgres.WithPassword("audit"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(c) })
	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	db, err := postgres.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(db.Close)
	return c, db
}

func startRabbitMQ(t *testing.T) (testcontainers.Container, *rabbitmq.Conn) {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "rabbitmq:3-alpine", ExposedPorts: []string{"5672/tcp"},
			WaitingFor: wait.ForListeningPort("5672/tcp").WithStartupTimeout(90 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(c) })
	host, err := c.Host(ctx)
	require.NoError(t, err)
	port, err := c.MappedPort(ctx, "5672/tcp")
	require.NoError(t, err)
	var conn *rabbitmq.Conn
	require.Eventually(t, func() bool {
		conn, err = rabbitmq.Connect(ctx, fmt.Sprintf("amqp://guest:guest@%s:%s/", host, port.Port()))
		return err == nil
	}, 60*time.Second, time.Second, "rabbitmq accepts connections")
	t.Cleanup(func() { _ = conn.Close() })
	return c, conn
}

func stop(t *testing.T, c testcontainers.Container) {
	t.Helper()
	timeout := 5 * time.Second
	require.NoError(t, c.Stop(context.Background(), &timeout))
}

func TestStoppingEachDependencyMakesAuditNotReady(t *testing.T) {
	if testing.Short() {
		t.Skip("needs Docker")
	}
	pgC, db := startPostgres(t)
	mqC, conn := startRabbitMQ(t)
	c, err := readiness.New(readiness.Deps{Postgres: readiness.PostgresDB(db), Broker: conn},
		health.WithTTL(time.Millisecond), health.WithTimeout(2*time.Second))
	require.NoError(t, err)
	report := func() health.Report { return c.Report(context.Background()) }

	r := report()
	require.True(t, r.Ready)
	require.Equal(t, health.StateOK, r.Status)
	require.Regexp(t, `^16\.\d+$`, dep(t, r, readiness.Postgres).Version)

	t.Run("postgres", func(t *testing.T) {
		stop(t, pgC)
		require.Eventually(t, func() bool { return dep(t, report(), readiness.Postgres).State == health.StateDown }, 30*time.Second, 100*time.Millisecond)
		require.False(t, report().Ready)
	})
	t.Run("rabbitmq", func(t *testing.T) {
		stop(t, mqC)
		require.Eventually(t, func() bool { return dep(t, report(), readiness.RabbitMQ).State == health.StateDown }, 30*time.Second, 100*time.Millisecond)
		require.False(t, report().Ready)
	})
}
