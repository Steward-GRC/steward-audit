// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	containerOnce sync.Once
	containerDSN  string
	containerErr  error
)

// newTestDB returns a migrated database of its own for the calling test. With
// DATABASE_TEST_DSN set it is created on that server; otherwise on one
// Postgres container shared by the package's tests.
func newTestDB(t *testing.T) *postgres.DB {
	t.Helper()
	base := os.Getenv("DATABASE_TEST_DSN")
	if base == "" {
		containerOnce.Do(startContainer)
		if containerErr != nil {
			t.Fatalf("start postgres container: %v", containerErr)
		}
		base = containerDSN
	}
	ctx := context.Background()

	admin, err := postgres.New(ctx, base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer admin.Close()
	name := uniqueDBName()
	if _, err := admin.Querier().Exec(ctx, fmt.Sprintf(`CREATE DATABASE %q`, name)); err != nil {
		t.Fatalf("create db %s: %v", name, err)
	}

	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + name
	dsn := u.String()

	dir, err := filepath.Abs("../../migrations")
	if err != nil {
		t.Fatalf("migrations dir: %v", err)
	}
	if err := postgres.Migrate(dsn, dir); err != nil {
		t.Fatalf("migrate %s: %v", name, err)
	}
	db, err := postgres.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect %s: %v", name, err)
	}
	t.Cleanup(func() {
		db.Close()
		dropCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if a, err := postgres.New(dropCtx, base); err == nil {
			_, _ = a.Querier().Exec(dropCtx, fmt.Sprintf(`DROP DATABASE %q WITH (FORCE)`, name))
			a.Close()
		}
	})
	return db
}

func startContainer() {
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, "postgres:16",
		tcpostgres.WithDatabase("audit"),
		tcpostgres.WithUsername("audit"),
		tcpostgres.WithPassword("audit"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		containerErr = err
		return
	}
	containerDSN, containerErr = c.ConnectionString(ctx, "sslmode=disable")
}

func uniqueDBName() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "test_" + hex.EncodeToString(b[:])
}
