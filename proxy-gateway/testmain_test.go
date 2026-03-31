package main

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func applyMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ddl, err := os.ReadFile("db/migrations/001_usage.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := pool.Exec(context.Background(), string(ddl)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Shared embedded Postgres — started once for the whole test binary.
// Each test gets its own database (CREATE DATABASE testN) so tests are
// fully isolated without paying the ~9s startup cost per test.
// ---------------------------------------------------------------------------

const sharedDBPort = 15432

var sharedPool *pgxpool.Pool // connects to "postgres" DB (admin)
var dbCounter atomic.Int64   // unique DB name per test

func TestMain(m *testing.M) {
	pg := embeddedpostgres.NewDatabase(
		embeddedpostgres.DefaultConfig().
			Port(sharedDBPort).
			Logger(os.Stderr),
	)
	if err := pg.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "embedded postgres start: %v\n", err)
		os.Exit(1)
	}

	dsn := fmt.Sprintf(
		"host=localhost port=%d user=postgres password=postgres dbname=postgres sslmode=disable",
		sharedDBPort,
	)
	var err error
	sharedPool, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		pg.Stop() //nolint:errcheck
		fmt.Fprintf(os.Stderr, "pgxpool.New: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	sharedPool.Close()
	pg.Stop() //nolint:errcheck
	os.Exit(code)
}

// newTestDB creates a fresh database for one test and returns a pool connected
// to it. The database is dropped when the test finishes.
func newTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	n := dbCounter.Add(1)
	dbName := fmt.Sprintf("testdb_%d", n)

	if _, err := sharedPool.Exec(context.Background(), "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		// Terminate any open connections before dropping.
		sharedPool.Exec(context.Background(), //nolint:errcheck
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1", dbName)
		sharedPool.Exec(context.Background(), "DROP DATABASE "+dbName) //nolint:errcheck
	})

	dsn := fmt.Sprintf(
		"host=localhost port=%d user=postgres password=postgres dbname=%s sslmode=disable",
		sharedDBPort, dbName,
	)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New for %s: %v", dbName, err)
	}
	t.Cleanup(pool.Close)

	applyMigration(t, pool)
	return pool
}
