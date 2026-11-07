//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"kaspersky_test/internal/domain"
	"kaspersky_test/internal/repository/postgres"
	"kaspersky_test/migrations"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func setupDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	db := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpContext(ctx, db, "."))

	return pool
}

func newThreat() *domain.Threat {
	now := time.Now().UTC()
	return &domain.Threat{
		MD5:       testMD5,
		Name:      "Trojan.Win32.Generic",
		Severity:  severityPtr(domain.SeverityHigh),
		Tags:      []string{"windows", "executable"},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func severityPtr(s domain.Severity) *domain.Severity { return &s }

// --- Create ---

func TestThreatRepo_Create(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.New(pool)
	ctx := context.Background()

	threat := newThreat()
	created, err := repo.Create(ctx, threat)
	require.NoError(t, err)
	require.NotNil(t, created)
	require.Equal(t, testMD5, created.MD5)
	require.Equal(t, "Trojan.Win32.Generic", created.Name)
	require.NotNil(t, created.Severity)
	require.Equal(t, domain.SeverityHigh, *created.Severity)
	require.ElementsMatch(t, []string{"windows", "executable"}, created.Tags)
	require.False(t, created.CreatedAt.IsZero())
	require.False(t, created.UpdatedAt.IsZero())
}

func TestThreatRepo_Create_Duplicate(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.New(pool)
	ctx := context.Background()

	_, err := repo.Create(ctx, newThreat())
	require.NoError(t, err)

	_, err = repo.Create(ctx, newThreat())
	require.Error(t, err)
	require.True(t, errors.Is(err, domain.ErrConflict), "expected ErrConflict, got %v", err)
}

func TestThreatRepo_GetByMD5(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.New(pool)
	ctx := context.Background()

	created, err := repo.Create(ctx, newThreat())
	require.NoError(t, err)

	got, err := repo.GetByMD5(ctx, testMD5)
	require.NoError(t, err)
	require.Equal(t, created.MD5, got.MD5)
	require.Equal(t, created.Name, got.Name)
	require.Equal(t, created.CreatedAt.Unix(), got.CreatedAt.Unix())
}

func TestThreatRepo_GetByMD5_NotFound(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.New(pool)
	ctx := context.Background()

	_, err := repo.GetByMD5(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	require.Error(t, err)
	require.True(t, errors.Is(err, domain.ErrNotFound), "expected ErrNotFound, got %v", err)
}

func TestThreatRepo_Update(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.New(pool)
	ctx := context.Background()

	created, err := repo.Create(ctx, newThreat())
	require.NoError(t, err)
	originalCreatedAt := created.CreatedAt

	time.Sleep(10 * time.Millisecond)

	updated := *created
	updated.Name = "Updated.Name"
	updated.Severity = severityPtr(domain.SeverityCritical)
	updated.Tags = []string{"linux"}
	updated.UpdatedAt = time.Now().UTC()

	got, err := repo.Update(ctx, &updated)
	require.NoError(t, err)
	require.Equal(t, "Updated.Name", got.Name)
	require.NotNil(t, got.Severity)
	require.Equal(t, domain.SeverityCritical, *got.Severity)
	require.ElementsMatch(t, []string{"linux"}, got.Tags)
	require.Equal(t, originalCreatedAt.Unix(), got.CreatedAt.Unix(), "created_at must not change")
	require.True(t, got.UpdatedAt.After(originalCreatedAt))
}

func TestThreatRepo_Update_NotFound(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.New(pool)
	ctx := context.Background()

	threat := newThreat()
	threat.MD5 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	threat.UpdatedAt = time.Now().UTC()

	_, err := repo.Update(ctx, threat)
	require.Error(t, err)
	require.True(t, errors.Is(err, domain.ErrNotFound), "expected ErrNotFound, got %v", err)
}

func TestThreatRepo_Update_FullReplace(t *testing.T) {
	pool := setupDB(t)
	repo := postgres.New(pool)
	ctx := context.Background()

	original := newThreat()
	original.Description = strPtr("original description")
	original.Family = strPtr("OriginalFamily")
	original.Confidence = intPtr(95)
	created, err := repo.Create(ctx, original)
	require.NoError(t, err)

	update := domain.Threat{
		MD5:       created.MD5,
		Name:      "Only.Name",
		Tags:      []string{},
		UpdatedAt: time.Now().UTC(),
	}
	got, err := repo.Update(ctx, &update)
	require.NoError(t, err)
	require.Equal(t, "Only.Name", got.Name)
	require.Nil(t, got.Description)
	require.Nil(t, got.Family)
	require.Nil(t, got.Confidence)
	require.Empty(t, got.Tags)
}

func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }
