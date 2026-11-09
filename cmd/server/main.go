// Command server starts the threat information exchange REST service.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kaspersky_test/internal/api"
	"kaspersky_test/internal/cache/redis_cache"
	"kaspersky_test/internal/config"
	"kaspersky_test/internal/repository/postgres"
	"kaspersky_test/internal/service"
	"kaspersky_test/migrations"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/redis/go-redis/v9"
)

// main is the process entry point.
func main() {
	if err := run(); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

// run loads configuration, initializes dependencies and serves HTTP until shutdown.
func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("create pool: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}

	if cfg.RunMigrations {
		if err := runMigrations(ctx, pool); err != nil {
			return fmt.Errorf("run migrations: %w", err)
		}
	}

	repo := postgres.New(pool)

	var threatCache redis_cache.ThreatCache
	var redisClient *redis.Client

	if cfg.RedisURL != "" {
		opts, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			return fmt.Errorf("parse redis url: %w", err)
		}

		redisClient = redis.NewClient(opts)
		defer redisClient.Close()
		if err := redisClient.Ping(ctx).Err(); err != nil {
			return fmt.Errorf("redis ping: %w", err)
		}
		threatCache = *redis_cache.NewThreatCache(redisClient, cfg.CacheTTL)
		slog.Info("redis cache enabled", "ttl", cfg.CacheTTL)
	} else {
		slog.Info("redis cache disabled (REDIS_URL is empty)")
	}

	svc := service.New(repo, &threatCache)
	handler := api.NewHandler(svc)

	var cachePinger api.Pinger
	if redisClient != nil {
		cachePinger = redis_cache.NewPingerAdapter(redisClient)
	}

	health := api.NewHealthHandler(pool, cachePinger)
	router := api.NewRouter(
		handler,
		health,
		log,
		cfg.RateLimitRPS,
		cfg.RateLimitBurst,
		cfg.APIKey,
	)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("http server listening", "addr", cfg.HTTPAddr, "tls", cfg.TLSEnabled())

		var err error
		if cfg.TLSEnabled() {
			err = srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeOut)

		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// runMigrations applies the embedded goose migrations to the database.
func runMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.UpContext(ctx, db, ".")
}
