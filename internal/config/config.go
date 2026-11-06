package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr      string
	DatabaseURL   string
	RunMigrations bool
	LogLevel      slog.Level

	RateLimitRPS   float64
	RateLimitBurst int

	APIKey string

	TLSCertFile string
	TLSKeyFile  string

	ShutdownTimeOut time.Duration
}

func Load() (*Config, error) {
	cfg := &Config{
		HTTPAddr:        envOr("HTTP_ADDR", ":8080"),
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		RunMigrations:   envBool("RUN_MIGRATIONS", true),
		LogLevel:        parseLogLevel(envOr("LOG_LEVEL", "info")),
		RateLimitRPS:    envFloat("RATE_LIMIT_RPS", 10),
		RateLimitBurst:  envInt("RATE_LIMIT_BURST", 20),
		APIKey:          os.Getenv("API_KEY"),
		TLSCertFile:     os.Getenv("TLS_СERT_FILE"),
		TLSKeyFile:      os.Getenv("TLS_KEY_FILE"),
		ShutdownTimeOut: 10 * time.Second,
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}
	if c.RateLimitRPS <= 0 {
		return fmt.Errorf("RATE_LIMIT_RPS must be > 0")
	}
	if c.RateLimitBurst <= 0 {
		return fmt.Errorf("RATE_LIMIT_BURST must be > 0")
	}
	return nil
}

func (c *Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}

	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}

	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}

	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
