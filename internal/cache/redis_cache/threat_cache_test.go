package redis_cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"kaspersky_test/internal/domain"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestThreatCache_GetSet(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, c *ThreatCache)
		md5      string
		wantName string
		wantErr  error
	}{
		{
			name: "hit after set",
			setup: func(t *testing.T, c *ThreatCache) {
				t.Helper()
				if err := c.Set(context.Background(), &domain.Threat{MD5: "test", Name: "Trojan"}); err != nil {
					t.Fatalf("seed set: %v", err)
				}
			},
			md5:      "test",
			wantName: "Trojan",
		},
		{
			name:    "miss on empty cache",
			setup:   func(*testing.T, *ThreatCache) {},
			md5:     "nonexistent",
			wantErr: domain.ErrNotFound,
		},
		{
			name: "miss after delete",
			setup: func(t *testing.T, c *ThreatCache) {
				t.Helper()
				ctx := context.Background()
				if err := c.Set(ctx, &domain.Threat{MD5: "test", Name: "Trojan"}); err != nil {
					t.Fatalf("seed set: %v", err)
				}
				if err := c.Delete(ctx, "test"); err != nil {
					t.Fatalf("delete: %v", err)
				}
			},
			md5:     "test",
			wantErr: domain.ErrNotFound,
		},
		{
			name: "overwrite existing",
			setup: func(t *testing.T, c *ThreatCache) {
				t.Helper()
				ctx := context.Background()
				if err := c.Set(ctx, &domain.Threat{MD5: "test", Name: "Old"}); err != nil {
					t.Fatalf("seed set: %v", err)
				}
				if err := c.Set(ctx, &domain.Threat{MD5: "test", Name: "New"}); err != nil {
					t.Fatalf("overwrite: %v", err)
				}
			},
			md5:      "test",
			wantName: "New",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mr := miniredis.RunT(t)
			rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			defer rdb.Close()

			cache := NewThreatCache(rdb, 5*time.Minute)
			tc.setup(t, cache)

			got, err := cache.Get(context.Background(), tc.md5)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("got = %+v, want nil", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("got nil, want threat")
			}
			if got.Name != tc.wantName {
				t.Fatalf("name = %q, want %q", got.Name, tc.wantName)
			}
		})
	}
}

func TestThreatCache_TTL(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	const ttl = 5 * time.Minute
	cache := NewThreatCache(rdb, ttl)
	ctx := context.Background()

	if err := cache.Set(ctx, &domain.Threat{MD5: "test", Name: "Trojan"}); err != nil {
		t.Fatalf("set: %v", err)
	}

	if _, err := cache.Get(ctx, "test"); err != nil {
		t.Fatalf("before expiry: %v", err)
	}

	mr.FastForward(ttl + time.Second)

	_, err := cache.Get(ctx, "test")
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("after expiry: err = %v, want ErrNotFound", err)
	}
}
