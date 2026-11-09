package redis_cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"kaspersky_test/internal/cache"
	"kaspersky_test/internal/domain"
	"time"

	"github.com/redis/go-redis/v9"
)

const threatKeyPrefix = "threat:"

type ThreatCache struct {
	client *redis.Client
	ttl    time.Duration
}

func NewThreatCache(client *redis.Client, ttl time.Duration) *ThreatCache {
	return &ThreatCache{
		client: client,
		ttl:    ttl,
	}
}

func (c *ThreatCache) Get(ctx context.Context, md5 string) (*domain.Threat, error) {
	data, err := c.client.Get(ctx, cacheKey(threatKeyPrefix, md5)).Bytes()

	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("redis get: %w", err)
	}

	var t domain.Threat

	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("unmarshall: %w", err)
	}
	return &t, nil
}

func (c *ThreatCache) Set(ctx context.Context, t *domain.Threat) error {
	data, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return c.client.Set(ctx, cacheKey(threatKeyPrefix, t.MD5), data, c.ttl).Err()
}

func (c *ThreatCache) Delete(ctx context.Context, md5 string) error {
	return c.client.Del(ctx, cacheKey(threatKeyPrefix, md5)).Err()
}

var _ cache.ThreatCache = (*ThreatCache)(nil)
