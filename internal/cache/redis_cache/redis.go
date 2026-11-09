package redis_cache

import (
	"context"

	"github.com/redis/go-redis/v9"
)

func cacheKey(prefix, id string) string {
	return prefix + id
}

type Client struct {
	rdb *redis.Client
}

func NewClient(rdb *redis.Client) *Client {
	return &Client{rdb: rdb}
}

type PingerAdapter struct {
	client *redis.Client
}

func NewPingerAdapter(client *redis.Client) *PingerAdapter {
	return &PingerAdapter{client: client}
}

func (p *PingerAdapter) Ping(ctx context.Context) error {
	return p.client.Ping(ctx).Err()
}
