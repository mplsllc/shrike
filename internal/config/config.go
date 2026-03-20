package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	DatabaseURL string

	Host string
	Port int

	CrawlerWorkers        int
	CrawlerDefaultInterval time.Duration

	CacheSize int
	CacheTTL  time.Duration

	RateLimitAnonymous   int
	RateLimitFree        int
	RateLimitContributor int

	ExportDir string
}

func Load() (*Config, error) {
	cfg := &Config{
		DatabaseURL: getEnv("DATABASE_URL", "postgres://shrike:shrike@localhost:5432/shrike?sslmode=disable"),

		Host: getEnv("SHRIKE_HOST", "127.0.0.1"),
		Port: getEnvInt("SHRIKE_PORT", 8043),

		CrawlerWorkers:        getEnvInt("SHRIKE_CRAWLER_WORKERS", 10),
		CrawlerDefaultInterval: getEnvDuration("SHRIKE_CRAWLER_DEFAULT_INTERVAL", 30*24*time.Hour),

		CacheSize: getEnvInt("SHRIKE_CACHE_SIZE", 100000),
		CacheTTL:  getEnvDuration("SHRIKE_CACHE_TTL", 15*time.Minute),

		RateLimitAnonymous:   getEnvInt("SHRIKE_RATE_LIMIT_ANONYMOUS", 5),
		RateLimitFree:        getEnvInt("SHRIKE_RATE_LIMIT_FREE", 15),
		RateLimitContributor: getEnvInt("SHRIKE_RATE_LIMIT_CONTRIBUTOR", 30),

		ExportDir: getEnv("SHRIKE_EXPORT_DIR", "./exports"),
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	return cfg, nil
}

func (c *Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
