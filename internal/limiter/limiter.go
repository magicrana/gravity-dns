package limiter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"gravity-dns/internal/store"
)

var (
	ErrUserRefusedAuth = errors.New("user authentication failed or expired")
	ErrDeviceLimit     = errors.New("device concurrency limit exceeded")
)

// Result indicates the outcome of the authentication and concurrency check.
type Result struct {
	Allowed     bool
	Reason      string
	User        *store.User
	ActiveCount int
}

// Limiter manages sliding-window device limits using Redis Sorted Sets.
type Limiter struct {
	client     *redis.Client
	store      *store.Store
	windowSec  int
	checkScript *redis.Script
}

// New creates a new Limiter instance.
func New(client *redis.Client, st *store.Store, windowSec int) *Limiter {
	if windowSec <= 0 {
		windowSec = 600 // 10 minutes default
	}

	// Redis Lua script for atomic sliding window evaluation:
	// Keys: [1] user:<token>:devices
	// ARGV: [1] now, [2] minScore (now - windowSec), [3] clientIP, [4] maxDevices, [5] keyTTL (3600)
	// Returns: [status (1=allowed, 0=limit exceeded), activeCount]
	luaScript := `
		local devKey = KEYS[1]
		local now = tonumber(ARGV[1])
		local minScore = tonumber(ARGV[2])
		local clientIP = ARGV[3]
		local maxDev = tonumber(ARGV[4])
		local ttl = tonumber(ARGV[5])

		-- 1. Prune entries older than sliding window
		redis.call('ZREMRANGEBYSCORE', devKey, '-inf', '(' .. minScore)

		-- 2. Check if clientIP is already registered in active devices
		local existingScore = redis.call('ZSCORE', devKey, clientIP)

		if existingScore then
			-- IP is already active: refresh its timestamp and extend TTL
			redis.call('ZADD', devKey, now, clientIP)
			redis.call('EXPIRE', devKey, ttl)
			local count = redis.call('ZCARD', devKey)
			return {1, count}
		else
			-- New client IP: check if active device count reaches or exceeds limit
			local currentCount = redis.call('ZCARD', devKey)
			if currentCount >= maxDev then
				-- Refuse: do not record new IP to avoid displacing valid sessions
				return {0, currentCount}
			end

			-- Allowed: record new active device
			redis.call('ZADD', devKey, now, clientIP)
			redis.call('EXPIRE', devKey, ttl)
			return {1, currentCount + 1}
		end
	`

	return &Limiter{
		client:      client,
		store:       st,
		windowSec:   windowSec,
		checkScript: redis.NewScript(luaScript),
	}
}

// NormalizeIP extracts the plain IP from host:port or IP string.
func NormalizeIP(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	// Could be just an IP
	return strings.TrimSpace(addr)
}

// CheckAndRecordQuery validates user status and evaluates sliding window concurrency limit.
func (l *Limiter) CheckAndRecordQuery(ctx context.Context, token, rawClientIP string) (*Result, error) {
	clientIP := NormalizeIP(rawClientIP)
	if clientIP == "" {
		clientIP = "unknown"
	}

	// 1. Fetch user from Store
	u, err := l.store.GetUser(ctx, token)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			return &Result{Allowed: false, Reason: "USER_NOT_FOUND"}, ErrUserRefusedAuth
		}
		return nil, fmt.Errorf("failed to query user in limiter: %w", err)
	}

	// 2. Validate user status and expiration
	if u.Status != "active" {
		return &Result{Allowed: false, Reason: "USER_INACTIVE", User: u}, ErrUserRefusedAuth
	}
	now := time.Now().Unix()
	if u.ExpiresAt > 0 && u.ExpiresAt < now {
		return &Result{Allowed: false, Reason: "USER_EXPIRED", User: u}, ErrUserRefusedAuth
	}

	maxDev := u.MaxDevices
	if maxDev <= 0 {
		maxDev = 2
	}

	// 3. Execute atomic sliding-window script
	devKey := fmt.Sprintf("user:%s:devices", token)
	minScore := now - int64(l.windowSec)
	ttl := 3600 // 1 hour

	res, err := l.checkScript.Run(ctx, l.client, []string{devKey}, now, minScore, clientIP, maxDev, ttl).Result()
	if err != nil {
		// Fallback in case of script error: run standard Redis pipeline
		return l.checkFallback(ctx, token, clientIP, u, now, minScore)
	}

	resSlice, ok := res.([]interface{})
	if !ok || len(resSlice) < 2 {
		return &Result{Allowed: true, User: u}, nil
	}

	allowedVal, _ := resSlice[0].(int64)
	countVal, _ := resSlice[1].(int64)

	if allowedVal == 1 {
		return &Result{
			Allowed:     true,
			User:        u,
			ActiveCount: int(countVal),
		}, nil
	}

	return &Result{
		Allowed:     false,
		Reason:      "DEVICE_LIMIT_EXCEEDED",
		User:        u,
		ActiveCount: int(countVal),
	}, ErrDeviceLimit
}

// checkFallback performs the check using standard Redis calls if Lua execution fails.
func (l *Limiter) checkFallback(ctx context.Context, token, clientIP string, u *store.User, now, minScore int64) (*Result, error) {
	devKey := fmt.Sprintf("user:%s:devices", token)
	maxDev := u.MaxDevices

	_ = l.client.ZRemRangeByScore(ctx, devKey, "-inf", fmt.Sprintf("(%d", minScore)).Err()

	// Check if already active
	score, err := l.client.ZScore(ctx, devKey, clientIP).Result()
	if err == nil && score > 0 {
		// Existing device
		l.client.ZAdd(ctx, devKey, redis.Z{Score: float64(now), Member: clientIP})
		l.client.Expire(ctx, devKey, time.Hour)
		cnt, _ := l.client.ZCard(ctx, devKey).Result()
		return &Result{Allowed: true, User: u, ActiveCount: int(cnt)}, nil
	}

	// New device
	cnt, _ := l.client.ZCard(ctx, devKey).Result()
	if int(cnt) >= maxDev {
		return &Result{Allowed: false, Reason: "DEVICE_LIMIT_EXCEEDED", User: u, ActiveCount: int(cnt)}, ErrDeviceLimit
	}

	l.client.ZAdd(ctx, devKey, redis.Z{Score: float64(now), Member: clientIP})
	l.client.Expire(ctx, devKey, time.Hour)
	return &Result{Allowed: true, User: u, ActiveCount: int(cnt) + 1}, nil
}
