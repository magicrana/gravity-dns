package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"gravity-dns/internal/config"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrUserExists      = errors.New("user token already exists")
	ErrInvalidPassword = errors.New("invalid credentials")
)

// Store encapsulates Redis interactions.
type Store struct {
	client    *redis.Client
	startTime time.Time
}

// New creates and connects a new Redis Store instance.
func New(cfg *config.RedisConfig) (*Store, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		PoolSize:     100,
		MinIdleConns: 10,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed to %s: %w", cfg.Addr, err)
	}

	return &Store{
		client:    client,
		startTime: time.Now(),
	}, nil
}

// Client returns the raw redis.Client.
func (s *Store) Client() *redis.Client {
	return s.client
}

// Close gracefully closes the Redis connection.
func (s *Store) Close() error {
	return s.client.Close()
}

// ==================== USER MANAGEMENT ====================

// CreateUser persists a new user account.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	if u.Token == "" {
		return errors.New("token cannot be empty")
	}
	if u.Username == "" {
		u.Username = u.Token
	}
	if u.Status == "" {
		u.Status = "active"
	}
	if u.MaxDevices <= 0 {
		u.MaxDevices = 2
	}
	if u.CreatedAt == 0 {
		u.CreatedAt = time.Now().Unix()
	}

	exists, err := s.client.SIsMember(ctx, "users:all", u.Token).Result()
	if err != nil {
		return err
	}
	if exists {
		return ErrUserExists
	}

	pipe := s.client.Pipeline()
	pipe.SAdd(ctx, "users:all", u.Token)
	userKey := fmt.Sprintf("user:%s", u.Token)
	pipe.HSet(ctx, userKey, map[string]interface{}{
		"token":       u.Token,
		"username":    u.Username,
		"status":      u.Status,
		"max_devices": u.MaxDevices,
		"expires_at":  u.ExpiresAt,
		"created_at":  u.CreatedAt,
		"notes":       u.Notes,
	})

	_, err = pipe.Exec(ctx)
	return err
}

// GetUser retrieves a user by token.
func (s *Store) GetUser(ctx context.Context, token string) (*User, error) {
	userKey := fmt.Sprintf("user:%s", token)
	vals, err := s.client.HGetAll(ctx, userKey).Result()
	if err != nil {
		return nil, err
	}
	if len(vals) == 0 {
		return nil, ErrUserNotFound
	}

	maxDev, _ := strconv.Atoi(vals["max_devices"])
	if maxDev <= 0 {
		maxDev = 2
	}
	expAt, _ := strconv.ParseInt(vals["expires_at"], 10, 64)
	creatAt, _ := strconv.ParseInt(vals["created_at"], 10, 64)

	return &User{
		Token:      vals["token"],
		Username:   vals["username"],
		Status:     vals["status"],
		MaxDevices: maxDev,
		ExpiresAt:  expAt,
		CreatedAt:  creatAt,
		Notes:      vals["notes"],
	}, nil
}

// UpdateUser modifies an existing user.
func (s *Store) UpdateUser(ctx context.Context, u *User) error {
	userKey := fmt.Sprintf("user:%s", u.Token)
	exists, err := s.client.Exists(ctx, userKey).Result()
	if err != nil {
		return err
	}
	if exists == 0 {
		return ErrUserNotFound
	}

	fields := map[string]interface{}{
		"username":    u.Username,
		"status":      u.Status,
		"max_devices": u.MaxDevices,
		"expires_at":  u.ExpiresAt,
		"notes":       u.Notes,
	}
	return s.client.HSet(ctx, userKey, fields).Err()
}

// DeleteUser removes a user and flushes their active sessions.
func (s *Store) DeleteUser(ctx context.Context, token string) error {
	userKey := fmt.Sprintf("user:%s", token)
	devicesKey := fmt.Sprintf("user:%s:devices", token)

	pipe := s.client.Pipeline()
	pipe.SRem(ctx, "users:all", token)
	pipe.Del(ctx, userKey)
	pipe.Del(ctx, devicesKey)
	_, err := pipe.Exec(ctx)
	return err
}

// ListUsers returns all users along with their currently active device count.
func (s *Store) ListUsers(ctx context.Context, windowSec int) ([]User, error) {
	tokens, err := s.client.SMembers(ctx, "users:all").Result()
	if err != nil {
		return nil, err
	}

	users := make([]User, 0, len(tokens))
	now := time.Now().Unix()
	minScore := strconv.FormatInt(now-int64(windowSec), 10)

	for _, token := range tokens {
		u, err := s.GetUser(ctx, token)
		if err != nil {
			continue
		}

		// Count active devices in current window
		devKey := fmt.Sprintf("user:%s:devices", token)
		count, err := s.client.ZCount(ctx, devKey, minScore, "+inf").Result()
		if err == nil {
			u.ActiveDevices = int(count)
		}

		users = append(users, *u)
	}

	return users, nil
}

// ==================== DEVICE SESSIONS ====================

// GetActiveDevices returns the list of active IP addresses and when they were last seen.
func (s *Store) GetActiveDevices(ctx context.Context, token string, windowSec int) ([]DeviceSession, error) {
	devKey := fmt.Sprintf("user:%s:devices", token)
	now := time.Now().Unix()
	minScore := strconv.FormatInt(now-int64(windowSec), 10)

	// Prune old entries first
	_ = s.client.ZRemRangeByScore(ctx, devKey, "0", fmt.Sprintf("(%d", now-int64(windowSec))).Err()

	// Fetch active IPs with their scores (timestamps)
	zEntries, err := s.client.ZRevRangeByScoreWithScores(ctx, devKey, &redis.ZRangeBy{
		Min: minScore,
		Max: "+inf",
	}).Result()
	if err != nil {
		return nil, err
	}

	sessions := make([]DeviceSession, 0, len(zEntries))
	for _, entry := range zEntries {
		ip, ok := entry.Member.(string)
		if !ok {
			continue
		}
		lastSeen := int64(entry.Score)
		elapsed := now - lastSeen
		remaining := int64(windowSec) - elapsed
		if remaining < 0 {
			remaining = 0
		}

		sessions = append(sessions, DeviceSession{
			IP:           ip,
			LastSeen:     lastSeen,
			SecondsAgo:   elapsed,
			RemainingSec: remaining,
		})
	}

	return sessions, nil
}

// KillUserSessions wipes all active device records for a token.
func (s *Store) KillUserSessions(ctx context.Context, token string) error {
	devKey := fmt.Sprintf("user:%s:devices", token)
	return s.client.Del(ctx, devKey).Err()
}

// ==================== DOMAIN HIJACK RULES ====================

// AddRule adds or updates a domain hijacking rule.
func (s *Store) AddRule(ctx context.Context, r Rule) error {
	domain := strings.ToLower(strings.TrimSpace(r.Domain))
	if domain == "" {
		return errors.New("domain cannot be empty")
	}

	ruleKey := fmt.Sprintf("rule:%s", domain)
	now := time.Now().Unix()
	if r.CreatedAt == 0 {
		r.CreatedAt = now
	}

	pipe := s.client.Pipeline()
	pipe.SAdd(ctx, "rules:all", domain)
	pipe.HSet(ctx, ruleKey, map[string]interface{}{
		"domain":     domain,
		"category":   r.Category,
		"enabled":    r.Enabled,
		"created_at": r.CreatedAt,
	})
	_, err := pipe.Exec(ctx)
	return err
}

// DeleteRule deletes a domain rule.
func (s *Store) DeleteRule(ctx context.Context, domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	ruleKey := fmt.Sprintf("rule:%s", domain)

	pipe := s.client.Pipeline()
	pipe.SRem(ctx, "rules:all", domain)
	pipe.Del(ctx, ruleKey)
	_, err := pipe.Exec(ctx)
	return err
}

// ToggleRule toggles a rule's enabled status.
func (s *Store) ToggleRule(ctx context.Context, domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	ruleKey := fmt.Sprintf("rule:%s", domain)

	val, err := s.client.HGet(ctx, ruleKey, "enabled").Result()
	if err != nil {
		return err
	}

	newStatus := !(val == "1" || val == "true")
	return s.client.HSet(ctx, ruleKey, "enabled", newStatus).Err()
}

// ListRules retrieves all configured rules.
func (s *Store) ListRules(ctx context.Context) ([]Rule, error) {
	domains, err := s.client.SMembers(ctx, "rules:all").Result()
	if err != nil {
		return nil, err
	}

	rules := make([]Rule, 0, len(domains))
	for _, d := range domains {
		ruleKey := fmt.Sprintf("rule:%s", d)
		data, err := s.client.HGetAll(ctx, ruleKey).Result()
		if err != nil || len(data) == 0 {
			continue
		}

		enabled := data["enabled"] == "1" || data["enabled"] == "true"
		createdAt, _ := strconv.ParseInt(data["created_at"], 10, 64)

		rules = append(rules, Rule{
			Domain:    data["domain"],
			Category:  data["category"],
			Enabled:   enabled,
			CreatedAt: createdAt,
		})
	}

	return rules, nil
}

// GetActiveRuleDomains returns only enabled domain patterns for fast matching.
func (s *Store) GetActiveRuleDomains(ctx context.Context) ([]string, error) {
	rules, err := s.ListRules(ctx)
	if err != nil {
		return nil, err
	}

	active := make([]string, 0, len(rules))
	for _, r := range rules {
		if r.Enabled {
			active = append(active, r.Domain)
		}
	}
	return active, nil
}

// SeedPresetRules seeds standard streaming service domains if the rules table is empty.
func (s *Store) SeedPresetRules(ctx context.Context) error {
	count, err := s.client.SCard(ctx, "rules:all").Result()
	if err != nil {
		return err
	}
	if count > 0 {
		return nil // Already seeded
	}

	presets := GetDefaultStreamingPresets()
	for _, p := range presets {
		for _, domain := range p.Domains {
			_ = s.AddRule(ctx, Rule{
				Domain:    domain,
				Category:  p.Name,
				Enabled:   true,
				CreatedAt: time.Now().Unix(),
			})
		}
	}
	return nil
}

// StreamingPreset defines a grouping of streaming domains.
type StreamingPreset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Domains     []string `json:"domains"`
}

// GetDefaultStreamingPresets returns popular geo-restricted media services.
func GetDefaultStreamingPresets() []StreamingPreset {
	return []StreamingPreset{
		{
			ID:          "netflix",
			Name:        "Netflix (US/Global)",
			Description: "Main web, catalog, and streaming endpoints",
			Domains: []string{
				"netflix.com",
				"*.netflix.com",
				"*.nflxvideo.net",
				"*.nflximg.net",
				"*.nflxext.com",
				"*.nflxso.net",
			},
		},
		{
			ID:          "hulu",
			Name:        "Hulu (US)",
			Description: "Hulu streaming and asset servers",
			Domains: []string{
				"hulu.com",
				"*.hulu.com",
				"*.huluim.com",
				"*.hulustream.com",
			},
		},
		{
			ID:          "disneyplus",
			Name:        "Disney+ (Global)",
			Description: "Disney+ and BAMTECH media delivery networks",
			Domains: []string{
				"disneyplus.com",
				"*.disneyplus.com",
				"*.bamgrid.com",
				"*.disney-plus.net",
				"*.dssott.com",
			},
		},
		{
			ID:          "primevideo",
			Name:        "Amazon Prime Video",
			Description: "Prime Video playback and auth endpoints",
			Domains: []string{
				"primevideo.com",
				"*.primevideo.com",
				"*.amazonvideo.com",
				"*.aiv-cdn.net",
			},
		},
		{
			ID:          "max",
			Name:        "Max (HBO Max)",
			Description: "Warner Bros. Discovery streaming network",
			Domains: []string{
				"max.com",
				"*.max.com",
				"*.hbo.com",
				"*.hbomax.com",
				"*.discomax.com",
			},
		},
		{
			ID:          "peacock",
			Name:        "Peacock TV",
			Description: "NBCUniversal Peacock streaming platform",
			Domains: []string{
				"peacocktv.com",
				"*.peacocktv.com",
			},
		},
		{
			ID:          "paramount",
			Name:        "Paramount+",
			Description: "Paramount and CBS Interactive streaming services",
			Domains: []string{
				"paramountplus.com",
				"*.paramountplus.com",
				"*.cbs.com",
				"*.cbsaavideo.com",
			},
		},
		{
			ID:          "bbc",
			Name:        "BBC iPlayer (UK)",
			Description: "British Broadcasting Corporation UK playback",
			Domains: []string{
				"bbc.co.uk",
				"*.bbc.co.uk",
				"*.bbci.co.uk",
				"*.bbc.com",
			},
		},
		{
			ID:          "crunchyroll",
			Name:        "Crunchyroll",
			Description: "Anime streaming network",
			Domains: []string{
				"crunchyroll.com",
				"*.crunchyroll.com",
				"*.vrv.co",
			},
		},
		{
			ID:          "toffee",
			Name:        "Toffee (Banglalink Live TV & Sports)",
			Description: "Top Bangladeshi live sports, cricket and TV streaming",
			Domains: []string{
				"toffeelive.com",
				"*.toffeelive.com",
			},
		},
		{
			ID:          "chorki",
			Name:        "Chorki (BD Movies & Series)",
			Description: "Bangladeshi premium OTT content and originals",
			Domains: []string{
				"chorki.com",
				"*.chorki.com",
			},
		},
		{
			ID:          "hoichoi",
			Name:        "Hoichoi (BD Catalog)",
			Description: "Bengali movies, web series, and exclusive BD catalog",
			Domains: []string{
				"hoichoi.tv",
				"*.hoichoi.tv",
			},
		},
		{
			ID:          "bioscope-bongo",
			Name:        "Bioscope & Bongo BD",
			Description: "Grameenphone Bioscope and Bongo entertainment portals",
			Domains: []string{
				"bioscopelive.com",
				"*.bioscopelive.com",
				"bongobd.com",
				"*.bongobd.com",
			},
		},
		{
			ID:          "bd-sports-tv",
			Name:        "T Sports, Rabbithole & JagoBD",
			Description: "Live Bangladesh cricket matches, T Sports & Live TV channels",
			Domains: []string{
				"rabbitholebd.com",
				"*.rabbitholebd.com",
				"tsports.com",
				"*.tsports.com",
				"jagobd.com",
				"*.jagobd.com",
			},
		},
	}
}

// ==================== STATS & LOGGING ====================

// RecordQuery updates system query statistics and records recent logs.
func (s *Store) RecordQuery(ctx context.Context, entry QueryLogEntry) {
	pipe := s.client.Pipeline()
	pipe.Incr(ctx, "stats:queries:total")
	switch entry.Action {
	case "HIJACKED":
		pipe.Incr(ctx, "stats:queries:hijacked")
	case "FORWARDED":
		pipe.Incr(ctx, "stats:queries:forwarded")
	default:
		pipe.Incr(ctx, "stats:queries:refused")
	}

	if data, err := json.Marshal(entry); err == nil {
		pipe.LPush(ctx, "queries:recent", data)
		pipe.LTrim(ctx, "queries:recent", 0, 99) // Keep last 100 queries
	}
	_, _ = pipe.Exec(ctx)
}

// GetRecentQueryLogs retrieves the latest recorded DNS queries.
func (s *Store) GetRecentQueryLogs(ctx context.Context, limit int64) ([]QueryLogEntry, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	items, err := s.client.LRange(ctx, "queries:recent", 0, limit-1).Result()
	if err != nil {
		return nil, err
	}

	entries := make([]QueryLogEntry, 0, len(items))
	for _, item := range items {
		var entry QueryLogEntry
		if err := json.Unmarshal([]byte(item), &entry); err == nil {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// GetStats returns aggregated platform statistics.
func (s *Store) GetStats(ctx context.Context, windowSec int) (*Stats, error) {
	pipe := s.client.Pipeline()
	totQ := pipe.Get(ctx, "stats:queries:total")
	hijQ := pipe.Get(ctx, "stats:queries:hijacked")
	fwdQ := pipe.Get(ctx, "stats:queries:forwarded")
	refQ := pipe.Get(ctx, "stats:queries:refused")
	uCount := pipe.SCard(ctx, "users:all")
	rCount := pipe.SCard(ctx, "rules:all")
	_, _ = pipe.Exec(ctx)

	parseCmd := func(cmd *redis.StringCmd) int64 {
		val, err := cmd.Int64()
		if err != nil {
			return 0
		}
		return val
	}

	// Calculate active devices across all users
	tokens, _ := s.client.SMembers(ctx, "users:all").Result()
	now := time.Now().Unix()
	minScore := strconv.FormatInt(now-int64(windowSec), 10)
	var activeDevices int64
	var activeUsers int64

	for _, token := range tokens {
		devKey := fmt.Sprintf("user:%s:devices", token)
		cnt, err := s.client.ZCount(ctx, devKey, minScore, "+inf").Result()
		if err == nil && cnt > 0 {
			activeDevices += cnt
			activeUsers++
		}
	}

	return &Stats{
		TotalQueries:     parseCmd(totQ),
		HijackedQueries:  parseCmd(hijQ),
		ForwardedQueries: parseCmd(fwdQ),
		RefusedQueries:   parseCmd(refQ),
		TotalUsers:       uCount.Val(),
		ActiveUsers:      activeUsers,
		ActiveDevices:    activeDevices,
		TotalRules:       rCount.Val(),
		UptimeSeconds:    int64(time.Since(s.startTime).Seconds()),
	}, nil
}

// ==================== ADMIN AUTHENTICATION ====================

// EnsureAdminUser verifies or creates the default admin user account.
func (s *Store) EnsureAdminUser(ctx context.Context, username, password string) error {
	adminKey := fmt.Sprintf("admin:user:%s", username)
	exists, err := s.client.Exists(ctx, adminKey).Result()
	if err != nil {
		return err
	}
	if exists == 0 {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		return s.client.HSet(ctx, adminKey, map[string]interface{}{
			"username":      username,
			"password_hash": string(hash),
			"created_at":    time.Now().Unix(),
		}).Err()
	}
	return nil
}

// AuthenticateAdmin validates admin credentials.
func (s *Store) AuthenticateAdmin(ctx context.Context, username, password string) error {
	adminKey := fmt.Sprintf("admin:user:%s", username)
	hash, err := s.client.HGet(ctx, adminKey, "password_hash").Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrInvalidPassword
		}
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return ErrInvalidPassword
	}

	// Update last login
	_ = s.client.HSet(ctx, adminKey, "last_login", time.Now().Unix()).Err()
	return nil
}

// UpdateAdminPassword updates password for an admin.
func (s *Store) UpdateAdminPassword(ctx context.Context, username, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	adminKey := fmt.Sprintf("admin:user:%s", username)
	return s.client.HSet(ctx, adminKey, "password_hash", string(hash)).Err()
}

// ResetAdminPassword forcibly initializes or updates admin credentials in Redis.
func (s *Store) ResetAdminPassword(ctx context.Context, username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	adminKey := fmt.Sprintf("admin:user:%s", username)
	return s.client.HSet(ctx, adminKey, map[string]interface{}{
		"username":      username,
		"password_hash": string(hash),
		"updated_at":    time.Now().Unix(),
	}).Err()
}

// UpdateAdminProfile changes admin username, password, or both after verifying old credentials.
func (s *Store) UpdateAdminProfile(ctx context.Context, oldUsername, newUsername, oldPassword, newPassword string) error {
	if err := s.AuthenticateAdmin(ctx, oldUsername, oldPassword); err != nil {
		return err
	}

	oldKey := fmt.Sprintf("admin:user:%s", oldUsername)
	newKey := fmt.Sprintf("admin:user:%s", newUsername)

	hashToSave := ""
	if newPassword != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		hashToSave = string(h)
	} else {
		// Retain existing password hash
		h, err := s.client.HGet(ctx, oldKey, "password_hash").Result()
		if err != nil {
			return err
		}
		hashToSave = h
	}

	if oldUsername != newUsername {
		// Migrate to new username
		pipe := s.client.Pipeline()
		pipe.HSet(ctx, newKey, map[string]interface{}{
			"username":      newUsername,
			"password_hash": hashToSave,
			"created_at":    time.Now().Unix(),
			"last_login":    time.Now().Unix(),
		})
		pipe.Del(ctx, oldKey)
		_, err := pipe.Exec(ctx)
		return err
	}

	// Username unchanged, only update password
	return s.client.HSet(ctx, oldKey, "password_hash", hashToSave).Err()
}

// HasAdminUsers checks if at least one admin account exists.
func (s *Store) HasAdminUsers(ctx context.Context) (bool, error) {
	keys, err := s.client.Keys(ctx, "admin:user:*").Result()
	if err != nil {
		return false, err
	}
	return len(keys) > 0, nil
}

// ==================== REDIS SERVER MANAGEMENT ====================

// GetRedisInfo retrieves operational metrics from the active Redis server.
func (s *Store) GetRedisInfo(ctx context.Context) (map[string]interface{}, error) {
	start := time.Now()
	pingErr := s.client.Ping(ctx).Err()
	latencyMs := float64(time.Since(start).Microseconds()) / 1000.0

	infoMap := map[string]interface{}{
		"status":      "online",
		"latency_ms":  latencyMs,
		"ping_ok":     pingErr == nil,
		"version":     "unknown",
		"used_memory": "unknown",
		"clients":     0,
		"uptime_days": 0,
		"total_keys":  0,
	}

	if pingErr != nil {
		infoMap["status"] = "offline"
		infoMap["error"] = pingErr.Error()
		return infoMap, nil
	}

	// Parse Redis INFO
	infoStr, err := s.client.Info(ctx).Result()
	if err == nil {
		lines := strings.Split(infoStr, "\r\n")
		for _, line := range lines {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				k := strings.TrimSpace(parts[0])
				v := strings.TrimSpace(parts[1])
				switch k {
				case "redis_version":
					infoMap["version"] = v
				case "used_memory_human":
					infoMap["used_memory"] = v
				case "connected_clients":
					c, _ := strconv.Atoi(v)
					infoMap["clients"] = c
				case "uptime_in_days":
					d, _ := strconv.Atoi(v)
					infoMap["uptime_days"] = d
				}
			}
		}
	}

	// DB Key Count
	if dbSize, err := s.client.DBSize(ctx).Result(); err == nil {
		infoMap["total_keys"] = dbSize
	}

	return infoMap, nil
}

// Reconnect swaps the underlying Redis connection to new parameters.
func (s *Store) Reconnect(cfg *config.RedisConfig) error {
	newClient := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		PoolSize:     100,
		MinIdleConns: 10,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := newClient.Ping(ctx).Err(); err != nil {
		_ = newClient.Close()
		return fmt.Errorf("failed to connect to Redis at %s: %w", cfg.Addr, err)
	}

	oldClient := s.client
	s.client = newClient
	if oldClient != nil {
		_ = oldClient.Close()
	}

	return nil
}

// FlushAllSessions deletes all sliding-window active device keys.
func (s *Store) FlushAllSessions(ctx context.Context) (int64, error) {
	keys, err := s.client.Keys(ctx, "user:*:devices").Result()
	if err != nil || len(keys) == 0 {
		return 0, err
	}
	return s.client.Del(ctx, keys...).Result()
}
