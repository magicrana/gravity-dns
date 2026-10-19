package store

import "time"

// User represents a client account authenticated via token.
type User struct {
	Token         string `json:"token"`
	Username      string `json:"username"`
	Status        string `json:"status"` // "active" or "disabled"
	MaxDevices    int    `json:"max_devices"`
	ExpiresAt     int64  `json:"expires_at"` // 0 = never
	CreatedAt     int64  `json:"created_at"`
	Notes         string `json:"notes"`
	ActiveDevices int    `json:"active_devices,omitempty"`
}

// IsActive checks if the user is enabled and not expired.
func (u *User) IsActive() bool {
	if u.Status != "active" {
		return false
	}
	if u.ExpiresAt > 0 && u.ExpiresAt < time.Now().Unix() {
		return false
	}
	return true
}

// DeviceSession represents an active client IP under a user's sliding window.
type DeviceSession struct {
	IP             string `json:"ip"`
	LastSeen       int64  `json:"last_seen"`
	SecondsAgo     int64  `json:"seconds_ago"`
	RemainingSec   int64  `json:"remaining_sec"`
	GeoCountry     string `json:"geo_country,omitempty"`
	GeoISP         string `json:"geo_isp,omitempty"`
}

// Rule represents a selective DNS hijacking domain rule.
type Rule struct {
	Domain    string `json:"domain"`   // e.g. "*.netflix.com" or "hulu.com"
	Category  string `json:"category"` // e.g. "Netflix", "Hulu", "Disney+"
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
}

// Stats represents high level system metrics.
type Stats struct {
	TotalQueries     int64 `json:"total_queries"`
	HijackedQueries  int64 `json:"hijacked_queries"`
	ForwardedQueries int64 `json:"forwarded_queries"`
	RefusedQueries   int64 `json:"refused_queries"`
	TotalUsers       int64 `json:"total_users"`
	ActiveUsers      int64 `json:"active_users"`
	ActiveDevices    int64 `json:"active_devices"`
	TotalRules       int64 `json:"total_rules"`
	UptimeSeconds    int64 `json:"uptime_seconds"`
}

// QueryLogEntry represents a recorded DNS resolution event for the live stream.
type QueryLogEntry struct {
	Timestamp int64  `json:"timestamp"`
	Token     string `json:"token"`
	Username  string `json:"username,omitempty"`
	ClientIP  string `json:"client_ip"`
	Domain    string `json:"domain"`
	QType     string `json:"qtype"`
	Action    string `json:"action"` // "HIJACKED", "FORWARDED", "REFUSED_AUTH", "REFUSED_LIMIT"
	Protocol  string `json:"protocol"` // "DoT" or "DoH"
}
