package panel

import (
	"strings"
	"testing"
	"time"
)

func TestSanitizePeerName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"my_peer-1", "my_peer-1"},
		{"peer with spaces!", "peerwithspaces"},
		{"user@example.com", "userexamplecom"},
		{"sip$phone#1", "sipphone1"},
	}

	for _, tc := range tests {
		got := sanitizePeerName(tc.input)
		if got != tc.expected {
			t.Errorf("sanitizePeerName(%q) = %q; want %q", tc.input, got, tc.expected)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	if got := formatBytes(500); got != "500 B" {
		t.Errorf("expected 500 B, got %s", got)
	}
	if got := formatBytes(1024); got != "1.0 KB" {
		t.Errorf("expected 1.0 KB, got %s", got)
	}
	if got := formatBytes(1048576 * 5); got != "5.0 MB" {
		t.Errorf("expected 5.0 MB, got %s", got)
	}
}

func TestFormatTimeAgo(t *testing.T) {
	if got := formatTimeAgo(0); got != "Never" {
		t.Errorf("expected Never, got %s", got)
	}
	now := time.Now().Unix()
	if got := formatTimeAgo(now - 10); !strings.Contains(got, "seconds ago") {
		t.Errorf("expected seconds ago, got %s", got)
	}
	if got := formatTimeAgo(now - 120); !strings.Contains(got, "mins ago") {
		t.Errorf("expected mins ago, got %s", got)
	}
}
