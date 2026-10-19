package limiter

import (
	"testing"
)

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.0.2.1:53421", "192.0.2.1"},
		{"192.0.2.1", "192.0.2.1"},
		{"[2001:db8::1]:853", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"  203.0.113.10  ", "203.0.113.10"},
	}

	for _, tc := range tests {
		actual := NormalizeIP(tc.input)
		if actual != tc.expected {
			t.Errorf("NormalizeIP(%q) = %q; want %q", tc.input, actual, tc.expected)
		}
	}
}
