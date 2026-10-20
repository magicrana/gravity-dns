package panel

import (
	"strings"
	"testing"
)

func TestGenerateQRCodeSVG(t *testing.T) {
	sampleConf := `[Interface]
PrivateKey = aaaaaa=
Address = 10.66.66.2/32
DNS = 10.66.66.1, 1.1.1.1

[Peer]
PublicKey = bbbbbb=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`
	svgBytes, err := generateQRCodeSVG(sampleConf)
	if err != nil {
		t.Fatalf("generateQRCodeSVG returned error: %v", err)
	}

	svgStr := string(svgBytes)
	if !strings.HasPrefix(svgStr, "<svg") {
		t.Errorf("expected SVG to start with <svg, got: %s", svgStr[:min(len(svgStr), 20)])
	}
	if !strings.Contains(svgStr, `<rect width=`) {
		t.Errorf("expected SVG to contain rect background")
	}
	if !strings.Contains(svgStr, `<path fill="#000000"`) {
		t.Errorf("expected SVG to contain path")
	}
	if !strings.HasSuffix(svgStr, "</svg>") {
		t.Errorf("expected SVG to end with </svg>")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
