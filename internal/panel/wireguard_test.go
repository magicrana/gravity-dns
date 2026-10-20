package panel

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
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

func TestComputeCurve25519PubKey(t *testing.T) {
	privBytes, err := base64.StdEncoding.DecodeString("qAiOIKO03rLAfV4s43i67e6f8ioGJCK9VL4E1IQogWA=")
	if err != nil {
		t.Fatal(err)
	}
	var privKey, pubKey [32]byte
	copy(privKey[:], privBytes)
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64
	curve25519.ScalarBaseMult(&pubKey, &privKey)
	expectedPub := "idcg0KhWMYe9PIEkc4yHbV85t4rIBe3MQSNDTs2GMQE="
	gotPub := base64.StdEncoding.EncodeToString(pubKey[:])
	if gotPub != expectedPub {
		t.Errorf("got %s, want %s", gotPub, expectedPub)
	}
}
