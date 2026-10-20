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

func TestPatchMissingServerPubKey(t *testing.T) {
	userReportedConf := `[Interface]
PrivateKey = iBwS5SzaQDSXnHmkq2Qar3tfb5EXlFoF+JbGmPwj5G4=
Address = 10.66.66.2/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = 
Endpoint = 103.42.5.144:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`
	serverPub := "D8YtB5yaOPMEKROEcFElZJGNR9uifqufNN/xArOi920="
	patched, changed := patchMissingServerPubKey(userReportedConf, serverPub)
	if !changed {
		t.Fatalf("expected changed to be true for missing server public key")
	}
	if !strings.Contains(patched, "PublicKey = "+serverPub) {
		t.Fatalf("expected patched config to contain server public key, got:\n%s", patched)
	}
	if strings.Contains(patched, "PublicKey = \n") || strings.Contains(patched, "PublicKey = \r\n") {
		t.Fatalf("patched config still contains empty PublicKey line")
	}

	// Idempotency: Running again should produce no changes
	patched2, changed2 := patchMissingServerPubKey(patched, serverPub)
	if changed2 {
		t.Errorf("expected second pass to return changed=false")
	}
	if patched2 != patched {
		t.Errorf("expected second pass to return identical content")
	}

	// Test updating mismatched/stale server public key
	staleKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	confWithStaleKey := strings.Replace(patched, serverPub, staleKey, 1)
	repaired, changed3 := patchMissingServerPubKey(confWithStaleKey, serverPub)
	if !changed3 {
		t.Errorf("expected changed=true when repairing stale server public key")
	}
	if !strings.Contains(repaired, "PublicKey = "+serverPub) {
		t.Errorf("expected repaired config to have new server public key")
	}
	if strings.Contains(repaired, staleKey) {
		t.Errorf("expected stale key to be completely removed")
	}
}

func TestGenerateKeypairAndDerive(t *testing.T) {
	priv, pub, err := generateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair error: %v", err)
	}
	if len(priv) != 44 || len(pub) != 44 {
		t.Fatalf("expected 44-char base64 keys, got priv=%d pub=%d", len(priv), len(pub))
	}

	derivedPub, err := derivePublicKey(priv)
	if err != nil {
		t.Fatalf("derivePublicKey error: %v", err)
	}
	if derivedPub != pub {
		t.Errorf("derived pub key mismatch: got %s, want %s", derivedPub, pub)
	}
}

