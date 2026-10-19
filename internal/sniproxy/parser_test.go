package sniproxy

import (
	"encoding/binary"
	"testing"
)

// buildTestClientHello constructs a synthetic valid TLS ClientHello with the given SNI.
func buildTestClientHello(sni string) []byte {
	// Extensions: SNI extension
	sniBytes := []byte(sni)
	sniData := make([]byte, 0, len(sniBytes)+5)
	// ServerNameList length
	sniData = binary.BigEndian.AppendUint16(sniData, uint16(len(sniBytes)+3))
	// NameType: 0x00 (host_name)
	sniData = append(sniData, 0x00)
	// HostName length
	sniData = binary.BigEndian.AppendUint16(sniData, uint16(len(sniBytes)))
	// HostName
	sniData = append(sniData, sniBytes...)

	extensions := make([]byte, 0, len(sniData)+4)
	// Extension Type: 0x0000 (server_name)
	extensions = binary.BigEndian.AppendUint16(extensions, 0x0000)
	// Extension Length
	extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(sniData)))
	extensions = append(extensions, sniData...)

	// Handshake body
	handshakeBody := make([]byte, 0, 128+len(extensions))
	// ProtocolVersion: TLS 1.2 (0x03, 0x03)
	handshakeBody = append(handshakeBody, 0x03, 0x03)
	// Random (32 bytes)
	handshakeBody = append(handshakeBody, make([]byte, 32)...)
	// SessionID length 0
	handshakeBody = append(handshakeBody, 0x00)
	// CipherSuites (length 2, 1 suite 0x002f)
	handshakeBody = append(handshakeBody, 0x00, 0x02, 0x00, 0x2f)
	// Compression methods (length 1, 0x00)
	handshakeBody = append(handshakeBody, 0x01, 0x00)
	// Extensions length
	handshakeBody = binary.BigEndian.AppendUint16(handshakeBody, uint16(len(extensions)))
	handshakeBody = append(handshakeBody, extensions...)

	// Handshake Header
	handshake := make([]byte, 0, len(handshakeBody)+4)
	handshake = append(handshake, 0x01) // ClientHello
	// Handshake length (3 bytes)
	handshakeLen := len(handshakeBody)
	handshake = append(handshake, byte(handshakeLen>>16), byte(handshakeLen>>8), byte(handshakeLen))
	handshake = append(handshake, handshakeBody...)

	// TLS Record Header
	record := make([]byte, 0, len(handshake)+5)
	record = append(record, 0x16) // ContentType: Handshake
	record = append(record, 0x03, 0x01) // Version TLS 1.0
	record = binary.BigEndian.AppendUint16(record, uint16(len(handshake)))
	record = append(record, handshake...)

	return record
}

func TestExtractSNI_Valid(t *testing.T) {
	testDomains := []string{
		"netflix.com",
		"www.netflix.com",
		"assets.hulu.com",
		"api.disneyplus.com",
		"sub.level.primevideo.com",
	}

	for _, domain := range testDomains {
		raw := buildTestClientHello(domain)
		extracted, err := ExtractSNI(raw)
		if err != nil {
			t.Fatalf("ExtractSNI failed for %s: %v", domain, err)
		}
		if extracted != domain {
			t.Errorf("expected %s, got %s", domain, extracted)
		}
	}
}

func TestExtractSNI_InvalidData(t *testing.T) {
	// 1. Empty buffer
	_, err := ExtractSNI([]byte{})
	if err != ErrIncompleteData {
		t.Errorf("expected ErrIncompleteData, got %v", err)
	}

	// 2. Non-TLS (HTTP GET)
	httpGet := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, err = ExtractSNI(httpGet)
	if err != ErrNotTLSHandshake {
		t.Errorf("expected ErrNotTLSHandshake, got %v", err)
	}

	// 3. Truncated ClientHello
	raw := buildTestClientHello("test.com")
	_, err = ExtractSNI(raw[:15])
	if err == nil {
		t.Errorf("expected error for truncated data, got nil")
	}
}
