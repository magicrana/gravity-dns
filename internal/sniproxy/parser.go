package sniproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrNotTLSHandshake     = errors.New("not a valid TLS handshake record")
	ErrNotClientHello      = errors.New("handshake message is not ClientHello")
	ErrIncompleteData      = errors.New("incomplete TLS record data")
	ErrSNINotFound         = errors.New("SNI extension not present")
)

// ExtractSNI parses the initial TLS ClientHello bytes and returns the server name indication.
func ExtractSNI(data []byte) (string, error) {
	// Need at least 5 bytes for TLS record header
	if len(data) < 5 {
		return "", ErrIncompleteData
	}

	// Byte 0 must be 0x16 (Handshake)
	if data[0] != 0x16 {
		return "", ErrNotTLSHandshake
	}

	// Bytes 1-2: TLS Record Version (0x0301, 0x0302, 0x0303)
	// Bytes 3-4: Record Length
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen && len(data) < 512 {
		// Handshake can span multiple packets, but typical ClientHello with SNI fits in first 512-2048 bytes
		// If we don't have enough bytes to read header, report incomplete
	}

	pos := 5
	if len(data) < pos+4 {
		return "", ErrIncompleteData
	}

	// Handshake Type: 0x01 = ClientHello
	if data[pos] != 0x01 {
		return "", ErrNotClientHello
	}

	// Handshake length (3 bytes)
	handshakeLen := int(data[pos+1])<<16 | int(data[pos+2])<<8 | int(data[pos+3])
	pos += 4

	if len(data) < pos+handshakeLen && len(data) < pos+34 {
		// Proceed as far as buffer allows
	}

	// Skip ProtocolVersion (2 bytes) + Random (32 bytes) = 34 bytes
	pos += 34
	if len(data) < pos+1 {
		return "", ErrIncompleteData
	}

	// Session ID length (1 byte)
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if len(data) < pos+2 {
		return "", ErrIncompleteData
	}

	// Cipher Suites length (2 bytes)
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if len(data) < pos+1 {
		return "", ErrIncompleteData
	}

	// Compression Methods length (1 byte)
	compMethodsLen := int(data[pos])
	pos += 1 + compMethodsLen
	if len(data) < pos+2 {
		return "", ErrSNINotFound
	}

	// Extensions length (2 bytes)
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	// Loop over extensions
	for pos+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > extensionsEnd {
			break
		}

		// 0x0000 = server_name (SNI)
		if extType == 0x0000 {
			sniData := data[pos : pos+extLen]
			if len(sniData) < 2 {
				return "", ErrSNINotFound
			}

			// Server Name List length (2 bytes)
			listLen := int(binary.BigEndian.Uint16(sniData[0:2]))
			sniPos := 2

			for sniPos+3 <= 2+listLen && sniPos+3 <= len(sniData) {
				nameType := sniData[sniPos]
				nameLen := int(binary.BigEndian.Uint16(sniData[sniPos+1 : sniPos+3]))
				sniPos += 3

				if sniPos+nameLen > len(sniData) {
					break
				}

				// Type 0 = host_name
				if nameType == 0x00 {
					hostName := string(sniData[sniPos : sniPos+nameLen])
					return strings.ToLower(hostName), nil
				}
				sniPos += nameLen
			}
		}

		pos += extLen
	}

	return "", ErrSNINotFound
}

// InspectClientHello reads the TLS ClientHello from a reader and returns the SNI and recorded raw bytes.
type HelloInfo struct {
	SNI      string
	RawBytes []byte
}

func FormatSNIError(err error) string {
	if errors.Is(err, ErrSNINotFound) {
		return "SNI extension missing or not present"
	}
	if errors.Is(err, ErrNotTLSHandshake) {
		return "Non-TLS traffic received"
	}
	return fmt.Sprintf("TLS parsing error: %v", err)
}
