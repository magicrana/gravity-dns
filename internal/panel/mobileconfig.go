package panel

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"gravity-dns/internal/config"
	"gravity-dns/internal/store"
)

// GenerateMobileConfig generates an Apple iOS/macOS .mobileconfig profile XML.
func GenerateMobileConfig(cfg *config.Config, u *store.User, protocol string) string {
	domain := cfg.Server.Domain
	serverIPv4 := cfg.Server.PublicIPv4
	token := u.Token
	username := u.Username

	profileUUID := uuid.New().String()
	payloadUUID := uuid.New().String()

	protocol = strings.ToUpper(strings.TrimSpace(protocol))
	if protocol != "DOH" {
		protocol = "DOT"
	}

	var dnsSettingsBlock string
	if protocol == "DOH" {
		dohPort := "8443"
		if parts := strings.Split(cfg.DNS.DoHListen, ":"); len(parts) == 2 && parts[1] != "" {
			dohPort = parts[1]
		}

		serverURL := fmt.Sprintf("https://%s:%s/dns-query/%s", domain, dohPort, token)
		if dohPort == "443" {
			serverURL = fmt.Sprintf("https://%s/dns-query/%s", domain, token)
		}

		dnsSettingsBlock = fmt.Sprintf(`
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>%s</string>
				<key>ServerAddresses</key>
				<array>
					<string>%s</string>
				</array>
			</dict>`, serverURL, serverIPv4)
	} else {
		// DoT (Default)
		sniHost := fmt.Sprintf("%s.%s", token, domain)
		dnsSettingsBlock = fmt.Sprintf(`
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>TLS</string>
				<key>ServerName</key>
				<string>%s</string>
				<key>ServerAddresses</key>
				<array>
					<string>%s</string>
				</array>
			</dict>`, sniHost, serverIPv4)
	}

	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadDisplayName</key>
	<string>GravityDNS - %s</string>
	<key>PayloadDescription</key>
	<string>Configures encrypted %s for native iOS/macOS SmartDNS bypass.</string>
	<key>PayloadIdentifier</key>
	<string>com.gravitydns.profile.%s</string>
	<key>PayloadOrganization</key>
	<string>GravityDNS</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadDisplayName</key>
			<string>GravityDNS Encrypted Resolver</string>
			<key>PayloadIdentifier</key>
			<string>com.gravitydns.dnssettings.%s</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			%s
		</dict>
	</array>
</dict>
</plist>`, username, protocol, token, profileUUID, token, payloadUUID, dnsSettingsBlock)

	return strings.TrimSpace(xml)
}
