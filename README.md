# GravityDNS - High-Performance SmartDNS & SNI Proxy Platform

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2022.04%20%2F%2024.04%20LTS-E95420?style=flat&logo=ubuntu)](https://ubuntu.com)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**GravityDNS** is a production-grade, self-hosted SmartDNS platform built in pure **Go (Golang)**. It allows users to bypass geo-restrictions without installing client-side VPN software by configuring their device's native Private DNS (DNS-over-TLS on `:853`) or DNS-over-HTTPS (`:443`/`:8443`) to their unique user subdomain, while enforcing per-user concurrent device limits via Redis and streaming hijacked traffic via an SNI Proxy.

---

## 🌟 Key Features

### 1. Pure Go DNS Engine (`cmd/dns`)
- **DNS-over-TLS (DoT)** on `0.0.0.0:853` (RFC 7858) using `github.com/miekg/dns` and standard `crypto/tls`.
- **DNS-over-HTTPS (DoH)** on `0.0.0.0:8443` (RFC 8484) supporting binary wireformat and GET/POST `/dns-query/{token}`.
- **Client Identification via Wildcard TLS SNI**: Handshake intercepts `tls.ConnectionState.ServerName` to extract the client token from `<token>.dns.domain.com`.
- **Sliding-Window Device Limiter**: Redis Sorted Set (`user:<token>:devices`) tracking active client IPs within a rolling 10-minute window. If concurrency exceeds quota, returns `RcodeRefused`.
- **Selective Hijacking / Spoofing**: Targeted domains matching wildcard rules (`*.netflix.com`, `*.hulu.com`, etc.) return the VPS IPv4 (`A` record) with a low TTL (60s) and synthesized `NODATA` for RFC 9460 HTTPS records to avoid Encrypted ClientHello (ECH) bypass.
- **Non-Hijacked Query Upstream Forwarding**: High-performance recursive resolver with failover and in-memory TTL caching.

### 2. High-Performance SNI Stream Router (`cmd/sniproxy`)
- Pure Go TCP proxy listening on `0.0.0.0:443`.
- Zero-copy TCP streaming (`io.Copy` invokes Linux kernel `splice(2)` for socket-to-socket transfers).
- Peeks TLS `ClientHello` without certificate termination, extracts the SNI hostname, resolves real origin IP via independent upstream DNS, and transparently pipes bidirectional TLS streams.
- Optional kernel-level Nginx stream configuration included (`configs/nginx-stream.conf`).

### 3. Control Plane & Web Management Panel (`cmd/panel`)
- Modern, responsive dark mode UI built with Tailwind CSS.
- **Session/JWT Admin Authentication** with bcrypt password hashing.
- **User Management**: Add/edit/delete users, configure max concurrent IPs, expiration periods, and notes.
- **Client Endpoints**:
  - Android Private DNS: `<token>.dns.domain.com` (1-click copy).
  - DNS-over-HTTPS URL: `https://dns.domain.com:8443/dns-query/<token>`.
  - Apple iOS / iPadOS / macOS: 1-click native `.mobileconfig` profile download!
- **Live Device Monitoring**: Real-time table of active client IPs in the 10-minute window with 1-click **Kill Sessions** (`DEL user:<token>:devices`).
- **Domain Spoofing Rules & Presets**: Pre-loaded 1-click presets for Netflix, Hulu, Disney+, Prime Video, Max/HBO, Peacock, Paramount+, BBC iPlayer, Crunchyroll, and custom wildcard rules.

---

## 📁 Repository Structure

```text
gravity-dns/
├── cmd/
│   ├── dns/            # DoT & DoH Engine
│   │   └── main.go
│   ├── panel/          # Admin Web UI & Management API
│   │   └── main.go
│   ├── sniproxy/       # Pure Go TLS SNI stream router
│   │   └── main.go
│   └── gravity/        # Unified multi-service CLI runner
│       └── main.go
├── internal/
│   ├── config/         # App configuration & env loader
│   ├── dnsengine/      # DoT/DoH connection server
│   ├── limiter/        # Redis sliding-window device limiter
│   ├── panel/          # HTTP handlers, JWT auth, and Apple .mobileconfig generator
│   ├── resolver/       # Upstream resolver & hijack rule matcher
│   ├── sniproxy/       # RFC TLS ClientHello parser & TCP stream router
│   └── store/          # Redis models, session states, and rule persistence
├── web/
│   ├── templates/      # Dark mode HTML5 templates (Tailwind CSS)
│   │   ├── login.html
│   │   └── dashboard.html
│   └── static/         # CSS and static assets
├── configs/
│   ├── gravity.yaml.example
│   ├── sysctl-tuning.conf
│   └── nginx-stream.conf
├── scripts/
│   ├── install.sh      # Automated interactive Ubuntu 22.04/24.04 installer
│   └── certbot-hook.sh # Certbot renewal deploy hook
├── go.mod
└── go.sum
```

---

## 🚀 Quick Deployment (Ubuntu 22.04 / 24.04 LTS)

### Prerequisites
1. An Ubuntu 22.04 or 24.04 LTS VPS with a Public IPv4 address.
2. A registered domain with DNS records configured:
   - `dns.yourdomain.com` &rarr; `A` record pointing to VPS IPv4.
   - `*.dns.yourdomain.com` &rarr; `A` record pointing to VPS IPv4 (Wildcard).

### One-Liner Automated Installation
Run the one-liner command directly on your Ubuntu 22.04 or 24.04 LTS server as `root`:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/magicrana/gravity-dns/main/install.sh)
```
*Or via standard pipe:*
```bash
curl -fsSL https://raw.githubusercontent.com/magicrana/gravity-dns/main/install.sh | bash
```

### Unattended / Non-Interactive One-Liner (Automated CI/CD)
To deploy without interactive prompts, pass environment variables inline:

```bash
sudo GRAVITY_NON_INTERACTIVE=true \
     GRAVITY_DOMAIN="dns.yourdomain.com" \
     GRAVITY_PUBLIC_IPV4="203.0.113.1" \
     GRAVITY_ADMIN_PASS="MySecretAdminPass123" \
     bash -c "$(curl -fsSL https://raw.githubusercontent.com/magicrana/gravity-dns/main/install.sh)"
```

### Alternatively, Clone & Run Manually:
```bash
git clone https://github.com/magicrana/gravity-dns.git /opt/gravity-dns
cd /opt/gravity-dns
sudo bash install.sh
```

### 🔄 In-Place Upgrades & Reinstallation
To update an existing installation to the latest version of GravityDNS, simply re-run the one-liner installer at any time:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/magicrana/gravity-dns/main/install.sh)
```
The installer automatically detects your existing installation and **updates everything** (Go engine binaries, web control panel templates, kernel configs, systemd services) **while strictly preserving your last installed admin password, base domain, TLS certificates, and settings**. A backup of your previous configuration is also automatically preserved at `/etc/gravity/gravity.yaml.bak`.

The script will automatically:
1. Detect your public IP and prompt for base domain and admin password.
2. Install `redis-server`, build tools, and modern Go compiler.
3. Apply kernel sysctl optimizations (`sysctl-tuning.conf` with TCP BBR and high-concurrency buffers).
4. Compile the binaries and install them to `/usr/local/bin/gravity`.
5. Create `/etc/gravity/gravity.yaml` configuration.
6. Configure and start systemd service `gravity.service`.
7. Configure UFW firewall rules for ports `853`, `8443`, `443`, `8080`, and `80`.

---

## ⚙️ Manual Configuration

Copy the example configuration to `/etc/gravity/gravity.yaml`:

```bash
sudo cp configs/gravity.yaml.example /etc/gravity/gravity.yaml
sudo nano /etc/gravity/gravity.yaml
```

Key configuration options:

```yaml
server:
  domain: "dns.yourdomain.com"
  public_ipv4: "203.0.113.1"

dns:
  enabled: true
  dot_listen: "0.0.0.0:853"
  doh_listen: "0.0.0.0:8443"
  tls_cert_file: "/etc/letsencrypt/live/dns.yourdomain.com/fullchain.pem"
  tls_key_file: "/etc/letsencrypt/live/dns.yourdomain.com/privkey.pem"
  upstream_dns:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  spoof_ttl: 60
  device_window_sec: 600

sniproxy:
  enabled: true
  listen: "0.0.0.0:443"
  upstream_dns:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  connect_timeout: 5
  idle_timeout: 300
  enforce_rules: true

redis:
  addr: "127.0.0.1:6379"

panel:
  enabled: true
  listen: "0.0.0.0:8080"
  jwt_secret: "YOUR_SUPER_SECRET_KEY"
  admin_username: "admin"
  admin_password: "YourStrongPassword"
```

---

## 🔒 Wildcard TLS Certificates (Let's Encrypt)

GravityDNS requires a wildcard certificate (`*.dns.yourdomain.com` and `dns.yourdomain.com`) so that client subdomains `<token>.dns.yourdomain.com` pass TLS handshake validation.

### Using Certbot DNS Challenge:
```bash
sudo certbot certonly --manual --preferred-challenges dns \
    -d "dns.yourdomain.com" \
    -d "*.dns.yourdomain.com"
```

Add the generated TXT records to your DNS provider, and certbot will generate the certificates in `/etc/letsencrypt/live/dns.yourdomain.com/`.

---

## 📱 Client Setup Guides

### 1. Android 9+ (Private DNS - DNS over TLS)
1. Go to **Settings** &rarr; **Network & Internet** (or Connections) &rarr; **Private DNS**.
2. Select **Private DNS provider hostname**.
3. Enter your unique endpoint: `<token>.dns.yourdomain.com`.
4. Tap **Save**. All traffic to streaming services is now spoofed and streamed via SNI proxy!

### 2. Apple iOS / iPadOS / macOS (.mobileconfig Profile)
1. Open the Web Management Panel &rarr; User Management &rarr; click **Quick Setup**.
2. Click **Download Profile (DoT)**.
3. Open iOS **Settings** &rarr; tap **Profile Downloaded** &rarr; tap **Install**.
4. Native system-wide encrypted DNS is activated with zero third-party apps required!

### 3. Windows 11 (DNS-over-HTTPS)
1. Open **Settings** &rarr; **Network & Internet** &rarr; **Ethernet** or **Wi-Fi**.
2. Click **Hardware properties** &rarr; Edit **DNS server assignment** to **Manual**.
3. Enter Preferred DNS: `VPS_IP`.
4. Select **Encrypted only (DNS over HTTPS)**.
5. In DoH Template, enter: `https://dns.yourdomain.com:8443/dns-query/<token>`.

---

## 🛠️ Service Management

```bash
# Unified Service
sudo systemctl start gravity.service
sudo systemctl stop gravity.service
sudo systemctl status gravity.service
sudo journalctl -u gravity.service -f

# CLI Control
gravity version
gravity all -config /etc/gravity/gravity.yaml
gravity dns -config /etc/gravity/gravity.yaml
gravity sniproxy -config /etc/gravity/gravity.yaml
gravity panel -config /etc/gravity/gravity.yaml
```

---

## 🧪 Testing

Run test suite:

```bash
go test -v ./...
```
