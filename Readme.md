# 🔍 iplens

> Fast, cross-platform CLI to inspect your network — public/private IPs, ISP, gateway, and proxy/VPN detection. Zero dependencies.

[![npm version](https://img.shields.io/npm/v/iplens.svg)](https://www.npmjs.com/package/iplens)
[![node](https://img.shields.io/node/v/iplens.svg)](https://www.npmjs.com/package/iplens)
[![license](https://img.shields.io/npm/l/iplens.svg)](LICENSE)
[![platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-blue.svg)](#)

`iplens` is a single-binary network diagnostic tool. It tells you what your machine looks like to the internet — the IPs it uses, the ISP it reaches through, the router it goes to first — and it does it fast, offline-tolerant, and with no npm dependencies.

## ✨ Features

- 🌐 **Public IP detection** (IPv4 + IPv6) via STUN for true post-NAT/post-CGNAT egress, with HTTPS fallback
- 🖥️ **Private IP detection** across all network interfaces
- 🚪 **Default gateway** discovery (Windows, macOS, Linux)
- 📡 **ISP & geolocation lookup** when online
- 🕵️ **Proxy / VPN heuristic** with curated datacenter + VPN-provider ASN list
- ⚡ **Fast** — parallel probes, ~2s typical runtime
- 📴 **Offline-tolerant** — gracefully degrades when no internet
- 🧠 **Cross-platform** — Linux, macOS, Windows
- 🔧 **Scripting-friendly** — `--json` for structured output
- 📦 **Zero npm dependencies** — just Node.js stdlib

## 📥 Installation

```bash
npm install -g iplens
```

Or run once without installing:

```bash
npx iplens
```

**Requirements:** Node.js 14 or higher.

## 🚀 Usage

```bash
iplens                  # human-readable output
iplens --json           # JSON for scripting
iplens --verbose        # include STUN probe details, raw API responses, signal info
iplens --timeout=5000   # override HTTPS request timeout (ms, default: 2000)
iplens --help           # show help
```

## 📖 Example Output

### Online

```
🔍 iplens v1.0.0

Public IPv4:
  - 203.0.113.42

Public IPv6:
  - 2001:db8:abcd:1234::1

Private IPv4:
  - 192.168.1.100
  - 10.0.0.5

Private IPv6:
  - fe80::1a2b:3c4d:5e6f:7890

Gateway: 192.168.1.1

ISP: AS12345 Example Internet Provider
Location: City, Country

Proxy/VPN: LIKELY NO
```

### Offline

```
🔍 iplens v1.0.0

Internet: OFFLINE

Private IPv4:
  - 192.168.1.100

Private IPv6:
  - fe80::1a2b:3c4d:5e6f:7890

Gateway: 192.168.1.1

Public info not available (offline)
```

### JSON output

```bash
$ iplens --json
```

```json
{
  "privateIPv4": ["192.168.1.100", "10.0.0.5"],
  "privateIPv6": ["fe80::1a2b:3c4d:5e6f:7890"],
  "gateway": "192.168.1.1",
  "internet": true,
  "publicIPv4": ["203.0.113.42"],
  "publicIPv6": ["2001:db8:abcd:1234::1"],
  "isp": {
    "org": "AS12345 Example Internet Provider",
    "city": "City",
    "country": "XX"
  },
  "proxy": {
    "status": "LIKELY NO",
    "signals": []
  }
}
```

## 🔧 Scripting examples

Extract your public IPv4 for use in a shell script:

```bash
MY_IP=$(iplens --json | jq -r '.publicIPv4[0]')
echo "Firewalling from $MY_IP"
```

Check if you're behind a VPN in a conditional:

```bash
if [ "$(iplens --json | jq -r '.proxy.status')" = "LIKELY YES" ]; then
  echo "VPN detected — skipping geolocation-sensitive calls"
fi
```

## 🕵️ How public IP detection works

`iplens` uses a two-tier strategy:

1. **STUN probe (primary)** — Sends UDP STUN Binding Requests to public STUN servers (Google, Cloudflare, Nextcloud) and parses the XOR-MAPPED-ADDRESS response. This reveals the **true post-NAT, post-CGNAT egress IP** — the address a remote server actually sees your traffic coming from.

2. **HTTPS APIs (fallback + enrichment)** — Queries `ipify`, `ifconfig.me`, `ipinfo.io`, and `ident.me`. Used when STUN is blocked (some corporate firewalls), and always used for ISP/geolocation metadata.

When STUN succeeds, its result is authoritative. HTTPS results only fill in gaps (e.g., an IP family STUN didn't resolve).

## 🌐 Note on browser comparisons

Results from `iplens` may differ from browser-based IP checkers (whatsmyip.com, ipleak.net, etc.) if your browser uses a built-in VPN/proxy — **Opera VPN**, **Edge Secure Network**, **Brave Firewall+VPN**, **Chrome IP Protection**, or extensions that tunnel traffic.

`iplens` reports your operating system's actual egress IP — the address used by `curl`, `ssh`, `git`, `docker`, and every other non-browser application on your machine. That's the useful answer for network diagnostics.

## ⚠️ Limitations

- **Proxy/VPN detection is heuristic.** It matches the ASN organization name against a curated list of datacenter and VPN provider keywords. It will miss small VPN providers and residential proxy services. It's a fast first signal, not a forensic tool.
- **STUN requires outbound UDP.** Some corporate and guest networks block UDP to ports 19302/3478. In those cases, `iplens` silently falls back to HTTPS API detection.
- **ISP lookup uses the free tier of ipinfo.io.** No auth is used, which means the free rate limit applies. For heavy automated use, consider forking and adding your own token.
- **IPv6 detection requires real IPv6 connectivity.** Many home and mobile networks have IPv6 disabled or broken upstream; `iplens` will simply report no public IPv6 in those cases.

## 🐛 Troubleshooting

**Public IP shows "None detected" but I have internet:**
Run `iplens --verbose` to see STUN probe results and raw HTTPS responses. Most likely cause is a firewall blocking both outbound UDP (STUN) and the HTTPS API domains.

**Gateway is `null`:**
On Linux without `ip` or `route` installed: `sudo apt install iproute2` (Debian/Ubuntu), `sudo dnf install iproute` (Fedora), `sudo apk add iproute2` (Alpine). On Windows, PowerShell must be available and executable.

**Results are inconsistent between runs:**
Dynamic IP reassignment, CGNAT port reshuffling, or failover between IPv4/IPv6 paths can cause this. Run with `--verbose` to see which source reported what.

## 🤝 Contributing

Issues and PRs welcome at [github.com/saurabh-vaish/iplens](https://github.com/saurabh-vaish/iplens).

Particularly useful contributions:
- New VPN provider / datacenter ASN keywords (see `VPN_PROVIDER_KEYWORDS` and `DATACENTER_KEYWORDS` in `index.js`)
- Platform-specific gateway detection fixes
- Test cases

## 📄 License

MIT © Saurabh Vaish