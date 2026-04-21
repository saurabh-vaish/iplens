#!/usr/bin/env node

const os = require("os");
const https = require("https");
const dns = require("dns");
const dgram = require("dgram");
const crypto = require("crypto");
const { exec } = require("child_process");

// ---------- Version ----------
let VERSION = "2.3";
try {
  VERSION = require("./package.json").version;
} catch {
  // fallback to hardcoded if package.json not found
}

// ---------- CLI Args ----------
const args = process.argv.slice(2);
const isJSON = args.includes("--json");
const isVerbose = args.includes("--verbose");
const showHelp = args.includes("--help") || args.includes("-h");
const timeoutArg = args.find(a => a.startsWith("--timeout="));
const TIMEOUT = (timeoutArg ? parseInt(timeoutArg.split("=")[1]) : NaN) || 2000;
const STUN_TIMEOUT = 1500;

// ---------- Help ----------
if (showHelp) {
  console.log(`
🔍 iplens v${VERSION}

Usage: iplens [options]

Options:
  --json              Output results as JSON
  --verbose           Show extra details (API responses, STUN, proxy signals)
  --timeout=<ms>      Request timeout in milliseconds (default: 2000)
  --help, -h          Show this help message
`);
  process.exit(0);
}

// ---------- Utils ----------
function safeExec(command) {
  return new Promise((resolve) => {
    exec(command, { timeout: TIMEOUT }, (err, stdout) => {
      if (err) {
        resolve({ success: false, error: err.message });
      } else {
        resolve({ success: true, output: stdout });
      }
    });
  });
}

function httpsGet(url, timeout, parser) {
  return new Promise((resolve) => {
    const req = https.get(url, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return resolve(null);
      }

      let data = "";
      res.on("data", chunk => (data += chunk));
      res.on("end", () => resolve(parser(data)));
    });

    req.on("error", () => resolve(null));
    req.setTimeout(timeout, () => {
      req.destroy();
      resolve(null);
    });
  });
}

function fetchJSON(url, timeout = TIMEOUT) {
  return httpsGet(url, timeout, (data) => {
    try { return JSON.parse(data); } catch { return null; }
  });
}

function fetchText(url, timeout = TIMEOUT) {
  return httpsGet(url, timeout, (data) => data.trim() || null);
}

// ---------- IP classification helpers ----------
function isIPv4(addr) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(addr);
}

function isIPv6(addr) {
  return addr && addr.includes(":");
}

// ---------- STUN client (RFC 5389, minimal) ----------
// Only implements Binding Request -> parse XOR-MAPPED-ADDRESS from response.
// No auth, no TURN, no long-term credentials — just enough to discover
// the true public (post-NAT, post-CGNAT) IP address.

const STUN_MAGIC_COOKIE = 0x2112A442;
const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_SUCCESS = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS = 0x0020;
const ATTR_MAPPED_ADDRESS = 0x0001; // legacy fallback

function buildStunBindingRequest() {
  const txnId = crypto.randomBytes(12);
  const header = Buffer.alloc(20);
  header.writeUInt16BE(STUN_BINDING_REQUEST, 0);
  header.writeUInt16BE(0, 2);
  header.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
  txnId.copy(header, 8);
  return { packet: header, txnId };
}

function parseStunResponse(msg, expectedTxnId) {
  if (msg.length < 20) return null;

  const msgType = msg.readUInt16BE(0);
  const msgLen = msg.readUInt16BE(2);
  const cookie = msg.readUInt32BE(4);
  const txnId = msg.slice(8, 20);

  if (msgType !== STUN_BINDING_SUCCESS) return null;
  if (cookie !== STUN_MAGIC_COOKIE) return null;
  if (!txnId.equals(expectedTxnId)) return null;
  if (msg.length < 20 + msgLen) return null;

  let offset = 20;
  const end = 20 + msgLen;

  while (offset + 4 <= end) {
    const attrType = msg.readUInt16BE(offset);
    const attrLen = msg.readUInt16BE(offset + 2);
    const valueStart = offset + 4;
    const valueEnd = valueStart + attrLen;

    if (valueEnd > msg.length) break;

    if (attrType === ATTR_XOR_MAPPED_ADDRESS || attrType === ATTR_MAPPED_ADDRESS) {
      const xor = attrType === ATTR_XOR_MAPPED_ADDRESS;
      const family = msg.readUInt8(valueStart + 1);
      const port = msg.readUInt16BE(valueStart + 2);

      if (family === 0x01) {
        const raw = msg.slice(valueStart + 4, valueStart + 8);
        const bytes = xor
          ? raw.map((b, i) => b ^ msg[4 + i])
          : raw;
        return {
          family: "IPv4",
          address: `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`,
          port: xor ? port ^ (STUN_MAGIC_COOKIE >>> 16) : port
        };
      } else if (family === 0x02) {
        const raw = msg.slice(valueStart + 4, valueStart + 20);
        const bytes = Buffer.alloc(16);
        if (xor) {
          for (let i = 0; i < 16; i++) {
            bytes[i] = raw[i] ^ msg[4 + i];
          }
        } else {
          raw.copy(bytes);
        }
        const parts = [];
        for (let i = 0; i < 16; i += 2) {
          parts.push(bytes.readUInt16BE(i).toString(16));
        }
        return {
          family: "IPv6",
          address: compressIPv6(parts.join(":")),
          port: xor ? port ^ (STUN_MAGIC_COOKIE >>> 16) : port
        };
      }
    }

    offset = valueEnd + ((4 - (attrLen % 4)) % 4);
  }

  return null;
}

function compressIPv6(addr) {
  const parts = addr.split(":");
  let bestStart = -1, bestLen = 0;
  let curStart = -1, curLen = 0;

  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === "0") {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestLen < 2) return parts.join(":");

  const head = parts.slice(0, bestStart).join(":");
  const tail = parts.slice(bestStart + bestLen).join(":");
  return `${head}::${tail}`;
}

function stunProbe(host, port, family, timeout = STUN_TIMEOUT) {
  return new Promise((resolve) => {
    const socketType = family === 6 ? "udp6" : "udp4";
    let socket;
    try {
      socket = dgram.createSocket(socketType);
    } catch {
      return resolve(null);
    }

    const { packet, txnId } = buildStunBindingRequest();

    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      try { socket.close(); } catch {}
      resolve(result);
    };

    const timer = setTimeout(() => done(null), timeout);

    socket.on("message", (msg) => {
      clearTimeout(timer);
      done(parseStunResponse(msg, txnId));
    });

    socket.on("error", () => {
      clearTimeout(timer);
      done(null);
    });

    dns.lookup(host, { family }, (err, address) => {
      if (err) {
        clearTimeout(timer);
        return done(null);
      }
      socket.send(packet, port, address, (sendErr) => {
        if (sendErr) {
          clearTimeout(timer);
          done(null);
        }
      });
    });
  });
}

async function discoverPublicIPsViaStun() {
  const servers = [
    { host: "stun.l.google.com", port: 19302 },
    { host: "stun.cloudflare.com", port: 3478 },
    { host: "stun.nextcloud.com", port: 3478 }
  ];

  const probeV4 = Promise.any(
    servers.map(s => stunProbe(s.host, s.port, 4).then(r => r || Promise.reject()))
  ).catch(() => null);

  const probeV6 = Promise.any(
    servers.map(s => stunProbe(s.host, s.port, 6).then(r => r || Promise.reject()))
  ).catch(() => null);

  const [v4, v6] = await Promise.all([probeV4, probeV6]);

  return {
    ipv4: v4 && v4.family === "IPv4" ? v4.address : null,
    ipv6: v6 && v6.family === "IPv6" ? v6.address : null
  };
}

// ---------- Internet Check (with timeout) ----------
function checkInternet(timeout = TIMEOUT) {
  return new Promise((resolve) => {
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        resolve(false);
      }
    }, timeout);

    dns.lookup("google.com", (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(!err);
      }
    });
  });
}

// ---------- Local IPs (Primary via OS) ----------
function getLocalIPsFromOS() {
  try {
    const interfaces = os.networkInterfaces();
    const ipv4 = [];
    const ipv6 = [];

    for (const name of Object.keys(interfaces)) {
      for (const net of interfaces[name]) {
        if (net.internal) continue;
        const family = typeof net.family === "number"
          ? (net.family === 4 ? "IPv4" : "IPv6")
          : net.family;

        if (family === "IPv4") ipv4.push(net.address);
        if (family === "IPv6") ipv6.push(net.address);
      }
    }

    return { ipv4, ipv6 };
  } catch {
    return { ipv4: [], ipv6: [] };
  }
}

// ---------- Local IPs (Fallback via OS Commands) ----------
async function getLocalIPsFromCommands(platform) {
  let cmd;

  if (platform === "win32") {
    cmd = "ipconfig";
  } else if (platform === "darwin") {
    cmd = "ifconfig";
  } else {
    cmd = "ip addr 2>/dev/null || ifconfig 2>/dev/null";
  }

  const res = await safeExec(cmd);

  if (!res.success) {
    return {
      success: false,
      hint: getInstallHint(platform),
      error: res.error
    };
  }

  return { success: true, raw: res.output };
}

function getInstallHint(platform) {
  if (platform === "linux") {
    return "Install iproute2 or net-tools (apt: sudo apt install iproute2 | dnf: sudo dnf install iproute | apk: sudo apk add iproute2)";
  }
  if (platform === "darwin") return "ifconfig should already exist (macOS)";
  if (platform === "win32") return "ipconfig is built-in (check PATH)";
  return "Command not available";
}

// ---------- Default Gateway ----------
async function getDefaultGateway(platform) {
  let cmd;

  if (platform === "win32") {
    cmd = "powershell -Command \"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop\"";
  } else if (platform === "darwin") {
    cmd = "route -n get default 2>/dev/null | awk '/gateway:/ {print $2}'";
  } else {
    cmd = "ip route show default 2>/dev/null | awk '/default/ {print $3; exit}' || route -n 2>/dev/null | awk '/^0.0.0.0/ {print $2; exit}'";
  }

  const res = await safeExec(cmd);
  if (!res.success) return null;
  const gw = res.output.trim();
  return gw || null;
}

// ---------- Public IPs via HTTPS APIs (fallback + ISP lookup) ----------
async function getPublicAndISPInfo(knownIP) {
  const jsonSources = [
    "https://api.ipify.org?format=json",
    "https://api64.ipify.org?format=json",
    "https://ifconfig.me/all.json",
    knownIP
      ? `https://ipinfo.io/${encodeURIComponent(knownIP)}/json`
      : "https://ipinfo.io/json"
  ];

  const textSources = [
    "https://v6.ident.me",
    "https://v4.ident.me"
  ];

  const [jsonResults, textResults] = await Promise.all([
    Promise.allSettled(jsonSources.map(url => fetchJSON(url))),
    Promise.allSettled(textSources.map(url => fetchText(url)))
  ]);

  const ipv4 = new Set();
  const ipv6 = new Set();
  let ispInfo = null;
  const rawResponses = [];

  const addIP = (ip) => {
    if (!ip) return;
    if (isIPv4(ip)) ipv4.add(ip);
    else if (isIPv6(ip)) ipv6.add(ip);
  };

  for (const result of jsonResults) {
    if (result.status !== "fulfilled" || !result.value) continue;
    const res = result.value;

    addIP(res.ip);
    addIP(res.ip_addr);

    if (res.org && !ispInfo) {
      ispInfo = {
        org: res.org,
        city: res.city || "",
        country: res.country || ""
      };
    }

    if (isVerbose) rawResponses.push(res);
  }

  for (const result of textResults) {
    if (result.status !== "fulfilled" || !result.value) continue;
    addIP(result.value);
    if (isVerbose) rawResponses.push({ plain: result.value });
  }

  return {
    publicIPv4: [...ipv4],
    publicIPv6: [...ipv6],
    isp: ispInfo,
    rawResponses: isVerbose ? rawResponses : undefined
  };
}

// ---------- Proxy / VPN Detection ----------
const DATACENTER_KEYWORDS = [
  "amazon", "aws",
  "google",
  "microsoft", "azure",
  "digitalocean",
  "cloudflare",
  "linode", "akamai",
  "vultr",
  "hetzner",
  "ovh",
  "fastly",
  "choopa",
  "leaseweb",
  "psychz",
  "zenlayer",
  "datacamp",
  "hostroyale",
  "quadranet",
  "colocrossing",
  "tzulo",
  "sharktech",
  "m247"
];

const VPN_PROVIDER_KEYWORDS = [
  "nordvpn", "nord vpn",
  "expressvpn", "express vpn",
  "surfshark",
  "protonvpn", "proton vpn",
  "mullvad",
  "private internet access", "pia",
  "cyberghost",
  "ipvanish",
  "tunnelbear",
  "windscribe",
  "hidemyass", "hma",
  "purevpn",
  "vyprvpn",
  "perfect privacy",
  "hide.me",
  "safervpn",
  "ivpn",
  "airvpn",
  "trust.zone"
];

function detectProxy(ipv4List, ipv6List, isp) {
  const signals = [];

  if (ipv4List.length > 1 || ipv6List.length > 1) {
    signals.push("Multiple distinct public IPs returned by providers");
  }

  if (isp && isp.org) {
    const org = isp.org.toLowerCase();

    const vpnHit = VPN_PROVIDER_KEYWORDS.find(kw => org.includes(kw));
    if (vpnHit) {
      signals.push(`VPN provider ASN detected (${isp.org})`);
    } else {
      const dcHit = DATACENTER_KEYWORDS.find(kw => org.includes(kw));
      if (dcHit) {
        signals.push(`Datacenter ASN detected (${isp.org})`);
      }
    }
  }

  return signals.length
    ? { status: "LIKELY YES", signals }
    : { status: "LIKELY NO", signals: [] };
}

// ---------- Output Helpers ----------
function printList(label, items, emptyMsg = "None") {
  console.log(`\n${label}:`);
  if (items && items.length) {
    items.forEach(i => console.log("  - " + i));
  } else {
    console.log("  " + emptyMsg);
  }
}

// ---------- Main ----------
(async () => {
  const result = {};
  const platform = os.platform();

  const local = getLocalIPsFromOS();
  result.privateIPv4 = local.ipv4;
  result.privateIPv6 = local.ipv6;

  if (local.ipv4.length === 0 && local.ipv6.length === 0) {
    const fallback = await getLocalIPsFromCommands(platform);
    result.fallback = fallback;
  }

  result.gateway = await getDefaultGateway(platform);

  const hasInternet = await checkInternet();
  result.internet = hasInternet;

  if (hasInternet) {
    // STUN first (gives true egress IP, post-CGNAT).
    const stun = await discoverPublicIPsViaStun();
    const stunIP = stun.ipv4 || stun.ipv6;

    // HTTPS APIs for ISP metadata. If STUN succeeded, we pass the STUN IP
    // to ipinfo.io so the ISP lookup matches the IP we're actually showing.
    const { publicIPv4, publicIPv6, isp, rawResponses } =
      await getPublicAndISPInfo(stunIP);

    // STUN-first: STUN IPs win, HTTPS fills gaps only.
    const finalIPv4 = stun.ipv4 ? [stun.ipv4] : publicIPv4;
    const finalIPv6 = stun.ipv6 ? [stun.ipv6] : publicIPv6;

    result.publicIPv4 = finalIPv4;
    result.publicIPv6 = finalIPv6;
    if (isp) result.isp = isp;
    result.proxy = detectProxy(finalIPv4, finalIPv6, isp);
    if (isVerbose) {
      result.stun = stun;
      if (rawResponses) result.rawResponses = rawResponses;
    }
  } else {
    result.note = "Offline mode";
  }

  // ---------- JSON Output ----------
  if (isJSON) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  // ---------- Human Output ----------
  console.log(`\n🔍 iplens v${VERSION}`);

  if (hasInternet) {
    printList("Public IPv4", result.publicIPv4, "None detected");
    printList("Public IPv6", result.publicIPv6, "None detected");

    printList("Private IPv4", result.privateIPv4);
    printList("Private IPv6", result.privateIPv6);

    if (result.gateway) {
      console.log(`\nGateway: ${result.gateway}`);
    }

    if (result.isp) {
      console.log(`\nISP: ${result.isp.org || "N/A"}`);
      const loc = [result.isp.city, result.isp.country].filter(Boolean).join(", ");
      if (loc) console.log(`Location: ${loc}`);
    }

    console.log(`\nProxy/VPN: ${result.proxy.status}`);
    if (result.proxy.signals.length && (isVerbose || result.proxy.status === "LIKELY YES")) {
      console.log("Signals:");
      result.proxy.signals.forEach(s => console.log("  - " + s));
    }
  } else {
    console.log("\nInternet: OFFLINE");

    printList("Private IPv4", result.privateIPv4);
    printList("Private IPv6", result.privateIPv6);

    if (result.gateway) {
      console.log(`\nGateway: ${result.gateway}`);
    }

    if (result.fallback) {
      if (result.fallback.success) {
        console.log("\nFallback (raw network output):");
        console.log(result.fallback.raw.substring(0, 800));
      } else {
        console.log("\nFallback failed:");
        console.log("  Error:", result.fallback.error);
        console.log("  Hint:", result.fallback.hint);
      }
    }

    console.log("\nPublic info not available (offline)");
  }

  if (isVerbose) {
    if (result.stun) {
      console.log("\nSTUN probe:");
      console.log("  IPv4:", result.stun.ipv4 || "no response");
      console.log("  IPv6:", result.stun.ipv6 || "no response");
    }
    if (result.rawResponses) {
      console.log("\nRaw API Responses:");
      console.log(JSON.stringify(result.rawResponses, null, 2));
    }
  }

  console.log("");
})().catch(err => {
  if (isJSON) {
    console.error(JSON.stringify({ error: err.message }));
  } else {
    console.error(`\n❌ Fatal error: ${err.message}\n`);
  }
  process.exit(1);
});