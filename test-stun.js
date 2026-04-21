// Unit test: feed a hand-crafted STUN Binding Success response to the parser
// and verify it extracts the right IP. This is the only way to validate the
// parser without hitting a real STUN server.

const crypto = require("crypto");

// Copy parser definitions from index.js
const STUN_MAGIC_COOKIE = 0x2112A442;
const STUN_BINDING_SUCCESS = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS = 0x0020;
const ATTR_MAPPED_ADDRESS = 0x0001;

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
      curStart = -1; curLen = 0;
    }
  }
  if (bestLen < 2) return parts.join(":");
  const head = parts.slice(0, bestStart).join(":");
  const tail = parts.slice(bestStart + bestLen).join(":");
  return `${head}::${tail}`;
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
        const bytes = xor ? raw.map((b, i) => b ^ msg[4 + i]) : raw;
        return {
          family: "IPv4",
          address: `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`,
          port: xor ? port ^ (STUN_MAGIC_COOKIE >>> 16) : port
        };
      } else if (family === 0x02) {
        const raw = msg.slice(valueStart + 4, valueStart + 20);
        const bytes = Buffer.alloc(16);
        if (xor) {
          for (let i = 0; i < 16; i++) bytes[i] = raw[i] ^ msg[4 + i];
        } else {
          raw.copy(bytes);
        }
        const parts = [];
        for (let i = 0; i < 16; i += 2) parts.push(bytes.readUInt16BE(i).toString(16));
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

// ---------- Test helpers ----------
function buildResponse(txnId, attrType, family, ip, port) {
  // Attribute value
  let attrValue;
  if (family === 0x01) {
    // IPv4: 1 byte reserved + 1 byte family + 2 bytes port + 4 bytes address
    attrValue = Buffer.alloc(8);
    attrValue.writeUInt8(0, 0); // reserved
    attrValue.writeUInt8(family, 1);

    if (attrType === ATTR_XOR_MAPPED_ADDRESS) {
      attrValue.writeUInt16BE(port ^ (STUN_MAGIC_COOKIE >>> 16), 2);
      const cookieBuf = Buffer.alloc(4);
      cookieBuf.writeUInt32BE(STUN_MAGIC_COOKIE, 0);
      const octets = ip.split(".").map(Number);
      for (let i = 0; i < 4; i++) attrValue[4 + i] = octets[i] ^ cookieBuf[i];
    } else {
      attrValue.writeUInt16BE(port, 2);
      const octets = ip.split(".").map(Number);
      for (let i = 0; i < 4; i++) attrValue[4 + i] = octets[i];
    }
  } else {
    // IPv6: 20 bytes
    attrValue = Buffer.alloc(20);
    attrValue.writeUInt8(0, 0);
    attrValue.writeUInt8(family, 1);
    attrValue.writeUInt16BE(port ^ (STUN_MAGIC_COOKIE >>> 16), 2);

    // Expand IPv6
    const parts = ip.split(":");
    const expanded = Array(8).fill("0");
    const dblIdx = parts.indexOf("");
    if (dblIdx !== -1) {
      const before = parts.slice(0, dblIdx).filter(p => p !== "");
      const after = parts.slice(dblIdx + 1).filter(p => p !== "");
      for (let i = 0; i < before.length; i++) expanded[i] = before[i];
      for (let i = 0; i < after.length; i++) expanded[8 - after.length + i] = after[i];
    } else {
      for (let i = 0; i < parts.length; i++) expanded[i] = parts[i];
    }
    const ipBuf = Buffer.alloc(16);
    for (let i = 0; i < 8; i++) ipBuf.writeUInt16BE(parseInt(expanded[i], 16), i * 2);

    const xorKey = Buffer.alloc(16);
    Buffer.alloc(4).writeUInt32BE(STUN_MAGIC_COOKIE, 0);
    xorKey.writeUInt32BE(STUN_MAGIC_COOKIE, 0);
    txnId.copy(xorKey, 4);
    for (let i = 0; i < 16; i++) attrValue[4 + i] = ipBuf[i] ^ xorKey[i];
  }

  // Attribute header
  const attr = Buffer.alloc(4 + attrValue.length);
  attr.writeUInt16BE(attrType, 0);
  attr.writeUInt16BE(attrValue.length, 2);
  attrValue.copy(attr, 4);

  // STUN header
  const header = Buffer.alloc(20);
  header.writeUInt16BE(STUN_BINDING_SUCCESS, 0);
  header.writeUInt16BE(attr.length, 2);
  header.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
  txnId.copy(header, 8);

  return Buffer.concat([header, attr]);
}

// ---------- Run tests ----------
let failed = 0;
function assert(name, actual, expected) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  console.log(`${pass ? "✓" : "✗"} ${name}`);
  if (!pass) {
    console.log(`    expected: ${JSON.stringify(expected)}`);
    console.log(`    actual:   ${JSON.stringify(actual)}`);
    failed++;
  }
}

// Test 1: XOR-MAPPED-ADDRESS IPv4
{
  const txnId = crypto.randomBytes(12);
  const resp = buildResponse(txnId, ATTR_XOR_MAPPED_ADDRESS, 0x01, "208.54.104.184", 54321);
  const parsed = parseStunResponse(resp, txnId);
  assert("XOR-MAPPED IPv4 parses correctly", parsed, {
    family: "IPv4", address: "208.54.104.184", port: 54321
  });
}

// Test 2: Legacy MAPPED-ADDRESS IPv4 (no XOR)
{
  const txnId = crypto.randomBytes(12);
  const resp = buildResponse(txnId, ATTR_MAPPED_ADDRESS, 0x01, "192.168.1.100", 3478);
  const parsed = parseStunResponse(resp, txnId);
  assert("Legacy MAPPED IPv4 parses correctly", parsed, {
    family: "IPv4", address: "192.168.1.100", port: 3478
  });
}

// Test 3: XOR-MAPPED-ADDRESS IPv6
{
  const txnId = crypto.randomBytes(12);
  const resp = buildResponse(txnId, ATTR_XOR_MAPPED_ADDRESS, 0x02, "2001:db8::1", 1234);
  const parsed = parseStunResponse(resp, txnId);
  assert("XOR-MAPPED IPv6 parses correctly", parsed, {
    family: "IPv6", address: "2001:db8::1", port: 1234
  });
}

// Test 4: Rejects wrong transaction ID
{
  const txnId = crypto.randomBytes(12);
  const wrongTxn = crypto.randomBytes(12);
  const resp = buildResponse(txnId, ATTR_XOR_MAPPED_ADDRESS, 0x01, "1.2.3.4", 100);
  const parsed = parseStunResponse(resp, wrongTxn);
  assert("Rejects mismatched transaction ID", parsed, null);
}

// Test 5: Rejects too-short message
{
  const parsed = parseStunResponse(Buffer.alloc(10), Buffer.alloc(12));
  assert("Rejects message shorter than 20 bytes", parsed, null);
}

// Test 6: Rejects wrong magic cookie
{
  const txnId = crypto.randomBytes(12);
  const resp = buildResponse(txnId, ATTR_XOR_MAPPED_ADDRESS, 0x01, "1.2.3.4", 100);
  resp.writeUInt32BE(0xDEADBEEF, 4); // corrupt magic cookie
  const parsed = parseStunResponse(resp, txnId);
  assert("Rejects wrong magic cookie", parsed, null);
}

// Test 7: IPv6 compression — full address
{
  const input = "2001:0db8:0000:0000:0000:0000:0000:0001";
  const parts = input.split(":").map(p => parseInt(p, 16).toString(16));
  const compressed = compressIPv6(parts.join(":"));
  assert("IPv6 compression (full zero run)", compressed, "2001:db8::1");
}

// Test 8: IPv6 compression — no zeros
{
  const compressed = compressIPv6("2001:db8:1:2:3:4:5:6");
  assert("IPv6 compression (no zeros)", compressed, "2001:db8:1:2:3:4:5:6");
}

console.log(`\n${failed === 0 ? "✅ all tests passed" : `❌ ${failed} test(s) failed`}`);
process.exit(failed === 0 ? 0 : 1);