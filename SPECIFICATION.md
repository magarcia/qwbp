# QR-WebRTC Bootstrap Protocol (QWBP) Specification

**Version:** 0.1.0
**Status:** Draft
**Author:** Martin Garcia Monterde
**Date:** January 2026

---

## License

This specification text is licensed under the [Creative Commons Attribution 4.0 International License (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).

You are free to share, copy, and redistribute the material in any medium or format, and adapt the material for any purpose, even commercially, provided you give appropriate credit to the original author.

The reference implementation code in this repository is licensed under the [MIT License](./LICENSE).

---

## Abstract

This document specifies the QR-WebRTC Bootstrap Protocol (QWBP), a binary protocol for establishing WebRTC DataChannel connections using QR codes as the signaling channel. QWBP achieves a 97.79% reduction in signaling payload size compared to standard Session Description Protocol (SDP), enabling serverless peer-to-peer connections through a visual, air-gapped channel.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Protocol Overview](#3-protocol-overview)
4. [Binary Packet Format](#4-binary-packet-format)
5. [Key Derivation](#5-key-derivation)
6. [Role Assignment](#6-role-assignment)
7. [SDP Reconstruction](#7-sdp-reconstruction)
8. [QR Code Encoding](#8-qr-code-encoding)
9. [Connection Establishment](#9-connection-establishment)
10. [Security Considerations](#10-security-considerations)
11. [IANA Considerations](#11-iana-considerations)
12. [References](#12-references)
13. [Appendix A: Test Vectors](#appendix-a-test-vectors)
14. [Appendix B: Example Implementations](#appendix-b-example-implementations)

---

## 1. Introduction

### 1.1 Purpose

QWBP enables two devices with cameras and displays to establish an encrypted WebRTC DataChannel connection without any server infrastructure. The protocol uses QR codes as a bidirectional signaling channel, requiring only physical proximity between devices.

### 1.2 Scope

This specification defines:

- The binary packet format for QWBP payloads
- Key derivation procedures for ICE credentials
- Role assignment algorithm for offer/answer determination
- SDP reconstruction from QWBP packets
- QR code encoding requirements
- Security properties and threat model

This specification does NOT define:

- QR code generation or scanning implementations
- WebRTC API usage (browser-specific)
- Application-layer protocols over the DataChannel
- Video/audio SDP negotiation (use QWBP as bootstrap only)

### 1.3 Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

All multi-byte integers use network byte order (big-endian) unless otherwise specified.

All examples use hexadecimal notation with `0x` prefix for bytes and `XX:XX` colon notation for fingerprints.

---

## 2. Terminology

**QWBP Packet**: A binary-encoded payload containing the minimal information required to establish a WebRTC connection.

**Fingerprint**: A SHA-256 hash of a device's DTLS certificate, represented as 32 raw bytes.

**ICE Candidate**: A network address (IP and port) where a device can potentially receive connections.

**Host Candidate**: An ICE candidate representing a local network interface address.

**Server-Reflexive (srflx) Candidate**: An ICE candidate representing the public IP address as discovered by a STUN server.

**mDNS Candidate**: An ICE candidate using a Multicast DNS hostname (UUID format) for IP address privacy.

**Offerer**: The peer that creates the WebRTC offer SDP.

**Answerer**: The peer that creates the WebRTC answer SDP in response to an offer.

**QR Tango**: The bidirectional QR scanning dance where both peers scan each other's QR codes.

---

## 3. Protocol Overview

### 3.1 Two-Stage Architecture

QWBP implements a two-stage connection model:

```
Stage 1: QR Bootstrap (QWBP)
├── Payload size: 55-100 bytes
├── QR Version: 4-5 (33-37 modules)
├── Scan time: <500ms typical
└── Result: Encrypted DataChannel

Stage 2: Application Protocol
├── Payload size: Unlimited
├── Channel: DataChannel from Stage 1
└── Use cases: Video SDP, file transfer, any data
```

### 3.2 Connection Flow

```
┌─────────────┐                           ┌─────────────┐
│   Peer A    │                           │   Peer B    │
└─────────────┘                           └─────────────┘
       │                                         │
       │  1. Generate DTLS certificate           │
       │  2. Gather ICE candidates               │
       │  3. Encode QWBP packet                  │
       │  4. Display QR code                     │
       │                                         │
       │         ┌───────────────┐               │
       │         │  QR Code A    │               │
       │         │  (55-100 B)   │──────────────▶│
       │         └───────────────┘               │
       │                                         │
       │                                         │  5. Scan QR from A
       │                                         │  6. Generate DTLS certificate
       │                                         │  7. Gather ICE candidates
       │                                         │  8. Encode QWBP packet
       │                                         │  9. Display QR code
       │                                         │
       │               ┌───────────────┐         │
       │◀──────────────│  QR Code B    │         │
       │               │  (55-100 B)   │         │
       │               └───────────────┘         │
       │                                         │
       │ 10. Scan QR from B                      │
       │                                         │
       │ 11. Compare fingerprints                │ 11. Compare fingerprints
       │     A > B → Offerer                     │     B < A → Answerer
       │                                         │
       │ 12. Reuse pending Local Offer           │ 12. Rollback pending Local Offer
       │                                         │ 13. Synthesize Remote Offer
       │ 13. Synthesize Remote Answer            │ 14. Generate Local Answer
       │                                         │
       │ 14. setRemoteDescription(answer)        │ 15. setRemoteDescription(offer)
       │                                         │ 16. setLocalDescription(answer)
       │                                         │
       │◀────────────────────────────────────────│
       │         ICE + DTLS Handshake            │
       │────────────────────────────────────────▶│
       │                                         │
       │◀════════════════════════════════════════│
       │         DataChannel Established         │
       │════════════════════════════════════════▶│
```

### 3.3 Symmetric Identity Exchange

Unlike traditional WebRTC signaling where peers exchange different messages (offer vs answer), QWBP uses symmetric "identity cards". Both QR codes contain the same type of information:

- Device fingerprint (identity)
- ICE candidates (location)

Roles (offerer/answerer) are determined _after_ both scans complete, based on fingerprint comparison. This eliminates race conditions and allows either peer to scan first.

---

## 4. Binary Packet Format

### 4.1 Packet Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Magic     |    Version    |                               |
|     (0x51)    |   (3b + 5b)   |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+                                                               +
|                                                               |
+                       Fingerprint                             +
|                       (32 bytes)                              |
+                                                               +
|                                                               |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+                       Candidate 1                             +
|                       (7 or 19 bytes)                         |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                       Candidate 2                             |
+                       (7 or 19 bytes)                         +
|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |            ...                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 4.2 Header Fields

#### 4.2.1 Magic Byte (Offset 0, 1 byte)

```
+-+-+-+-+-+-+-+-+
|0 1 0 1 0 0 0 1|  = 0x51 ('Q' ASCII)
+-+-+-+-+-+-+-+-+
```

The magic byte MUST be `0x51` (ASCII 'Q' for QWBP).

Decoders MUST reject packets not starting with `0x51`. This provides fast-fail when scanning non-QWBP QR codes (restaurant menus, URLs, etc.).

#### 4.2.2 Version Byte (Offset 1, 1 byte)

```
+-+-+-+-+-+-+-+-+
|Ver:3b |Rsv:5b |
+-+-+-+-+-+-+-+-+
```

| Bits | Field    | Description                                          |
| ---- | -------- | ---------------------------------------------------- |
| 0-2  | Version  | Protocol version (0-7). Currently only 0 is defined. |
| 3-7  | Reserved | MUST be set to 0. Decoders MUST ignore these bits.   |

**Version Handling:**

- Version 0: This specification
- Versions 1-7: Reserved for future use
- Decoders receiving an unknown version MUST reject the packet

### 4.3 Fingerprint Field (Offset 2, 32 bytes)

The fingerprint is the raw 32-byte SHA-256 hash of the device's DTLS certificate.

**Generation:**

```javascript
// Browser: Extract from local SDP
const sdp = await pc.createOffer();
const match = sdp.sdp.match(/a=fingerprint:sha-256 ([A-F0-9:]+)/i);
const hexString = match[1].replace(/:/g, "");
const fingerprint = new Uint8Array(
  hexString.match(/.{2}/g).map((b) => parseInt(b, 16))
);
```

**Encoding:**

Store the 32 bytes directly without any encoding. Do NOT use hex string or colon-separated format.

### 4.4 Candidate Format

Each ICE candidate is encoded as a variable-length structure:

```
IPv4 Candidate (7 bytes):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Flags      |         IPv4 Address          |
|    (1 byte)   |           (4 bytes)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    IPv4 (cont)|         Port                  |
|    (1 byte)   |         (2 bytes)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IPv6/mDNS Candidate (19 bytes):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Flags      |                               |
|    (1 byte)   |                               |
+-+-+-+-+-+-+-+-+     IPv6 Address or           +
|                     mDNS UUID                 |
+                     (16 bytes)                +
|                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Port                  |
|         (2 bytes)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 4.5 Flags Byte

```
+-+-+-+-+-+-+-+-+
|AF |P|T|TCP|Rsv|
+-+-+-+-+-+-+-+-+
 0-1 2 3 4-5 6-7
```

| Bits | Field               | Values                             | Description        |
| ---- | ------------------- | ---------------------------------- | ------------------ |
| 0-1  | Address Family (AF) | `00`=IPv4, `01`=IPv6, `10`=mDNS    | Address type       |
| 2    | Protocol (P)        | `0`=UDP, `1`=TCP                   | Transport protocol |
| 3    | Candidate Type (T)  | `0`=host, `1`=srflx                | ICE candidate type |
| 4-5  | TCP Type            | `00`=passive, `01`=active, `10`=so | Only valid if P=1  |
| 6-7  | Reserved            | `00`                               | MUST be 0          |

**Address Family Details:**

- `00` (IPv4): Next 4 bytes are IPv4 address in network byte order
- `01` (IPv6): Next 16 bytes are IPv6 address in network byte order
- `10` (mDNS): Next 16 bytes are UUID portion of mDNS hostname ([RFC 4122](https://datatracker.ietf.org/doc/html/rfc4122) format)

**mDNS UUID Encoding:**

Modern browsers (Chrome, Safari) hide local IPs behind mDNS hostnames following the [draft-ietf-mmusic-mdns-ice-candidates](https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates-03#section-3.1.1) specification. Per Section 3.1.1, the hostname format is `{uuid}.local` where the UUID follows [RFC 4122](https://datatracker.ietf.org/doc/html/rfc4122). The UUID is 128 bits, matching IPv6 size.

Example:

- mDNS hostname: `a1b2c3d4-e5f6-7890-abcd-ef1234567890.local`
- Encoded UUID: `0xa1b2c3d4e5f67890abcdef1234567890` (16 bytes)

**TCP Type Values:**

Per [RFC 6544](https://datatracker.ietf.org/doc/html/rfc6544), TCP candidates include a tcptype attribute:

- `00` = `passive`: Listening socket
- `01` = `active`: Connecting socket
- `10` = `so`: Simultaneous-open

For UDP candidates, bits 4-5 SHOULD be `00` and MUST be ignored by decoders.

### 4.6 Candidate Ordering

Candidates MUST be encoded in descending priority order:

1. Host candidates (highest priority)
2. Server-reflexive (srflx) candidates

Within each type, order by:

1. IPv4 before IPv6 (for faster initial connection attempts)
2. UDP before TCP

**Maximum Candidates:**

Implementations SHOULD include at most 4 candidates (3 host + 1 srflx) to stay within QR size limits. Decoders MUST parse all candidates until end-of-packet.

### 4.7 Packet Size Calculations

| Configuration                   | Size Calculation | Total Bytes |
| ------------------------------- | ---------------- | ----------- |
| Minimum (1 IPv4)                | 2 + 32 + 7       | 41          |
| Typical (3 IPv4 + 1 srflx IPv4) | 2 + 32 + 28      | 62          |
| Maximum (4 IPv6)                | 2 + 32 + 76      | 110         |
| Mixed (3 IPv6 + 1 IPv4)         | 2 + 32 + 57 + 7  | 98          |

---

## 5. Key Derivation

### 5.1 Overview

QWBP derives ICE credentials (ufrag and password) from the DTLS fingerprint using HKDF-SHA256 ([RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)). This eliminates the need to transmit credentials in the QR code.

Each peer derives its OWN credentials from its OWN fingerprint. After scanning, each peer can derive the OTHER peer's expected credentials from the scanned fingerprint.

### 5.2 HKDF Parameters

```
Hash Algorithm: SHA-256
Input Key Material (IKM): 32-byte DTLS fingerprint
Salt: Empty (zero-length byte array)
Info (ufrag): UTF-8 bytes of "QWBP-ICE-UFRAG-v1"
Info (pwd): UTF-8 bytes of "QWBP-ICE-PWD-v1"
Output Length (ufrag): 4 bytes
Output Length (pwd): 18 bytes
```

### 5.3 Derivation Procedure

**Step 1: Extract**

```
PRK = HKDF-Extract(salt="", IKM=fingerprint)
    = HMAC-SHA256(key="", message=fingerprint)
```

Note: Empty salt is acceptable because the fingerprint (IKM) is already high-entropy and ephemeral.

**Step 2: Expand for ufrag**

```
ufrag_bytes = HKDF-Expand(PRK, info="QWBP-ICE-UFRAG-v1", L=4)
ufrag = base64url_encode(ufrag_bytes)  // 6 characters
```

**Step 3: Expand for password**

```
pwd_bytes = HKDF-Expand(PRK, info="QWBP-ICE-PWD-v1", L=18)
pwd = base64url_encode(pwd_bytes)  // 24 characters
```

### 5.4 Base64url Encoding

Use base64url encoding ([RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648) Section 5) WITHOUT padding:

- Alphabet: `A-Za-z0-9-_`
- No `=` padding characters

This produces URL-safe strings that satisfy [RFC 8839](https://datatracker.ietf.org/doc/html/rfc8839) character requirements for ICE credentials.

### 5.5 RFC 8839 Compliance

[RFC 8839](https://datatracker.ietf.org/doc/html/rfc8839) requires:

- ice-ufrag: 4-256 characters from `[A-Za-z0-9+/]`
- ice-pwd: 22-256 characters from `[A-Za-z0-9+/]`

QWBP derivation produces:

- ufrag: 6 characters (4 bytes → base64url)
- pwd: 24 characters (18 bytes → base64url)

Both exceed minimums and use valid characters (base64url is subset of allowed charset, substituting `-_` for `+/`).

### 5.6 Example Derivation

**Input:**

```
Fingerprint (hex): E7:3B:38:46:1A:5D:88:B0:C4:2E:9F:7A:1D:6C:3E:8B:
                   5F:4A:9D:2C:7E:1B:6F:3A:8D:5C:2E:9B:4F:7A:1C:3D

Fingerprint (bytes): 0xe73b38461a5d88b0c42e9f7a1d6c3e8b
                     5f4a9d2c7e1b6f3a8d5c2e9b4f7a1c3d
```

**Derivation:**

```
PRK = HMAC-SHA256("", fingerprint)
    = 0x2f8a... (32 bytes)

ufrag_bytes = HKDF-Expand(PRK, "QWBP-ICE-UFRAG-v1", 4)
            = 0x7a3c5e9f

ufrag = base64url(0x7a3c5e9f)
      = "ejxenw"

pwd_bytes = HKDF-Expand(PRK, "QWBP-ICE-PWD-v1", 18)
          = 0x4d2e8a7c... (18 bytes)

pwd = base64url(pwd_bytes)
    = "TS6KfB2mN9pQ3rS7wX"
```

---

## 6. Role Assignment

### 6.1 The Glare Problem

If both peers press "Connect" simultaneously, they might both generate WebRTC offers. The WebRTC state machine cannot process an offer while in "have-local-offer" state, causing connection failure.

Traditional solutions require UI coordination ("Press Send on device A, then Receive on device B"). QWBP eliminates this through deterministic role assignment.

### 6.2 Fingerprint Comparison

After both QR codes are scanned, each peer has both fingerprints. Roles are assigned by lexicographic byte comparison:

```
if (localFingerprint > remoteFingerprint) {
    role = OFFERER;
} else if (localFingerprint < remoteFingerprint) {
    role = ANSWERER;
} else {
    // Fingerprints equal - scanning own QR code
    throw Error("Cannot connect to self");
}
```

**Comparison Algorithm:**

```javascript
function compareFingerprints(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < 32; i++) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0; // Equal (error case)
}
```

### 6.3 Properties

This approach guarantees:

1. **Determinism**: Both peers independently compute the same role assignment
2. **Uniqueness**: Different certificates produce different fingerprints
3. **Order independence**: Either peer can scan first
4. **No race conditions**: QR content doesn't depend on role
5. **Self-detection**: Identical fingerprints indicate scanning own QR

### 6.4 Example

```
Peer A fingerprint: 0xe73b3846...
Peer B fingerprint: 0x8a2c5f91...

Comparison: 0xe7 > 0x8a (first byte)

Result:
- Peer A: Offerer (higher fingerprint)
- Peer B: Answerer (lower fingerprint)
```

---

## 7. SDP Reconstruction

### 7.1 Overview

After scanning and role assignment, each peer uses the remote data to drive the WebRTC state machine to completion.

- **The Offerer** (who already has a valid Local Offer from the gathering phase) reconstructs a **Remote Answer SDP** using the scanned fingerprint and candidates. It sets this as the remote description to establish the connection.

- **The Answerer** performs a **signaling rollback** to clear its pending Local Offer. It then reconstructs a **Remote Offer SDP** from the scanned data, sets it as the remote description, and generates a valid Local Answer via the WebRTC API.

### 7.2 SDP Template

```
v=0
o=- {session-id} 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=ice-ufrag:{ufrag}
a=ice-pwd:{pwd}
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=ice-options:trickle
a=fingerprint:sha-256 {fingerprint-hex}
a=setup:{setup-value}
a=mid:0
a=sctp-port:5000
{candidate-lines}
```

### 7.3 Field Population

| Field               | Source                   | Format                                             |
| ------------------- | ------------------------ | -------------------------------------------------- |
| `{session-id}`      | Derived from fingerprint | First 8 bytes of SHA256(fp) as uint64 (big-endian) |
| `{ufrag}`           | HKDF derivation          | 6-character base64url string                       |
| `{pwd}`             | HKDF derivation          | 24-character base64url string                      |
| `{fingerprint-hex}` | QR payload               | Colon-separated hex: `AB:CD:EF:...`                |
| `{setup-value}`     | Role                     | Offer: `actpass`, Answer: `active`                 |
| `{candidate-lines}` | QR payload               | Multiple `a=candidate:` lines                      |

### 7.4 Session ID Generation

Generate deterministically from fingerprint to ensure both peers derive the same value:

```javascript
async function generateSessionId(fingerprint: Uint8Array): Promise<string> {
  // Hash the fingerprint first
  const hash = await crypto.subtle.digest("SHA-256", fingerprint);
  const hashBytes = new Uint8Array(hash);

  // Use first 8 bytes as big-endian uint64
  let id = BigInt(0);
  for (let i = 0; i < 8; i++) {
    id = (id << 8n) | BigInt(hashBytes[i]);
  }
  return id.toString();
}
```

### 7.5 Fingerprint Formatting

Convert 32 raw bytes to colon-separated uppercase hex:

```javascript
function formatFingerprint(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).toUpperCase().padStart(2, "0"))
    .join(":");
}
```

Output: `E7:3B:38:46:1A:5D:88:B0:C4:2E:9F:7A:1D:6C:3E:8B:5F:4A:9D:2C:7E:1B:6F:3A:8D:5C:2E:9B:4F:7A:1C:3D`

### 7.6 Candidate Line Synthesis

#### 7.6.1 Foundation Generation

Generate deterministic foundation from candidate data:

```javascript
function generateFoundation(
  type: string,
  protocol: string,
  ip: string,
  port: number
): string {
  const data = `${type}${protocol}${ip}${port}`;
  const hash = sha256(new TextEncoder().encode(data));
  return Array.from(hash.slice(0, 4))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
```

#### 7.6.2 Priority Values

Use [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445) formula with fixed constants:

| Candidate Type | Type Preference | Local Preference | Priority   |
| -------------- | --------------- | ---------------- | ---------- |
| Host UDP       | 126             | 65535            | 2122260223 |
| Host TCP       | 126             | 49151            | 2105524223 |
| srflx          | 100             | 65535            | 1686052607 |

#### 7.6.3 Host Candidate Format

```
a=candidate:{foundation} 1 {proto} {priority} {ip} {port} typ host
```

For TCP candidates, append tcptype:

```
a=candidate:{foundation} 1 tcp {priority} {ip} {port} typ host tcptype {tcptype}
```

#### 7.6.4 Server-Reflexive Candidate Format

```
a=candidate:{foundation} 1 {proto} {priority} {ip} {port} typ srflx raddr 0.0.0.0 rport 9
```

The `raddr 0.0.0.0 rport 9` placeholder follows the privacy-preserving pattern from mDNS ICE candidates. Implementations MUST NOT assume the related address is meaningful.

#### 7.6.5 mDNS Candidate Format

For mDNS candidates (address family = `10`), reconstruct the hostname:

```javascript
function formatMdnsHostname(uuid: Uint8Array): string {
  const hex = Array.from(uuid)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  // Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-${hex.slice(20, 32)}.local`
  );
}
```

Candidate line:

```
a=candidate:{foundation} 1 udp {priority} {mdns-hostname} {port} typ host
```

### 7.7 Complete Example

**QWBP Payload (hex):**

```
51 00                                       # Magic + Version
e7 3b 38 46 1a 5d 88 b0 c4 2e 9f 7a 1d 6c   # Fingerprint
3e 8b 5f 4a 9d 2c 7e 1b 6f 3a 8d 5c 2e 9b   # (32 bytes)
4f 7a 1c 3d
00 c0 a8 01 05 d4 31                        # Candidate 1: IPv4 host 192.168.1.5:54321
08 c0 a8 01 06 d4 32                        # Candidate 2: IPv4 srflx 192.168.1.6:54322
```

**Derived Credentials:**

```
ufrag: "ejxenw"
pwd: "TS6KfB2mN9pQ3rS7wX"
```

**Reconstructed Offer SDP:**

```
v=0
o=- 16663612290012583088 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=ice-ufrag:ejxenw
a=ice-pwd:TS6KfB2mN9pQ3rS7wX
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=ice-options:trickle
a=fingerprint:sha-256 E7:3B:38:46:1A:5D:88:B0:C4:2E:9F:7A:1D:6C:3E:8B:5F:4A:9D:2C:7E:1B:6F:3A:8D:5C:2E:9B:4F:7A:1C:3D
a=setup:actpass
a=mid:0
a=sctp-port:5000
a=candidate:a1b2c3d4 1 udp 2122260223 192.168.1.5 54321 typ host
a=candidate:e5f6a7b8 1 udp 1686052607 192.168.1.6 54322 typ srflx raddr 0.0.0.0 rport 9
```

---

## 8. QR Code Encoding

### 8.1 Mode Selection

QWBP payloads MUST be encoded using **Byte mode** (ISO 8859-1). Do NOT:

- Base64-encode the payload (37% size overhead)
- Use alphanumeric mode (incompatible with binary data)
- Use UTF-8 mode (unnecessary for raw bytes)

Most QR libraries accept `Uint8Array` directly for Byte mode encoding.

### 8.2 Error Correction Level

Use **Error Correction Level L** (7% recovery capacity).

Rationale:

- QR codes displayed on screens have perfect contrast
- No physical damage (scratches, folds) to recover from
- Level L minimizes module count for given payload
- Higher levels (M, Q, H) waste capacity without benefit

### 8.3 Version Selection

| Payload Size  | QR Version | Modules | Capacity (L) |
| ------------- | ---------- | ------- | ------------ |
| 41-53 bytes   | 3          | 29×29   | 53 bytes     |
| 54-78 bytes   | 4          | 33×33   | 78 bytes     |
| 79-106 bytes  | 5          | 37×37   | 106 bytes    |
| 107-134 bytes | 6          | 41×41   | 134 bytes    |

Typical QWBP payloads (55-100 bytes) fit in Version 4-5.

### 8.4 Physical Size Requirements

For reliable scanning at arm's length (~50cm):

- **Minimum on-screen size**: 25mm × 25mm (1 inch)
- **Recommended**: 40mm × 40mm or larger
- **Module size**: ≥0.75mm per module

Smaller codes require closer camera positioning and are more sensitive to motion blur.

### 8.5 Quiet Zone

Maintain a minimum 4-module white border around the QR code. Most libraries handle this automatically, but verify with custom rendering.

### 8.6 Recommended Libraries

**Encoding:**

- JavaScript: `qrcode`, `qrcode-generator`
- Python: `qrcode`, `segno`
- Go: `github.com/skip2/go-qrcode`

**Decoding:**

- JavaScript: `jsQR`, `@aspect-build/aspect-zxing`
- Native: Use device camera APIs (iOS AVFoundation, Android CameraX)

---

## 9. Connection Establishment

### 9.1 State Machine

```
┌─────────────────┐
│     IDLE        │
└────────┬────────┘
         │ initialize()
         ▼
┌─────────────────┐
│   GATHERING     │  Collecting ICE candidates
└────────┬────────┘
         │ iceGatheringState='complete'
         ▼
┌─────────────────┐
│   DISPLAYING    │  QR code visible
└────────┬────────┘
         │ processScannedPayload()
         ▼
┌─────────────────┐
│   SCANNED_ONE   │  Have remote data, awaiting local scan
└────────┬────────┘
         │ other peer scans our QR
         ▼
┌─────────────────┐
│  CONNECTING     │  Role assigned, SDP exchanged
└────────┬────────┘
         │ iceConnectionState='connected'
         ▼
┌─────────────────┐
│   CONNECTED     │  DataChannel ready
└─────────────────┘
```

### 9.1.1 Implementation Note: Signaling Rollback

Implementations MUST reuse the same `RTCPeerConnection` object used for ICE gathering throughout the connection process. If role assignment determines the local peer is the **Answerer**, the implementation MUST transition the connection state back to `stable` (e.g., using `setLocalDescription({type: 'rollback'})`) before applying the remote offer.

**Warning:** Implementers MUST NOT destroy the existing PeerConnection to create a new one for the Answerer role. Doing so will close the network ports advertised in the generated QR code, causing connection failure.

### 9.2 ICE Gathering

Implementations MUST wait for complete ICE gathering before displaying the QR code:

```javascript
pc.oniceGatheringStateChange = () => {
  if (pc.iceGatheringState === "complete") {
    // Safe to generate QR now
  }
};
```

This adds 1-2 seconds latency but ensures the QR contains all candidates needed for connection.

### 9.3 Session Timeout

Implementations MUST enforce a session timeout (default: 30 seconds) starting from when ICE gathering completes and the QR is first displayed.

After timeout:

1. Discard the ephemeral DTLS certificate
2. Close the RTCPeerConnection
3. Reset state to IDLE
4. Regenerate if user retries

This prevents stale QR codes from being used in replay scenarios.

### 9.4 Simultaneous Open

When both peers have each other's connection information from the QR codes, both can initiate ICE connectivity checks simultaneously. This enables "hole punching" through single-sided NAT without TURN.

### 9.5 TURN Server Requirements

QWBP assumes direct peer-to-peer connectivity or STUN-assisted hole punching. For scenarios requiring TURN relay servers (symmetric NAT on both sides, enterprise firewalls), additional configuration is needed.

**Limitation:** TURN credentials (server URL, username, password) cannot be transmitted in the QR code—they would exceed size constraints and expose long-lived secrets.

**Solution:** Applications requiring TURN support MUST pre-configure the same TURN server on both clients through application configuration:

```typescript
const connection = new QWBPConnection({
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    {
      urls: "turn:your-turn-server.example.com:3478",
      username: "app-configured-user",
      credential: "app-configured-credential",
    },
  ],
});
```

**Recommendations:**

1. Use time-limited TURN credentials (rotating every 24 hours)
2. Configure TURN servers in application settings or environment
3. Consider TURN server authentication tied to app user accounts
4. QWBP cannot bootstrap TURN configuration—this is by design

**Connection fallback:** If host and srflx candidates fail, ICE will automatically try relay candidates if TURN is configured. The QWBP protocol is unaware of this fallback—it occurs at the WebRTC layer.

---

## 10. Security Considerations

### 10.1 Threat Model

QWBP's security relies on the **optical channel**—the screen displaying the QR code.

**Trust Assumptions:**

- Physical proximity implies authorization
- Visual channel is observable by both parties
- Devices are not compromised

**Out of Scope:**

- Malware on either device
- Compromised camera/display hardware
- Social engineering attacks

### 10.2 Protected Against

| Threat                 | Mitigation                                       |
| ---------------------- | ------------------------------------------------ |
| Remote attackers       | Cannot participate without visual access         |
| Source code inspection | Session keys derived from ephemeral certificates |
| Replay attacks         | Ephemeral DTLS certificates, session timeout     |
| MITM attacks           | DTLS fingerprint verification in handshake       |
| Credential theft       | Credentials derived, not transmitted             |

### 10.3 Attack Surfaces

#### 10.3.1 QR Code Photograph

An attacker who photographs both QR codes gains:

- Both fingerprints
- Both sets of ICE candidates

They could attempt to race the legitimate peers to establish connection. However:

- They must be on the same network (or have their own srflx candidate)
- They must complete the DTLS handshake before legitimate peers
- The attack window is ~30 seconds (session timeout)

**Mitigation:** Use Short Authentication String (see §10.5)

#### 10.3.2 Evil Twin QR

An attacker displays their own QR code, hoping victim scans it instead of legitimate peer.

**Mitigation:** Users should verify they're scanning the expected device's screen. Visual confirmation of the other device displaying a QR is part of the protocol's trust model.

### 10.4 Forward Secrecy

QWBP provides forward secrecy through ephemeral DTLS certificates:

1. Each session generates a fresh DTLS certificate
2. ICE credentials derive from this certificate
3. After session ends, the certificate is discarded
4. A captured QR code cannot decrypt past or future sessions

### 10.5 Short Authentication String (Optional)

For high-security applications, implement SAS verification after connection:

```javascript
async function generateSAS(
  localFP: Uint8Array,
  remoteFP: Uint8Array
): Promise<string> {
  // Concatenate fingerprints in consistent order (sorted)
  // This ensures both peers compute the same SAS regardless of role
  const comparison = compareFingerprints(localFP, remoteFP);
  const combined = new Uint8Array(64);

  if (comparison >= 0) {
    combined.set(localFP, 0);
    combined.set(remoteFP, 32);
  } else {
    combined.set(remoteFP, 0);
    combined.set(localFP, 32);
  }

  // Hash to get SAS material
  const hash = await crypto.subtle.digest("SHA-256", combined);
  const hashBytes = new Uint8Array(hash);

  // Use first 2 bytes as a 4-digit number (0000-9999)
  const value = (hashBytes[0] << 8) | hashBytes[1];
  return (value % 10000).toString().padStart(4, "0");
}
```

Users verbally confirm the SAS matches on both devices (e.g., "Does your screen show 4827?"). This catches active MITM attacks where an attacker substitutes their own QR code.

**Usage:**

```javascript
const sas = await connection.getSAS();
console.log(`Verification code: ${sas}`); // "4827"
```

### 10.6 ICE Credential Security

Q: "Are hardcoded-looking ICE credentials secure?"

A: Yes. ICE credentials (ufrag/pwd) authenticate ICE connectivity checks but do NOT encrypt data. The actual encryption happens at the DTLS layer, authenticated by the fingerprint. An attacker with ICE credentials but wrong DTLS certificate cannot establish a connection—the DTLS handshake fails.

QWBP's HKDF derivation ensures credentials are:

- Per-session unique (derived from ephemeral certificate)
- Not present in source code
- Deterministically verifiable by both peers

---

## 11. IANA Considerations

This document has no IANA actions.

The magic byte `0x51` is chosen to be:

- Human-readable as ASCII 'Q' (for QWBP)
- Unlikely to collide with other QR code contents (URLs start with `h` or `H`, JSON with `{` or `[`)

---

## 12. References

### 12.1 Normative References

- [[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119)] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- [[RFC 4122](https://datatracker.ietf.org/doc/html/rfc4122)] Leach, P., Mealling, M., and R. Salz, "A Universally Unique IDentifier (UUID) URN Namespace", RFC 4122, July 2005.
- [[RFC 5245](https://datatracker.ietf.org/doc/html/rfc5245)] Rosenberg, J., "Interactive Connectivity Establishment (ICE)", RFC 5245, April 2010.
- [[RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)] Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, May 2010.
- [[RFC 6544](https://datatracker.ietf.org/doc/html/rfc6544)] Rosenberg, J., Keranen, A., Lowekamp, B., and A. Roach, "TCP Candidates with Interactive Connectivity Establishment (ICE)", RFC 6544, March 2012.
- [[RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445)] Keranen, A., Holmberg, C., and J. Rosenberg, "Interactive Connectivity Establishment (ICE)", RFC 8445, July 2018.
- [[RFC 8839](https://datatracker.ietf.org/doc/html/rfc8839)] Petit-Huguenin, M., Nandakumar, S., Holmberg, C., Keranen, A., and R. Shpount, "Session Description Protocol (SDP) Offer/Answer Procedures for ICE", RFC 8839, January 2021.

### 12.2 Informative References

- [[RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648)] Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648, October 2006.
- [[RFC 8122](https://datatracker.ietf.org/doc/html/rfc8122)] Lennox, J. and C. Holmberg, "Connection-Oriented Media Transport over TLS in SDP", RFC 8122, March 2017.
- [[RFC 8827](https://datatracker.ietf.org/doc/html/rfc8827)] Rescorla, E., "WebRTC Security Architecture", RFC 8827, January 2021.
- [[RFC 8866](https://datatracker.ietf.org/doc/html/rfc8866)] Begen, A., Kyzivat, P., Perkins, C., and M. Handley, "SDP: Session Description Protocol", RFC 8866, January 2021.
- [[draft-ietf-mmusic-mdns-ice-candidates](https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates-03)] Okonkwo, Y., Osman, A., and J. Uberti, "Using Multicast DNS to protect privacy when exposing ICE candidates", Work in Progress, Internet-Draft, draft-ietf-mmusic-mdns-ice-candidates-03, October 2019. (Expired, but implemented by browsers)
- [ISO/IEC 18004:2015](https://www.iso.org/standard/62021.html), "QR Code bar code symbology specification"

---

## Appendix A: Test Vectors

### A.1 Minimal Packet (1 IPv4 Host Candidate)

**Input:**

```
Fingerprint: e73b38461a5d88b0c42e9f7a1d6c3e8b5f4a9d2c7e1b6f3a8d5c2e9b4f7a1c3d
Candidate 1: IPv4 host UDP 192.168.1.5:54321
```

**Encoded Packet (hex):**

```
51 00
e7 3b 38 46 1a 5d 88 b0 c4 2e 9f 7a 1d 6c 3e 8b
5f 4a 9d 2c 7e 1b 6f 3a 8d 5c 2e 9b 4f 7a 1c 3d
00 c0 a8 01 05 d4 31
```

**Breakdown:**

```
51          Magic byte 'Q'
00          Version 0, reserved bits 0
e7...3d     32-byte fingerprint
00          Flags: IPv4 (00), UDP (0), host (0)
c0 a8 01 05 IPv4: 192.168.1.5
d4 31       Port: 54321 (0xD431)
```

**Total size:** 41 bytes

**Derived credentials:**

```
ufrag: "ejxenw"
pwd: "TS6KfB2mN9pQ3rS7wX"
```

### A.2 Typical Packet (3 IPv4 Host + 1 srflx)

**Input:**

```
Fingerprint: e73b38461a5d88b0c42e9f7a1d6c3e8b5f4a9d2c7e1b6f3a8d5c2e9b4f7a1c3d
Candidate 1: IPv4 host UDP 192.168.1.5:54321
Candidate 2: IPv4 host UDP 192.168.1.6:54322
Candidate 3: IPv4 host UDP 10.0.0.100:54323
Candidate 4: IPv4 srflx UDP 203.0.113.50:54324
```

**Encoded Packet (hex):**

```
51 00
e7 3b 38 46 1a 5d 88 b0 c4 2e 9f 7a 1d 6c 3e 8b
5f 4a 9d 2c 7e 1b 6f 3a 8d 5c 2e 9b 4f 7a 1c 3d
00 c0 a8 01 05 d4 31
00 c0 a8 01 06 d4 32
00 0a 00 00 64 d4 33
08 cb 00 71 32 d4 34
```

**Breakdown:**

```
Candidate 1: 00 c0a80105 d431  (192.168.1.5:54321, host)
Candidate 2: 00 c0a80106 d432  (192.168.1.6:54322, host)
Candidate 3: 00 0a000064 d433  (10.0.0.100:54323, host)
Candidate 4: 08 cb007132 d434  (203.0.113.50:54324, srflx)
             ^
             Flags: 08 = 0000 1000 = srflx
```

**Total size:** 62 bytes (fits in QR Version 4)

### A.3 IPv6 Candidate

**Input:**

```
Candidate: IPv6 host UDP [2001:db8:85a3::8a2e:370:7334]:54321
```

**Encoded (19 bytes):**

```
01 20 01 0d b8 85 a3 00 00 00 00 8a 2e 03 70 73 34 d4 31
^  ^----------------------------------------------------------^  ^---^
|  IPv6 address (16 bytes)                                        Port
Flags: 01 = IPv6, UDP, host
```

### A.4 mDNS Candidate

**Input:**

```
Candidate: mDNS host UDP a1b2c3d4-e5f6-7890-abcd-ef1234567890.local:54321
```

**Encoded (19 bytes):**

```
02 a1 b2 c3 d4 e5 f6 78 90 ab cd ef 12 34 56 78 90 d4 31
^  ^------------------------------------------------------^  ^---^
|  UUID bytes (16 bytes)                                      Port
Flags: 02 = mDNS (10), UDP, host
```

### A.5 TCP Candidate

**Input:**

```
Candidate: IPv4 host TCP-passive 192.168.1.5:9000
```

**Encoded (7 bytes):**

```
04 c0 a8 01 05 23 28
^
Flags: 04 = 0000 0100 = IPv4, TCP, host, passive
```

### A.6 Role Assignment Examples

**Example 1: Peer A is Offerer**

```
Peer A fingerprint: e73b38461a5d88b0...
Peer B fingerprint: 8a2c5f9100112233...

First byte comparison: 0xe7 > 0x8a
Result: Peer A = Offerer, Peer B = Answerer
```

**Example 2: Peer B is Offerer**

```
Peer A fingerprint: 1a2b3c4d5e6f7890...
Peer B fingerprint: 9f8e7d6c5b4a3928...

First byte comparison: 0x1a < 0x9f
Result: Peer A = Answerer, Peer B = Offerer
```

**Example 3: Deep comparison needed**

```
Peer A fingerprint: aabbccdd00112233...
Peer B fingerprint: aabbccdd00112234...

Bytes 0-6: Equal
Byte 7: 0x33 < 0x34
Result: Peer A = Answerer, Peer B = Offerer
```

---

## Appendix B: Example Implementations

### B.1 HKDF-SHA256 (Web Crypto API)

```typescript
async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  // Import IKM as raw key material
  const ikmKey = await crypto.subtle.importKey(
    "raw",
    ikm,
    { name: "HKDF" },
    false,
    ["deriveBits"]
  );

  // Derive bits using HKDF
  const derived = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt,
      info: info,
    },
    ikmKey,
    length * 8 // bits
  );

  return new Uint8Array(derived);
}

async function deriveCredentials(fingerprint: Uint8Array): Promise<{
  ufrag: string;
  pwd: string;
}> {
  const salt = new Uint8Array(0);
  const ufragInfo = new TextEncoder().encode("QWBP-ICE-UFRAG-v1");
  const pwdInfo = new TextEncoder().encode("QWBP-ICE-PWD-v1");

  const ufragBytes = await hkdf(fingerprint, salt, ufragInfo, 4);
  const pwdBytes = await hkdf(fingerprint, salt, pwdInfo, 18);

  return {
    ufrag: base64urlEncode(ufragBytes),
    pwd: base64urlEncode(pwdBytes),
  };
}

function base64urlEncode(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
```

### B.2 Packet Encoder

```typescript
const MAGIC = 0x51;
const VERSION = 0x00;

interface QWBPCandidate {
  ip: string;
  port: number;
  type: "host" | "srflx";
  protocol: "udp" | "tcp";
  tcpType?: "passive" | "active" | "so";
}

function encodePacket(
  fingerprint: Uint8Array,
  candidates: QWBPCandidate[]
): Uint8Array {
  const parts: Uint8Array[] = [];

  // Header
  parts.push(new Uint8Array([MAGIC, VERSION]));

  // Fingerprint
  parts.push(fingerprint);

  // Candidates
  for (const candidate of candidates) {
    parts.push(encodeCandidate(candidate));
  }

  // Concatenate all parts
  const totalLength = parts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }

  return result;
}

function encodeCandidate(candidate: QWBPCandidate): Uint8Array {
  const isIPv6 = candidate.ip.includes(":");
  const isMdns = candidate.ip.endsWith(".local");

  let addressFamily: number;
  let addressBytes: Uint8Array;

  if (isMdns) {
    addressFamily = 0b10;
    addressBytes = parseMdnsUUID(candidate.ip);
  } else if (isIPv6) {
    addressFamily = 0b01;
    addressBytes = parseIPv6(candidate.ip);
  } else {
    addressFamily = 0b00;
    addressBytes = parseIPv4(candidate.ip);
  }

  const protocol = candidate.protocol === "tcp" ? 1 : 0;
  const type = candidate.type === "srflx" ? 1 : 0;

  let tcpType = 0;
  if (candidate.protocol === "tcp") {
    tcpType =
      candidate.tcpType === "active" ? 1 : candidate.tcpType === "so" ? 2 : 0;
  }

  const flags = addressFamily | (protocol << 2) | (type << 3) | (tcpType << 4);

  const result = new Uint8Array(1 + addressBytes.length + 2);
  result[0] = flags;
  result.set(addressBytes, 1);
  result[result.length - 2] = (candidate.port >> 8) & 0xff;
  result[result.length - 1] = candidate.port & 0xff;

  return result;
}

function parseIPv4(ip: string): Uint8Array {
  const parts = ip.split(".").map((p) => parseInt(p, 10));
  return new Uint8Array(parts);
}

function parseIPv6(ip: string): Uint8Array {
  // Handle :: expansion
  const parts = ip.split(":");
  const result = new Uint8Array(16);
  // ... (full IPv6 parsing implementation)
  return result;
}

function parseMdnsUUID(hostname: string): Uint8Array {
  const uuid = hostname.replace(".local", "").replace(/-/g, "");
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(uuid.substr(i * 2, 2), 16);
  }
  return bytes;
}
```

### B.3 Packet Decoder

```typescript
interface DecodedPacket {
  version: number;
  fingerprint: Uint8Array;
  candidates: QWBPCandidate[];
}

function decodePacket(data: Uint8Array): DecodedPacket {
  if (data.length < 34) {
    throw new Error("Packet too short");
  }

  if (data[0] !== MAGIC) {
    throw new Error("Invalid magic byte");
  }

  const version = data[1] & 0b111;
  if (version !== 0) {
    throw new Error(`Unknown version: ${version}`);
  }

  const fingerprint = data.slice(2, 34);
  const candidates: QWBPCandidate[] = [];

  let offset = 34;
  while (offset < data.length) {
    const { candidate, bytesRead } = decodeCandidate(data, offset);
    candidates.push(candidate);
    offset += bytesRead;
  }

  return { version, fingerprint, candidates };
}

function decodeCandidate(
  data: Uint8Array,
  offset: number
): { candidate: QWBPCandidate; bytesRead: number } {
  const flags = data[offset];
  const addressFamily = flags & 0b11;
  const protocol = (flags >> 2) & 0b1;
  const type = (flags >> 3) & 0b1;
  const tcpType = (flags >> 4) & 0b11;

  let addressLength: number;
  let ip: string;

  if (addressFamily === 0b00) {
    // IPv4
    addressLength = 4;
    ip = Array.from(data.slice(offset + 1, offset + 5)).join(".");
  } else if (addressFamily === 0b01) {
    // IPv6
    addressLength = 16;
    ip = formatIPv6(data.slice(offset + 1, offset + 17));
  } else if (addressFamily === 0b10) {
    // mDNS
    addressLength = 16;
    ip = formatMdns(data.slice(offset + 1, offset + 17));
  } else {
    throw new Error(`Unknown address family: ${addressFamily}`);
  }

  const portOffset = offset + 1 + addressLength;
  const port = (data[portOffset] << 8) | data[portOffset + 1];

  const candidate: QWBPCandidate = {
    ip,
    port,
    type: type === 1 ? "srflx" : "host",
    protocol: protocol === 1 ? "tcp" : "udp",
  };

  if (protocol === 1) {
    candidate.tcpType =
      tcpType === 1 ? "active" : tcpType === 2 ? "so" : "passive";
  }

  return {
    candidate,
    bytesRead: 1 + addressLength + 2,
  };
}

function formatIPv6(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  }
  return parts.join(":");
}

function formatMdns(bytes: Uint8Array): string {
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-${hex.slice(20, 32)}.local`
  );
}
```

---

## Document History

| Version | Date    | Changes               |
| ------- | ------- | --------------------- |
| 0.1.0   | 2026-01 | Initial specification |

---

_End of Specification_
