# Browser Compatibility

This document details QWBP's browser compatibility, including minimum versions, known issues, and required WebRTC APIs.

## Browser Support Matrix

| Browser | Min Version | Status | Notes |
|---------|-------------|--------|-------|
| Chrome Desktop | 80+ | Full | Reference implementation |
| Chrome Android | 80+ | Full | Camera permission exposes raw IP |
| Safari Desktop | 14.1+ | Full | Privacy settings affect candidates |
| Safari iOS | 14.5+ | Full | Local Network prompt required |
| Firefox | 75+ | Full | Platform-dependent mDNS |
| Edge | 80+ | Full | Chromium-based |

## WebRTC API Requirements

QWBP requires the following WebRTC APIs to be available:

### Required APIs

| API | Purpose |
|-----|---------|
| `RTCPeerConnection` | Core WebRTC connection |
| `RTCPeerConnection.generateCertificate()` | ECDSA P-256 certificate generation |
| `RTCDataChannel` | Data transfer |
| `crypto.subtle.deriveBits()` | HKDF-SHA256 credential derivation |
| `crypto.subtle.digest()` | SHA-256 hashing |

### Feature Detection

```typescript
function isQWBPSupported(): boolean {
  return (
    typeof RTCPeerConnection !== 'undefined' &&
    typeof RTCPeerConnection.generateCertificate === 'function' &&
    typeof crypto?.subtle?.deriveBits === 'function'
  );
}
```

## Platform-Specific Behavior

### Chrome (Desktop & Android)

- **Version 80+**: Full support
- ICE candidates include both IPv4 and IPv6 addresses
- mDNS candidates use UUID format (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.local`)
- Camera permission on Android exposes the device's raw IP address

### Safari (Desktop & iOS)

- **Desktop 14.1+**: Full support
- **iOS 14.5+**: Full support
- Privacy settings ("Hide IP Address") affect available candidates
- mDNS candidates may be the only candidates in restrictive privacy modes
- **iOS Local Network prompt**: First-time use triggers a system prompt asking for local network access permission

### Firefox

- **Version 75+**: Full support
- mDNS behavior is platform-dependent:
  - macOS: mDNS candidates generated
  - Windows: mDNS may be unavailable
  - Linux: Depends on Avahi configuration
- `about:config` settings can affect WebRTC behavior

### Edge

- **Version 80+**: Full support (Chromium-based)
- Behavior identical to Chrome

## Known Issues

### 1. Symmetric NAT

**Issue**: If both peers are behind symmetric NATs (common in corporate firewalls and some cellular networks), STUN hole-punching will fail.

**Impact**: Connection cannot be established using only the QR code exchange.

**Workaround**: Pre-configure a TURN server on both clients:

```typescript
const connection = new QWBPConnection({
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    {
      urls: 'turn:your-turn-server.example.com:3478',
      username: 'app-configured-user',
      credential: 'app-configured-credential',
    },
  ],
});
```

### 2. iOS Local Network Prompt

**Issue**: On iOS, the first QR exchange triggers a "Local Network" permission prompt.

**Impact**: Users may be confused by the prompt or deny it, preventing local network connections.

**Workaround**:
- Display a message explaining the prompt before initializing
- The prompt only appears once per app installation
- Connections via STUN (srflx candidates) still work without this permission

### 3. Safari Privacy Settings

**Issue**: Safari's "Hide IP Address" feature can prevent host candidates from being generated.

**Impact**: Only mDNS candidates are available, which may not resolve across different networks.

**Detection**:

```typescript
// After initialize(), check candidate types
const candidates = connection.getQRPayload(); // Decode and inspect
// If only mDNS candidates, warn user about potential connectivity issues
```

### 4. Firefox mDNS on Windows

**Issue**: Firefox on Windows may not generate mDNS candidates.

**Impact**: Local network discovery may be affected on Windows.

**Workaround**: Ensure at least one peer is on a platform that generates routable candidates, or pre-configure STUN servers.

### 5. Corporate Firewall Restrictions

**Issue**: Some corporate firewalls block WebRTC entirely or restrict UDP traffic.

**Impact**: Connection establishment may fail completely.

**Detection**: ICE gathering timeout or no candidates found.

## Testing Your Environment

Use this code to test QWBP compatibility in a browser:

```typescript
import { QWBPConnection } from 'qwbp';

async function testCompatibility() {
  try {
    const conn = new QWBPConnection();
    await conn.initialize();

    const payload = conn.getQRPayload();
    console.log('QR payload size:', payload.length, 'bytes');
    console.log('Connection state:', conn.connectionState);

    conn.close();
    return { supported: true, payloadSize: payload.length };
  } catch (error) {
    return { supported: false, error: error.message };
  }
}
```

## Version History

| QWBP Version | Browser Changes |
|--------------|-----------------|
| 0.1.0 | Initial release with Chrome, Safari, Firefox support |
