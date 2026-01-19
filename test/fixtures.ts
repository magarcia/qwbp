/**
 * Shared test fixtures for QWBP tests
 */

/** Test fingerprint from specification (Appendix A) */
export const TEST_FINGERPRINT = new Uint8Array([
  0xe7, 0x3b, 0x38, 0x46, 0x1a, 0x5d, 0x88, 0xb0,
  0xc4, 0x2e, 0x9f, 0x7a, 0x1d, 0x6c, 0x3e, 0x8b,
  0x5f, 0x4a, 0x9d, 0x2c, 0x7e, 0x1b, 0x6f, 0x3a,
  0x8d, 0x5c, 0x2e, 0x9b, 0x4f, 0x7a, 0x1c, 0x3d,
]);

/** Second fingerprint for peer simulation (lower than TEST_FINGERPRINT) */
export const TEST_PEER_FINGERPRINT = new Uint8Array([
  0xa1, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
  0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
  0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
  0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
]);

/** Test ICE candidates */
export const TEST_CANDIDATES = [
  { ip: '192.168.1.5', port: 54321, type: 'host' as const, protocol: 'udp' as const },
  { ip: '203.0.113.50', port: 54322, type: 'srflx' as const, protocol: 'udp' as const },
];

/** Test ICE candidates for peer */
export const TEST_PEER_CANDIDATES = [
  { ip: '192.168.1.10', port: 12345, type: 'host' as const, protocol: 'udp' as const },
];

/**
 * Browser SDP Capture Instructions:
 *
 * To capture fresh browser SDPs for testing, follow these steps:
 *
 * 1. Open browser DevTools console on any HTTPS page (WebRTC requires secure context)
 *
 * 2. Run the following code:
 *    ```javascript
 *    const pc = new RTCPeerConnection({
 *      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
 *    });
 *    const dc = pc.createDataChannel('test');
 *    pc.onicecandidate = (e) => {
 *      if (!e.candidate) {
 *        console.log('ICE gathering complete. SDP:');
 *        console.log(pc.localDescription.sdp);
 *      }
 *    };
 *    pc.createOffer().then(o => pc.setLocalDescription(o));
 *    ```
 *
 * 3. Wait for "ICE gathering complete" message (usually 2-5 seconds)
 *
 * 4. Copy the logged SDP and add to BROWSER_SDP_SAMPLES below
 *
 * 5. Extract and verify:
 *    - Fingerprint from `a=fingerprint:sha-256` line
 *    - Candidate count from `a=candidate:` lines
 *    - Candidate types (host, srflx) and address formats (IPv4, IPv6, mDNS)
 *
 * Notes:
 * - mDNS candidates (*.local) appear on modern browsers for privacy
 * - IPv6 candidates depend on network configuration
 * - srflx candidates require STUN server response
 * - Browser versions affect SDP format and attributes
 */

export interface BrowserSDPSample {
  /** Full SDP offer with candidates gathered */
  sdp: string;
  /** Expected fingerprint bytes extracted from SDP */
  fingerprint: Uint8Array;
  /** Minimum expected candidate count (varies by network) */
  minCandidateCount: number;
  /** Expected candidate types present */
  expectedCandidateTypes: Array<'host' | 'srflx'>;
  /** Browser version for documentation */
  browserVersion: string;
  /** Notes about this sample */
  notes?: string;
}

/**
 * Browser SDP samples for compatibility testing
 *
 * These SDPs are modeled on real browser output patterns to ensure our
 * extraction functions handle browser-specific formatting correctly.
 * Each sample replicates the structure and quirks of its respective browser.
 */
export const BROWSER_SDP_SAMPLES: Record<string, BrowserSDPSample> = {
  chrome_desktop: {
    browserVersion: 'Chrome 120.0.6099.109',
    sdp: `v=0
o=- 5765230285091029391 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
a=msid-semantic: WMS
m=application 56231 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 192.168.1.100
a=candidate:2054585653 1 udp 2122260223 192.168.1.100 56231 typ host generation 0 network-id 1 network-cost 10
a=candidate:842163049 1 udp 1686052607 203.0.113.45 56231 typ srflx raddr 192.168.1.100 rport 56231 generation 0 network-id 1 network-cost 10
a=ice-ufrag:ABCD
a=ice-pwd:abcdefghijklmnopqrstuvwx
a=ice-options:trickle
a=fingerprint:sha-256 A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:01:12:23:34:45:56:67:78:89:9A:AB:BC:CD:DE:EF:F0
a=setup:actpass
a=mid:0
a=sctp-port:5000
a=max-message-size:262144
`,
    fingerprint: new Uint8Array([
      0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
      0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
      0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
      0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
    ]),
    minCandidateCount: 2,
    expectedCandidateTypes: ['host', 'srflx'],
    notes: 'Standard Chrome desktop with IPv4 host and srflx candidates',
  },

  chrome_android: {
    browserVersion: 'Chrome 120.0.6099.43 Android',
    sdp: `v=0
o=- 1234567890123456789 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
a=msid-semantic: WMS
m=application 45678 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 10.0.0.50
a=candidate:1 1 udp 2122194687 10.0.0.50 45678 typ host generation 0 network-id 3 network-cost 900
a=candidate:2 1 udp 2122129151 fe80::1234:5678:abcd:ef01 45679 typ host generation 0 network-id 4 network-cost 900
a=candidate:3 1 udp 1686052607 198.51.100.25 45678 typ srflx raddr 10.0.0.50 rport 45678 generation 0 network-id 3 network-cost 900
a=ice-ufrag:xyz1
a=ice-pwd:0123456789abcdefghijklmn
a=ice-options:trickle renomination
a=fingerprint:sha-256 DE:AD:BE:EF:CA:FE:BA:BE:12:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00
a=setup:actpass
a=mid:0
a=sctp-port:5000
a=max-message-size:262144
`,
    fingerprint: new Uint8Array([
      0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
      0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
      0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    ]),
    minCandidateCount: 2,
    expectedCandidateTypes: ['host', 'srflx'],
    notes: 'Chrome Android with IPv4, IPv6 link-local, and srflx candidates',
  },

  firefox_desktop: {
    browserVersion: 'Firefox 121.0',
    sdp: `v=0
o=mozilla...THIS_IS_SDPARTA-121.0 7891234567890123456 0 IN IP4 0.0.0.0
s=-
t=0 0
a=sendrecv
a=fingerprint:sha-256 99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC:BB:AA:12:34:56:78:9A:BC:DE:F0:FE:DC:BA:98:76:54:32:10
a=group:BUNDLE 0
a=ice-options:trickle
a=msid-semantic:WMS *
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=candidate:0 1 UDP 2122252543 192.168.1.105 54321 typ host
a=candidate:1 1 UDP 2122218495 2001:db8::1 54322 typ host
a=candidate:2 1 UDP 1686052863 203.0.113.99 54321 typ srflx raddr 192.168.1.105 rport 54321
a=sendrecv
a=end-of-candidates
a=ice-pwd:abcdefghijklmnopqrstuv
a=ice-ufrag:abc1
a=mid:0
a=sctp-port:5000
a=setup:actpass
a=max-message-size:1073741823
`,
    fingerprint: new Uint8Array([
      0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
      0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa,
      0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ]),
    minCandidateCount: 2,
    expectedCandidateTypes: ['host', 'srflx'],
    notes: 'Firefox with session-level fingerprint and end-of-candidates marker',
  },

  safari_desktop: {
    browserVersion: 'Safari 17.2',
    sdp: `v=0
o=- 4611731400430051336 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
b=AS:30
a=ice-ufrag:mno2
a=ice-pwd:mnopqrstuvwxyz0123456789
a=ice-options:trickle
a=fingerprint:sha-256 FE:ED:FA:CE:BE:EF:CA:FE:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:A1:B2:C3:D4:E5:F6:07:18
a=setup:actpass
a=mid:0
a=sctp-port:5000
a=candidate:1 1 udp 2113937151 192.168.1.200 60001 typ host
a=candidate:2 1 udp 1845501695 203.0.113.150 60001 typ srflx raddr 192.168.1.200 rport 60001
`,
    fingerprint: new Uint8Array([
      0xfe, 0xed, 0xfa, 0xce, 0xbe, 0xef, 0xca, 0xfe,
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
      0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
    ]),
    minCandidateCount: 2,
    expectedCandidateTypes: ['host', 'srflx'],
    notes: 'Safari desktop with bandwidth attribute and different priority calculation',
  },

  safari_ios: {
    browserVersion: 'Safari iOS 17.2',
    sdp: `v=0
o=- 8912345678901234567 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=ice-ufrag:pqr3
a=ice-pwd:pqrstuvwxyz01234567890a
a=ice-options:trickle
a=fingerprint:sha-256 01:23:45:67:89:AB:CD:EF:FE:DC:BA:98:76:54:32:10:A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90
a=setup:actpass
a=mid:0
a=sctp-port:5000
a=candidate:1 1 udp 2113937151 192.168.0.15 59876 typ host
a=candidate:2 1 udp 2113937151 f8d7c6b5-a4e3-12d1-9f8e-7d6c5b4a3210.local 59877 typ host
a=candidate:3 1 udp 1845501695 100.64.0.1 59876 typ srflx raddr 192.168.0.15 rport 59876
`,
    fingerprint: new Uint8Array([
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
      0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
      0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
    ]),
    minCandidateCount: 2,
    expectedCandidateTypes: ['host', 'srflx'],
    notes: 'Safari iOS with mDNS candidate for privacy and carrier-grade NAT srflx',
  },

  chrome_mdns: {
    browserVersion: 'Chrome 120.0.6099.109',
    sdp: `v=0
o=- 3456789012345678901 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
a=msid-semantic: WMS
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=candidate:1 1 udp 2122260223 a1b2c3d4-e5f6-7890-abcd-ef1234567890.local 54000 typ host generation 0 network-id 1
a=ice-ufrag:stu4
a=ice-pwd:stuvwxyz0123456789abcdef
a=ice-options:trickle
a=fingerprint:sha-256 AB:CD:EF:01:23:45:67:89:9A:BC:DE:F0:12:34:56:78:8A:9B:0C:1D:2E:3F:40:51:62:73:84:95:A6:B7:C8:D9
a=setup:actpass
a=mid:0
a=sctp-port:5000
a=max-message-size:262144
`,
    fingerprint: new Uint8Array([
      0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
      0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
      0x8a, 0x9b, 0x0c, 0x1d, 0x2e, 0x3f, 0x40, 0x51,
      0x62, 0x73, 0x84, 0x95, 0xa6, 0xb7, 0xc8, 0xd9,
    ]),
    minCandidateCount: 1,
    expectedCandidateTypes: ['host'],
    notes: 'Chrome with mDNS-only candidates (privacy mode, no STUN response)',
  },

  firefox_tcp: {
    browserVersion: 'Firefox 121.0',
    sdp: `v=0
o=mozilla...THIS_IS_SDPARTA-121.0 2345678901234567890 0 IN IP4 0.0.0.0
s=-
t=0 0
a=sendrecv
a=fingerprint:sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:10:20:30:40:50:60:70:80:90:A0:B0:C0:D0:E0:F0:01
a=group:BUNDLE 0
a=ice-options:trickle
a=msid-semantic:WMS *
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=candidate:0 1 UDP 2122252543 192.168.1.110 60000 typ host
a=candidate:1 1 TCP 2105524479 192.168.1.110 9 typ host tcptype active
a=candidate:2 1 TCP 2105524479 192.168.1.110 60001 typ host tcptype passive
a=candidate:3 1 UDP 1686052863 203.0.113.110 60000 typ srflx raddr 192.168.1.110 rport 60000
a=sendrecv
a=end-of-candidates
a=ice-pwd:0123456789abcdefghijkl
a=ice-ufrag:vwx5
a=mid:0
a=sctp-port:5000
a=setup:actpass
`,
    fingerprint: new Uint8Array([
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
      0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
      0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
      0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
    ]),
    minCandidateCount: 3,
    expectedCandidateTypes: ['host', 'srflx'],
    notes: 'Firefox with TCP ICE candidates (active and passive)',
  },
};
