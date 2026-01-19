/**
 * SDP extraction tests
 *
 * Tests for extractFingerprintFromSDP and extractCandidatesFromSDP
 */

import { describe, it, expect } from 'vitest';
import {
  extractFingerprintFromSDP,
  extractCandidatesFromSDP,
  reconstructSDP,
  validateSDP,
} from '../src/index.js';
import { TEST_FINGERPRINT, BROWSER_SDP_SAMPLES } from './fixtures.js';

describe('extractFingerprintFromSDP', () => {
  it('should extract fingerprint from valid SDP', () => {
    const sdp = `v=0
o=- 123456 2 IN IP4 127.0.0.1
s=-
a=fingerprint:sha-256 E7:3B:38:46:1A:5D:88:B0:C4:2E:9F:7A:1D:6C:3E:8B:5F:4A:9D:2C:7E:1B:6F:3A:8D:5C:2E:9B:4F:7A:1C:3D
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

    const fingerprint = extractFingerprintFromSDP(sdp);
    expect(fingerprint).toEqual(TEST_FINGERPRINT);
  });

  it('should throw if no fingerprint found', () => {
    const sdp = `v=0
o=- 123456 2 IN IP4 127.0.0.1
s=-
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

    expect(() => extractFingerprintFromSDP(sdp)).toThrow(/No SHA-256 fingerprint/i);
  });

  it('should throw if fingerprint has wrong length', () => {
    const sdp = `v=0
a=fingerprint:sha-256 E7:3B:38:46
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

    expect(() => extractFingerprintFromSDP(sdp)).toThrow(/Invalid fingerprint length/i);
  });
});

describe('extractCandidatesFromSDP', () => {
  describe('Basic Extraction', () => {
    it('should extract UDP host candidates', () => {
      const sdp = `v=0
a=candidate:1 1 udp 2122260223 192.168.1.5 54321 typ host
a=candidate:2 1 udp 2122260222 192.168.1.6 54322 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);

      expect(candidates.length).toBe(2);
      expect(candidates[0].ip).toBe('192.168.1.5');
      expect(candidates[0].port).toBe(54321);
      expect(candidates[0].type).toBe('host');
      expect(candidates[0].protocol).toBe('udp');
    });

    it('should extract srflx candidates', () => {
      const sdp = `v=0
a=candidate:1 1 udp 1686052607 203.0.113.50 54321 typ srflx raddr 192.168.1.5 rport 54321
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);

      expect(candidates.length).toBe(1);
      expect(candidates[0].type).toBe('srflx');
    });

    it('should handle empty SDP', () => {
      const candidates = extractCandidatesFromSDP('');
      expect(candidates.length).toBe(0);
    });

    it('should handle malformed candidate lines', () => {
      const sdp = `v=0
a=candidate:malformed line here
a=candidate:1 1 udp 2122260223 192.168.1.5 54321 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);

      expect(candidates.length).toBe(1);
      expect(candidates[0].ip).toBe('192.168.1.5');
    });
  });

  describe('Filtering', () => {
    it('should include both UDP and TCP candidates', () => {
      const sdp = `v=0
a=candidate:1 1 tcp 2122260223 192.168.1.5 54321 typ host tcptype passive
a=candidate:2 1 udp 2122260222 192.168.1.6 54322 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);

      expect(candidates.length).toBe(2);
      expect(candidates.some(c => c.protocol === 'tcp')).toBe(true);
      expect(candidates.some(c => c.protocol === 'udp')).toBe(true);
    });

    it('should skip relay candidates', () => {
      const sdp = `v=0
a=candidate:1 1 udp 41819903 203.0.113.50 54321 typ relay
a=candidate:2 1 udp 2122260222 192.168.1.5 54322 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);

      expect(candidates.length).toBe(1);
      expect(candidates[0].type).toBe('host');
    });

    it('should respect maxCandidates limit', () => {
      const sdp = `v=0
a=candidate:1 1 udp 2122260223 192.168.1.1 54321 typ host
a=candidate:2 1 udp 2122260222 192.168.1.2 54322 typ host
a=candidate:3 1 udp 2122260221 192.168.1.3 54323 typ host
a=candidate:4 1 udp 2122260220 192.168.1.4 54324 typ host
a=candidate:5 1 udp 2122260219 192.168.1.5 54325 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp, 2);
      expect(candidates.length).toBe(2);
    });
  });

  describe('Port Validation', () => {
    it('should handle port 1', () => {
      const sdp = `v=0
a=candidate:1 1 udp 2122260223 192.168.1.5 1 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);
      expect(candidates[0].port).toBe(1);
    });

    it('should handle port 65535', () => {
      const sdp = `v=0
a=candidate:1 1 udp 2122260223 192.168.1.5 65535 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);
      expect(candidates[0].port).toBe(65535);
    });

    it('should reject port 0', () => {
      const sdp = `v=0
a=candidate:1 1 udp 2122260223 192.168.1.5 0 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);
      expect(candidates.length).toBe(0);
    });

    it('should reject port over 65535', () => {
      const sdp = `v=0
a=candidate:1 1 udp 2122260223 192.168.1.5 65536 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);
      expect(candidates.length).toBe(0);
    });
  });

  describe('Sorting', () => {
    it('should sort host before srflx', () => {
      const sdp = `v=0
a=candidate:1 1 udp 1686052607 203.0.113.50 54321 typ srflx
a=candidate:2 1 udp 2122260223 192.168.1.5 54322 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);

      expect(candidates[0].type).toBe('host');
      expect(candidates[1].type).toBe('srflx');
    });

    it('should sort host before srflx (reverse input order)', () => {
      const sdp = `v=0
a=candidate:1 1 udp 2122260223 192.168.1.5 54322 typ host
a=candidate:2 1 udp 1686052607 203.0.113.50 54321 typ srflx
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);

      expect(candidates[0].type).toBe('host');
      expect(candidates[1].type).toBe('srflx');
    });

    it('should sort IPv4 before IPv6', () => {
      const sdp = `v=0
a=candidate:1 1 udp 2122260223 2001:db8::1 54321 typ host
a=candidate:2 1 udp 2122260222 192.168.1.5 54322 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);

      expect(candidates[0].ip).toBe('192.168.1.5');
      expect(candidates[1].ip).toBe('2001:db8::1');
    });

    it('should sort IPv6 after IPv4 (reverse input order)', () => {
      const sdp = `v=0
a=candidate:1 1 udp 2122260222 192.168.1.5 54322 typ host
a=candidate:2 1 udp 2122260223 2001:db8::1 54321 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);

      expect(candidates[0].ip).toBe('192.168.1.5');
      expect(candidates[1].ip).toBe('2001:db8::1');
    });

    it('should keep order when both types match', () => {
      const sdp = `v=0
a=candidate:1 1 udp 2122260223 192.168.1.5 54321 typ host
a=candidate:2 1 udp 2122260222 192.168.1.6 54322 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);
      expect(candidates.length).toBe(2);
    });

    it('should handle mDNS candidates in sorting', () => {
      const sdp = `v=0
a=candidate:1 1 udp 2122260223 a1b2c3d4-e5f6-7890-abcd-ef1234567890.local 54321 typ host
a=candidate:2 1 udp 2122260222 192.168.1.5 54322 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);

      expect(candidates[0].ip).toBe('192.168.1.5');
      expect(candidates[1].ip).toContain('.local');
    });

    it('should prioritize IPv4 srflx when only srflx candidates exist', () => {
      // When no host candidates exist, only the first (best) srflx is included
      // to keep consistency with the smart selection that reserves slots for hosts
      const sdp = `v=0
a=candidate:1 1 udp 1686052607 2001:db8::1 54321 typ srflx
a=candidate:2 1 udp 1686052606 203.0.113.50 54322 typ srflx
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const candidates = extractCandidatesFromSDP(sdp);

      // Smart selection includes one srflx, preferring IPv4
      expect(candidates.length).toBe(1);
      expect(candidates[0].ip).toBe('203.0.113.50');
    });
  });
});

describe('Browser SDP Compatibility', () => {
  describe('Fingerprint Extraction', () => {
    Object.entries(BROWSER_SDP_SAMPLES).forEach(([browserName, sample]) => {
      it(`should extract fingerprint from ${browserName} SDP`, () => {
        const fingerprint = extractFingerprintFromSDP(sample.sdp);
        expect(fingerprint).toEqual(sample.fingerprint);
      });
    });
  });

  describe('Candidate Extraction', () => {
    Object.entries(BROWSER_SDP_SAMPLES).forEach(([browserName, sample]) => {
      it(`should extract candidates from ${browserName} SDP`, () => {
        const candidates = extractCandidatesFromSDP(sample.sdp);
        expect(candidates.length).toBeGreaterThanOrEqual(sample.minCandidateCount);
      });
    });

    it('should extract IPv4 and IPv6 candidates (Chrome Android)', () => {
      const { sdp } = BROWSER_SDP_SAMPLES.chrome_android;
      const candidates = extractCandidatesFromSDP(sdp);

      const hasIPv4 = candidates.some(c => !c.ip.includes(':') && !c.ip.includes('.local'));
      const hasIPv6 = candidates.some(c => c.ip.includes(':'));

      expect(hasIPv4).toBe(true);
      expect(hasIPv6).toBe(true);
    });

    it('should extract mDNS candidates (Safari iOS)', () => {
      const { sdp } = BROWSER_SDP_SAMPLES.safari_ios;
      const candidates = extractCandidatesFromSDP(sdp);

      const hasMDNS = candidates.some(c => c.ip.endsWith('.local'));
      expect(hasMDNS).toBe(true);
    });

    it('should extract TCP candidates (Firefox TCP)', () => {
      const { sdp } = BROWSER_SDP_SAMPLES.firefox_tcp;
      const candidates = extractCandidatesFromSDP(sdp);

      const tcpCandidates = candidates.filter(c => c.protocol === 'tcp');
      expect(tcpCandidates.length).toBeGreaterThan(0);

      const hasTcpPassive = tcpCandidates.some(c => c.tcpType === 'passive');
      expect(hasTcpPassive).toBe(true);
    });

    it('should extract srflx candidates with raddr/rport', () => {
      const { sdp } = BROWSER_SDP_SAMPLES.chrome_desktop;
      const candidates = extractCandidatesFromSDP(sdp);

      const srflxCandidates = candidates.filter(c => c.type === 'srflx');
      expect(srflxCandidates.length).toBeGreaterThan(0);
    });

    it('should handle carrier-grade NAT addresses (Safari iOS)', () => {
      const { sdp } = BROWSER_SDP_SAMPLES.safari_ios;
      const candidates = extractCandidatesFromSDP(sdp);

      // 100.64.0.0/10 is carrier-grade NAT range
      const hasCGNAT = candidates.some(c => c.ip.startsWith('100.64.'));
      expect(hasCGNAT).toBe(true);
    });
  });

  describe('Candidate Type Detection', () => {
    Object.entries(BROWSER_SDP_SAMPLES).forEach(([browserName, sample]) => {
      if (sample.expectedCandidateTypes.length > 0) {
        it(`should detect expected candidate types from ${browserName}`, () => {
          const candidates = extractCandidatesFromSDP(sample.sdp);
          const types = new Set(candidates.map(c => c.type));

          sample.expectedCandidateTypes.forEach(expectedType => {
            expect(types.has(expectedType)).toBe(true);
          });
        });
      }
    });
  });

  describe('Reconstructed SDP Validation', () => {
    Object.entries(BROWSER_SDP_SAMPLES).forEach(([browserName, sample]) => {
      it(`should produce valid SDP from ${browserName} fingerprint`, async () => {
        const reconstructed = await reconstructSDP(sample.fingerprint, true);
        const isValid = validateSDP(reconstructed);
        expect(isValid).toBe(true);
      });
    });

    it('should include all required WebRTC attributes', async () => {
      const { fingerprint } = BROWSER_SDP_SAMPLES.chrome_desktop;
      const reconstructed = await reconstructSDP(fingerprint, true);

      expect(reconstructed).toMatch(/a=fingerprint:sha-256/);
      expect(reconstructed).toMatch(/a=ice-ufrag:/);
      expect(reconstructed).toMatch(/a=ice-pwd:/);
      expect(reconstructed).toMatch(/m=application/);
      expect(reconstructed).toMatch(/a=setup:(actpass|active)/);
      expect(reconstructed).toMatch(/a=sctp-port:/);
    });

    it('should set correct setup attribute for offer vs answer', async () => {
      const { fingerprint } = BROWSER_SDP_SAMPLES.firefox_desktop;

      const offer = await reconstructSDP(fingerprint, true);
      expect(offer).toMatch(/a=setup:actpass/);

      const answer = await reconstructSDP(fingerprint, false);
      expect(answer).toMatch(/a=setup:active/);
    });
  });

  describe('Edge Cases', () => {
    it('should handle SDP with extra whitespace in fingerprint line', () => {
      const sdp = `v=0
o=- 123 2 IN IP4 127.0.0.1
s=-
a=fingerprint:sha-256   A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:01:12:23:34:45:56:67:78:89:9A:AB:BC:CD:DE:EF:F0
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const fingerprint = extractFingerprintFromSDP(sdp);
      expect(fingerprint).toEqual(BROWSER_SDP_SAMPLES.chrome_desktop.fingerprint);
    });

    it('should handle SDP with lowercase fingerprint', () => {
      const sdp = `v=0
o=- 123 2 IN IP4 127.0.0.1
s=-
a=fingerprint:sha-256 a1:b2:c3:d4:e5:f6:07:18:29:3a:4b:5c:6d:7e:8f:90:01:12:23:34:45:56:67:78:89:9a:ab:bc:cd:de:ef:f0
m=application 9 UDP/DTLS/SCTP webrtc-datachannel`;

      const fingerprint = extractFingerprintFromSDP(sdp);
      expect(fingerprint).toEqual(BROWSER_SDP_SAMPLES.chrome_desktop.fingerprint);
    });

    it('should handle Firefox origin line format', () => {
      const { sdp } = BROWSER_SDP_SAMPLES.firefox_desktop;
      expect(sdp).toMatch(/o=mozilla\.\.\.THIS_IS_SDPARTA/);

      const fingerprint = extractFingerprintFromSDP(sdp);
      expect(fingerprint).toEqual(BROWSER_SDP_SAMPLES.firefox_desktop.fingerprint);
    });

    it('should handle candidates with generation and network attributes', () => {
      const { sdp } = BROWSER_SDP_SAMPLES.chrome_desktop;
      const candidates = extractCandidatesFromSDP(sdp);

      expect(candidates.length).toBeGreaterThan(0);
      expect(candidates[0].ip).toBeDefined();
      expect(candidates[0].port).toBeDefined();
    });

    it('should handle uppercase protocol in candidate line (Firefox)', () => {
      const { sdp } = BROWSER_SDP_SAMPLES.firefox_desktop;
      expect(sdp).toMatch(/a=candidate:\d+ 1 UDP/);

      const candidates = extractCandidatesFromSDP(sdp);
      expect(candidates.some(c => c.protocol === 'udp')).toBe(true);
    });
  });
});
