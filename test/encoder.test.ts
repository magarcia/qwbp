/**
 * Encoder module tests
 *
 * Tests for packet encoding and address parsing
 */

import { describe, it, expect } from 'vitest';
import { encode, decode } from '../src/index.js';
import type { QWBPCandidate } from '../src/index.js';
import { TEST_FINGERPRINT } from './fixtures.js';

describe('Encoder', () => {
  describe('IPv4 Candidates', () => {
    it('should encode single IPv4 host candidate', () => {
      const candidate: QWBPCandidate = {
        ip: '192.168.1.5',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);

      expect(packet.length).toBe(41);
      expect(packet[0]).toBe(0x51); // Magic byte
      expect(packet[1]).toBe(0x00); // Version
      expect(packet[34]).toBe(0x00); // Flags: IPv4, UDP, host
      expect(packet[35]).toBe(192);
      expect(packet[36]).toBe(168);
      expect(packet[37]).toBe(1);
      expect(packet[38]).toBe(5);
    });

    it('should encode srflx candidate with correct flag', () => {
      const candidate: QWBPCandidate = {
        ip: '203.0.113.50',
        port: 54321,
        type: 'srflx',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      expect(packet[34]).toBe(0x08); // srflx flag
    });

    it('should encode multiple candidates', () => {
      const candidates: QWBPCandidate[] = [
        { ip: '192.168.1.5', port: 54321, type: 'host', protocol: 'udp' },
        { ip: '192.168.1.6', port: 54322, type: 'host', protocol: 'udp' },
        { ip: '10.0.0.100', port: 54323, type: 'host', protocol: 'udp' },
        { ip: '203.0.113.50', port: 54324, type: 'srflx', protocol: 'udp' },
      ];

      const packet = encode(TEST_FINGERPRINT, candidates);
      expect(packet.length).toBe(62); // 2 + 32 + 4*7
    });
  });

  describe('IPv6 Candidates', () => {
    it('should encode IPv6 candidate', () => {
      const candidate: QWBPCandidate = {
        ip: '2001:db8:85a3::8a2e:370:7334',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      expect(packet.length).toBe(53); // 2 + 32 + 19
      expect(packet[34] & 0x03).toBe(0x01); // IPv6 flag
    });

    it('should handle IPv6 with brackets', () => {
      const candidate: QWBPCandidate = {
        ip: '[2001:db8:85a3::8a2e:370:7334]',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      const decoded = decode(packet);
      expect(decoded.candidates[0].ip).toContain('2001');
    });

    it('should handle IPv6 without :: compression', () => {
      const candidate: QWBPCandidate = {
        ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      const decoded = decode(packet);
      expect(decoded.candidates[0].ip).toContain('2001');
    });

    it('should handle IPv6 with leading ::', () => {
      const candidate: QWBPCandidate = {
        ip: '::1',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      const decoded = decode(packet);
      expect(decoded.candidates[0].port).toBe(54321);
    });

    it('should handle IPv6 with trailing ::', () => {
      const candidate: QWBPCandidate = {
        ip: 'fe80::',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      const decoded = decode(packet);
      expect(decoded.candidates[0].port).toBe(54321);
    });

    it('should reject IPv6 with invalid format (leading single colon)', () => {
      const candidate: QWBPCandidate = {
        ip: ':1::2',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      expect(() => encode(TEST_FINGERPRINT, [candidate])).toThrow(/Invalid IPv6/i);
    });

    it('should encode uncompressed IPv6 identically to compressed form', () => {
      const uncompressed: QWBPCandidate = {
        ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const compressed: QWBPCandidate = {
        ip: '2001:db8:85a3::8a2e:370:7334',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packetUncompressed = encode(TEST_FINGERPRINT, [uncompressed]);
      const packetCompressed = encode(TEST_FINGERPRINT, [compressed]);

      expect(packetUncompressed).toEqual(packetCompressed);
    });

    it('should encode IPv4-mapped IPv6 address (::ffff:x.x.x.x)', () => {
      const candidate: QWBPCandidate = {
        ip: '::ffff:192.168.1.1',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);

      // Should be flagged as IPv6
      expect(packet[34] & 0x03).toBe(0x01);

      // Verify ::ffff: prefix at bytes 10-11 of the address
      // Packet structure: magic(1) + version(1) + fingerprint(32) + flags(1) + address(16) + port(2)
      // Address starts at byte 35, so bytes 10-11 of address are at packet[45-46]
      expect(packet[45]).toBe(0xff);
      expect(packet[46]).toBe(0xff);

      // Verify IPv4 portion at bytes 12-15 of the address (packet[47-50])
      expect(packet[47]).toBe(192);
      expect(packet[48]).toBe(168);
      expect(packet[49]).toBe(1);
      expect(packet[50]).toBe(1);
    });

    it('should encode all-zeros IPv6 address (::)', () => {
      const candidate: QWBPCandidate = {
        ip: '::',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);

      // All 16 address bytes (packet[35-50]) should be zero
      for (let i = 35; i < 51; i++) {
        expect(packet[i]).toBe(0);
      }
    });
  });

  describe('mDNS Candidates', () => {
    it('should encode mDNS candidate', () => {
      const candidate: QWBPCandidate = {
        ip: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890.local',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      expect(packet.length).toBe(53); // Same as IPv6
      expect(packet[34] & 0x03).toBe(0x02); // mDNS flag
    });
  });

  describe('TCP Candidates', () => {
    it('should encode TCP passive type', () => {
      const candidate: QWBPCandidate = {
        ip: '192.168.1.5',
        port: 9000,
        type: 'host',
        protocol: 'tcp',
        tcpType: 'passive',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      expect(packet[34]).toBe(0x04); // TCP flag
    });

    it('should encode TCP active type', () => {
      const candidate: QWBPCandidate = {
        ip: '192.168.1.5',
        port: 9000,
        type: 'host',
        protocol: 'tcp',
        tcpType: 'active',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      expect(packet[34]).toBe(0x14); // TCP + active
    });

    it('should encode TCP so type', () => {
      const candidate: QWBPCandidate = {
        ip: '192.168.1.5',
        port: 9000,
        type: 'host',
        protocol: 'tcp',
        tcpType: 'so',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      expect(packet[34]).toBe(0x24); // TCP + so
    });
  });

  describe('Port Encoding', () => {
    it('should encode port in big-endian', () => {
      const candidate: QWBPCandidate = {
        ip: '192.168.1.5',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      expect(packet[39]).toBe(0xd4);
      expect(packet[40]).toBe(0x31);
    });

    it('should handle port 80', () => {
      const candidate: QWBPCandidate = {
        ip: '192.168.1.5',
        port: 80,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      expect(packet[39]).toBe(0x00);
      expect(packet[40]).toBe(0x50);
    });

    it('should handle port 65535', () => {
      const candidate: QWBPCandidate = {
        ip: '192.168.1.5',
        port: 65535,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      expect(packet[39]).toBe(0xff);
      expect(packet[40]).toBe(0xff);
    });
  });

  describe('Error Handling', () => {
    it('should reject fingerprint with wrong length', () => {
      const badFingerprint = new Uint8Array(16);
      const candidate: QWBPCandidate = {
        ip: '192.168.1.5',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      expect(() => encode(badFingerprint, [candidate])).toThrow(
        /Invalid fingerprint length/i
      );
    });

    it('should reject invalid IPv4 with wrong octet count', () => {
      const candidate: QWBPCandidate = {
        ip: '192.168.1',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      expect(() => encode(TEST_FINGERPRINT, [candidate])).toThrow(/Invalid IPv4/i);
    });

    it('should reject invalid IPv4 with out-of-range octet', () => {
      const candidate: QWBPCandidate = {
        ip: '192.168.1.300',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      expect(() => encode(TEST_FINGERPRINT, [candidate])).toThrow(/Invalid IPv4/i);
    });

    it('should reject invalid IPv6 with too many :: separators', () => {
      const candidate: QWBPCandidate = {
        ip: '2001::db8::1',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      expect(() => encode(TEST_FINGERPRINT, [candidate])).toThrow(/Invalid IPv6/i);
    });

    it('should reject invalid mDNS UUID', () => {
      const candidate: QWBPCandidate = {
        ip: 'invalid-uuid.local',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      expect(() => encode(TEST_FINGERPRINT, [candidate])).toThrow(/Invalid mDNS UUID/i);
    });
  });
});
