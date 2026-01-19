/**
 * Decoder module tests
 *
 * Tests for packet decoding and validation
 */

import { describe, it, expect } from 'vitest';
import {
  encode,
  decode,
  isValidPacket,
  MAGIC_BYTE,
  PROTOCOL_VERSION,
} from '../src/index.js';
import type { QWBPCandidate } from '../src/index.js';
import { TEST_FINGERPRINT } from './fixtures.js';

describe('Decoder', () => {
  describe('IPv4 Candidates', () => {
    it('should decode single IPv4 host candidate', () => {
      const candidate: QWBPCandidate = {
        ip: '192.168.1.5',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      const decoded = decode(packet);

      expect(decoded.version).toBe(0);
      expect(decoded.fingerprint).toEqual(TEST_FINGERPRINT);
      expect(decoded.candidates.length).toBe(1);
      expect(decoded.candidates[0].ip).toBe('192.168.1.5');
      expect(decoded.candidates[0].port).toBe(54321);
      expect(decoded.candidates[0].type).toBe('host');
      expect(decoded.candidates[0].protocol).toBe('udp');
    });

    it('should decode multiple candidates', () => {
      const candidates: QWBPCandidate[] = [
        { ip: '192.168.1.5', port: 54321, type: 'host', protocol: 'udp' },
        { ip: '192.168.1.6', port: 54322, type: 'host', protocol: 'udp' },
        { ip: '10.0.0.100', port: 54323, type: 'host', protocol: 'udp' },
        { ip: '203.0.113.50', port: 54324, type: 'srflx', protocol: 'udp' },
      ];

      const packet = encode(TEST_FINGERPRINT, candidates);
      const decoded = decode(packet);

      expect(decoded.candidates.length).toBe(4);
      expect(decoded.candidates[3].type).toBe('srflx');
      expect(decoded.candidates[3].ip).toBe('203.0.113.50');
    });
  });

  describe('IPv6 Candidates', () => {
    it('should decode IPv6 address', () => {
      const candidate: QWBPCandidate = {
        ip: '2001:db8:85a3::8a2e:370:7334',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      const decoded = decode(packet);

      expect(decoded.candidates[0].ip).toContain('2001');
      expect(decoded.candidates[0].ip).toContain('db8');
      expect(decoded.candidates[0].port).toBe(54321);
    });
  });

  describe('mDNS Candidates', () => {
    it('should decode mDNS hostname', () => {
      const candidate: QWBPCandidate = {
        ip: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890.local',
        port: 54321,
        type: 'host',
        protocol: 'udp',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      const decoded = decode(packet);

      expect(decoded.candidates[0].ip).toBe(
        'a1b2c3d4-e5f6-7890-abcd-ef1234567890.local'
      );
    });
  });

  describe('TCP Candidates', () => {
    it('should decode TCP passive type', () => {
      const candidate: QWBPCandidate = {
        ip: '192.168.1.5',
        port: 9000,
        type: 'host',
        protocol: 'tcp',
        tcpType: 'passive',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      const decoded = decode(packet);

      expect(decoded.candidates[0].protocol).toBe('tcp');
      expect(decoded.candidates[0].tcpType).toBe('passive');
    });

    it('should decode TCP active type', () => {
      const candidate: QWBPCandidate = {
        ip: '192.168.1.5',
        port: 9000,
        type: 'host',
        protocol: 'tcp',
        tcpType: 'active',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      const decoded = decode(packet);

      expect(decoded.candidates[0].protocol).toBe('tcp');
      expect(decoded.candidates[0].tcpType).toBe('active');
    });

    it('should decode TCP so type', () => {
      const candidate: QWBPCandidate = {
        ip: '192.168.1.5',
        port: 9000,
        type: 'host',
        protocol: 'tcp',
        tcpType: 'so',
      };

      const packet = encode(TEST_FINGERPRINT, [candidate]);
      const decoded = decode(packet);

      expect(decoded.candidates[0].protocol).toBe('tcp');
      expect(decoded.candidates[0].tcpType).toBe('so');
    });
  });

  describe('Error Handling', () => {
    const validCandidate: QWBPCandidate = {
      ip: '192.168.1.5',
      port: 54321,
      type: 'host',
      protocol: 'udp',
    };

    it('should reject packets with wrong magic byte', () => {
      const packet = encode(TEST_FINGERPRINT, [validCandidate]);
      packet[0] = 0x00;

      expect(() => decode(packet)).toThrow(/magic byte/i);
    });

    it('should reject packets that are too short', () => {
      const shortPacket = new Uint8Array([MAGIC_BYTE, PROTOCOL_VERSION]);

      expect(() => decode(shortPacket)).toThrow(/too short/i);
    });

    it('should reject unknown versions', () => {
      const packet = encode(TEST_FINGERPRINT, [validCandidate]);
      packet[1] = 0x07;

      expect(() => decode(packet)).toThrow(/version/i);
    });

    it('should reject truncated IPv4 candidate', () => {
      const packet = new Uint8Array(44);
      packet[0] = MAGIC_BYTE;
      packet[1] = PROTOCOL_VERSION;
      packet.set(TEST_FINGERPRINT, 2);
      // First valid candidate
      packet[34] = 0x00;
      packet[35] = 192;
      packet[36] = 168;
      packet[37] = 1;
      packet[38] = 5;
      packet[39] = 0xd4;
      packet[40] = 0x31;
      // Second truncated candidate
      packet[41] = 0x00;
      packet[42] = 192;
      packet[43] = 168;

      expect(() => decode(packet)).toThrow(/truncated.*IPv4/i);
    });

    it('should reject truncated IPv6 candidate', () => {
      const packet = new Uint8Array(41);
      packet[0] = MAGIC_BYTE;
      packet[1] = PROTOCOL_VERSION;
      packet.set(TEST_FINGERPRINT, 2);
      packet[34] = 0x01;

      expect(() => decode(packet)).toThrow(/truncated.*IPv6/i);
    });

    it('should reject truncated mDNS candidate', () => {
      const packet = new Uint8Array(41);
      packet[0] = MAGIC_BYTE;
      packet[1] = PROTOCOL_VERSION;
      packet.set(TEST_FINGERPRINT, 2);
      packet[34] = 0x02;

      expect(() => decode(packet)).toThrow(/truncated.*mDNS/i);
    });

    it('should reject unknown address family', () => {
      const packet = new Uint8Array(41);
      packet[0] = MAGIC_BYTE;
      packet[1] = PROTOCOL_VERSION;
      packet.set(TEST_FINGERPRINT, 2);
      packet[34] = 0x03;

      expect(() => decode(packet)).toThrow(/Unknown address family/i);
    });
  });
});

describe('isValidPacket', () => {
  const validCandidate: QWBPCandidate = {
    ip: '192.168.1.5',
    port: 54321,
    type: 'host',
    protocol: 'udp',
  };

  it('should return true for valid packet', () => {
    const packet = encode(TEST_FINGERPRINT, [validCandidate]);
    expect(isValidPacket(packet)).toBe(true);
  });

  it('should return false for packet too short', () => {
    const shortPacket = new Uint8Array([MAGIC_BYTE, PROTOCOL_VERSION]);
    expect(isValidPacket(shortPacket)).toBe(false);
  });

  it('should return false for wrong magic byte', () => {
    const packet = encode(TEST_FINGERPRINT, [validCandidate]);
    packet[0] = 0x00;
    expect(isValidPacket(packet)).toBe(false);
  });

  it('should return false for unsupported version', () => {
    const packet = encode(TEST_FINGERPRINT, [validCandidate]);
    packet[1] = 0x07;
    expect(isValidPacket(packet)).toBe(false);
  });
});
