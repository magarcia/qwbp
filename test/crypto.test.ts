/**
 * Crypto module tests
 *
 * Tests for HKDF key derivation, base64url encoding, and fingerprint utilities
 */

import { describe, it, expect } from 'vitest';
import {
  deriveCredentials,
  formatFingerprint,
  compareFingerprints,
  generateSessionId,
  base64urlEncode,
  base64urlDecode,
} from '../src/index.js';
import { TEST_FINGERPRINT } from './fixtures.js';

describe('HKDF Key Derivation', () => {
  it('should derive 6-character ufrag from fingerprint', async () => {
    const credentials = await deriveCredentials(TEST_FINGERPRINT);

    expect(credentials.ufrag.length).toBe(6);
    expect(credentials.ufrag).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('should derive 24-character password from fingerprint', async () => {
    const credentials = await deriveCredentials(TEST_FINGERPRINT);

    expect(credentials.pwd.length).toBe(24);
    expect(credentials.pwd).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('should produce consistent results for same fingerprint', async () => {
    const creds1 = await deriveCredentials(TEST_FINGERPRINT);
    const creds2 = await deriveCredentials(TEST_FINGERPRINT);

    expect(creds1.ufrag).toBe(creds2.ufrag);
    expect(creds1.pwd).toBe(creds2.pwd);
  });

  it('should produce different results for different fingerprints', async () => {
    const otherFingerprint = new Uint8Array(32).fill(0xaa);

    const creds1 = await deriveCredentials(TEST_FINGERPRINT);
    const creds2 = await deriveCredentials(otherFingerprint);

    expect(creds1.ufrag).not.toBe(creds2.ufrag);
    expect(creds1.pwd).not.toBe(creds2.pwd);
  });

  it('should meet RFC 8839 minimum lengths', async () => {
    const credentials = await deriveCredentials(TEST_FINGERPRINT);

    // RFC 8839: ufrag >= 4 chars, pwd >= 22 chars
    expect(credentials.ufrag.length).toBeGreaterThanOrEqual(4);
    expect(credentials.pwd.length).toBeGreaterThanOrEqual(22);
  });

  it('should reject fingerprint with wrong length', async () => {
    const badFingerprint = new Uint8Array(16);

    await expect(deriveCredentials(badFingerprint)).rejects.toThrow(
      /Invalid fingerprint length/i
    );
  });
});

describe('Fingerprint Utilities', () => {
  describe('formatFingerprint', () => {
    it('should format as colon-separated hex', () => {
      const formatted = formatFingerprint(TEST_FINGERPRINT);

      expect(formatted).toBe(
        'E7:3B:38:46:1A:5D:88:B0:C4:2E:9F:7A:1D:6C:3E:8B:' +
        '5F:4A:9D:2C:7E:1B:6F:3A:8D:5C:2E:9B:4F:7A:1C:3D'
      );
    });

    it('should be 95 characters (32 hex pairs + 31 colons)', () => {
      const formatted = formatFingerprint(TEST_FINGERPRINT);
      expect(formatted.length).toBe(95);
    });
  });

  describe('compareFingerprints', () => {
    it('should return 1 when first is greater', () => {
      const a = new Uint8Array(32).fill(0xff);
      const b = new Uint8Array(32).fill(0x00);

      expect(compareFingerprints(a, b)).toBe(1);
    });

    it('should return -1 when first is smaller', () => {
      const a = new Uint8Array(32).fill(0x00);
      const b = new Uint8Array(32).fill(0xff);

      expect(compareFingerprints(a, b)).toBe(-1);
    });

    it('should return 0 when equal', () => {
      expect(compareFingerprints(TEST_FINGERPRINT, TEST_FINGERPRINT)).toBe(0);
    });

    it('should compare byte by byte', () => {
      const a = new Uint8Array(32).fill(0xaa);
      const b = new Uint8Array(32).fill(0xaa);
      b[31] = 0xab;

      expect(compareFingerprints(a, b)).toBe(-1);
    });
  });

  describe('generateSessionId', () => {
    it('should generate deterministic session ID', async () => {
      const id1 = await generateSessionId(TEST_FINGERPRINT);
      const id2 = await generateSessionId(TEST_FINGERPRINT);

      expect(id1).toBe(id2);
    });

    it('should return numeric string', async () => {
      const id = await generateSessionId(TEST_FINGERPRINT);
      expect(id).toMatch(/^\d+$/);
    });
  });
});

describe('Base64url Encoding', () => {
  it('should encode without padding', () => {
    const data = new Uint8Array([1, 2, 3, 4]);
    const encoded = base64urlEncode(data);

    expect(encoded).not.toContain('=');
  });

  it('should use URL-safe characters', () => {
    const data = new Uint8Array([251, 255, 254]);
    const encoded = base64urlEncode(data);

    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
  });
});

describe('Base64url Decoding', () => {
  it('should decode base64url string to bytes', () => {
    const original = new Uint8Array([1, 2, 3, 4]);
    const encoded = base64urlEncode(original);
    const decoded = base64urlDecode(encoded);

    expect(decoded).toEqual(original);
  });

  it('should handle URL-safe characters', () => {
    const original = new Uint8Array([251, 255, 254]);
    const encoded = base64urlEncode(original);
    const decoded = base64urlDecode(encoded);

    expect(decoded).toEqual(original);
  });

  it('should add padding when decoding', () => {
    const decoded = base64urlDecode('AQID');
    expect(decoded).toEqual(new Uint8Array([1, 2, 3]));
  });

  it('should handle strings that need multiple padding chars', () => {
    const decoded = base64urlDecode('AQ');
    expect(decoded).toEqual(new Uint8Array([1]));
  });
});

describe('Role Assignment', () => {
  it('should assign offerer to higher fingerprint', () => {
    const fpA = new Uint8Array(32);
    const fpB = new Uint8Array(32);
    fpA[0] = 0xe7;
    fpB[0] = 0x8a;

    expect(compareFingerprints(fpA, fpB)).toBe(1);
  });

  it('should assign answerer to lower fingerprint', () => {
    const fpA = new Uint8Array(32);
    const fpB = new Uint8Array(32);
    fpA[0] = 0x1a;
    fpB[0] = 0x9f;

    expect(compareFingerprints(fpA, fpB)).toBe(-1);
  });

  it('should compare deeply when early bytes match', () => {
    const fpA = new Uint8Array(32).fill(0xaa);
    const fpB = new Uint8Array(32).fill(0xaa);
    fpA[7] = 0x33;
    fpB[7] = 0x34;

    expect(compareFingerprints(fpA, fpB)).toBe(-1);
  });
});
