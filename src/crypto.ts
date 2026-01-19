/**
 * QWBP Cryptographic Functions
 *
 * Implements HKDF-SHA256 key derivation for ICE credentials
 *
 * @category Crypto
 * @packageDocumentation
 */

import {
  HKDF_INFO_UFRAG,
  HKDF_INFO_PWD,
  HKDF_UFRAG_LENGTH,
  HKDF_PWD_LENGTH,
} from './constants.js';
import type { IceCredentials } from './types.js';

/**
 * Derives bits using HKDF-SHA256
 *
 * @param ikm - Input key material (fingerprint)
 * @param salt - Salt (empty for QWBP)
 * @param info - Context/application-specific info
 * @param length - Number of bytes to derive
 * @returns Derived bytes
 */
async function hkdfDerive(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  // Import IKM as raw key material for HKDF
  const ikmKey = await crypto.subtle.importKey(
    'raw',
    ikm as unknown as ArrayBuffer,
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );

  // Derive bits using HKDF-SHA256
  const derived = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as unknown as ArrayBuffer,
      info: info as unknown as ArrayBuffer,
    },
    ikmKey,
    length * 8 // Convert bytes to bits
  );

  return new Uint8Array(derived);
}

/**
 * Encodes bytes to base64url string (no padding)
 *
 * @category Crypto
 *
 * @param bytes - Bytes to encode
 * @returns Base64url encoded string without padding
 */
export function base64urlEncode(bytes: Uint8Array): string {
  // Convert to base64
  const base64 = btoa(String.fromCharCode(...bytes));

  // Convert to base64url (replace + with -, / with _, remove padding)
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Decodes base64url string to bytes
 *
 * @category Crypto
 *
 * @param str - Base64url encoded string
 * @returns Decoded bytes
 */
export function base64urlDecode(str: string): Uint8Array {
  // Convert from base64url to base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if needed
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }

  // Decode
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Derives ICE credentials from a DTLS fingerprint using HKDF-SHA256
 *
 * @category Crypto
 *
 * @param fingerprint - 32-byte DTLS fingerprint (SHA-256 of certificate)
 * @returns ICE credentials (ufrag and pwd)
 *
 * @example
 * ```typescript
 * const fingerprint = extractFingerprint(sdp);
 * const credentials = await deriveCredentials(fingerprint);
 * console.log(credentials.ufrag); // "ejxenw"
 * console.log(credentials.pwd);   // "TS6KfB2mN9pQ3rS7wX"
 * ```
 */
export async function deriveCredentials(
  fingerprint: Uint8Array
): Promise<IceCredentials> {
  if (fingerprint.length !== 32) {
    throw new Error(
      `Invalid fingerprint length: expected 32, got ${fingerprint.length}`
    );
  }

  // Empty salt - fingerprint is already high-entropy
  const salt = new Uint8Array(0);

  // Derive ufrag (4 bytes -> 6 base64url chars)
  const ufragInfo = new TextEncoder().encode(HKDF_INFO_UFRAG);
  const ufragBytes = await hkdfDerive(
    fingerprint,
    salt,
    ufragInfo,
    HKDF_UFRAG_LENGTH
  );

  // Derive password (18 bytes -> 24 base64url chars)
  const pwdInfo = new TextEncoder().encode(HKDF_INFO_PWD);
  const pwdBytes = await hkdfDerive(fingerprint, salt, pwdInfo, HKDF_PWD_LENGTH);

  return {
    ufrag: base64urlEncode(ufragBytes),
    pwd: base64urlEncode(pwdBytes),
  };
}

/**
 * Extracts fingerprint from SDP string
 *
 * @category Crypto
 *
 * @param sdp - SDP string containing fingerprint line
 * @returns 32-byte fingerprint
 * @throws Error if fingerprint not found or invalid format
 *
 * @example
 * ```typescript
 * const sdp = await pc.createOffer();
 * const fingerprint = extractFingerprintFromSDP(sdp.sdp);
 * ```
 */
export function extractFingerprintFromSDP(sdp: string): Uint8Array {
  const match = sdp.match(/a=fingerprint:sha-256\s+([A-Fa-f0-9:]+)/i);

  if (!match) {
    throw new Error('No SHA-256 fingerprint found in SDP');
  }

  const hexString = match[1].replace(/:/g, '');

  if (hexString.length !== 64) {
    throw new Error(
      `Invalid fingerprint length: expected 64 hex chars, got ${hexString.length}`
    );
  }

  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hexString.substring(i * 2, i * 2 + 2), 16);
  }

  return bytes;
}

/**
 * Formats fingerprint bytes as colon-separated hex string
 *
 * @category Crypto
 *
 * @param fingerprint - 32-byte fingerprint
 * @returns Formatted string like "E7:3B:38:..."
 *
 * @example
 * ```typescript
 * const formatted = formatFingerprint(fingerprint);
 * // "E7:3B:38:46:1A:5D:88:B0:..."
 * ```
 */
export function formatFingerprint(fingerprint: Uint8Array): string {
  return Array.from(fingerprint)
    .map((b) => b.toString(16).toUpperCase().padStart(2, '0'))
    .join(':');
}

/**
 * Compares two fingerprints for role assignment
 *
 * @category Crypto
 *
 * @param a - First fingerprint
 * @param b - Second fingerprint
 * @returns 1 if a > b, -1 if a < b, 0 if equal
 *
 * @example
 * ```typescript
 * const result = compareFingerprints(localFP, remoteFP);
 * if (result > 0) {
 *   role = 'offerer';
 * } else if (result < 0) {
 *   role = 'answerer';
 * } else {
 *   throw new Error('Cannot connect to self');
 * }
 * ```
 */
export function compareFingerprints(
  a: Uint8Array,
  b: Uint8Array
): -1 | 0 | 1 {
  for (let i = 0; i < 32; i++) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

/**
 * Generates a deterministic session ID from fingerprint
 *
 * Uses first 8 bytes of SHA256(fingerprint) as big-endian uint64
 *
 * @category Crypto
 *
 * @param fingerprint - 32-byte fingerprint
 * @returns Session ID as string
 */
export async function generateSessionId(fingerprint: Uint8Array): Promise<string> {
  // Hash the fingerprint to get session ID material
  const hash = await crypto.subtle.digest('SHA-256', fingerprint as unknown as ArrayBuffer);
  const hashBytes = new Uint8Array(hash);

  // Use first 8 bytes as big-endian uint64
  let id = BigInt(0);
  for (let i = 0; i < 8; i++) {
    id = (id << 8n) | BigInt(hashBytes[i]);
  }
  return id.toString();
}

/**
 * Generates a Short Authentication String (SAS) from two fingerprints
 *
 * The SAS is a 4-digit code that both peers can visually verify to detect
 * active MITM attacks. Both peers should see the same code.
 *
 * @category Crypto
 *
 * @param localFingerprint - Local device's 32-byte fingerprint
 * @param remoteFingerprint - Remote device's 32-byte fingerprint
 * @returns 4-digit string (e.g., "1234")
 *
 * @example
 * ```typescript
 * const sas = await generateSAS(localFP, remoteFP);
 * console.log(`Verify this code matches: ${sas}`); // "1234"
 * ```
 */
export async function generateSAS(
  localFingerprint: Uint8Array,
  remoteFingerprint: Uint8Array
): Promise<string> {
  // Combine fingerprints in a deterministic order (sorted)
  // This ensures both peers compute the same SAS regardless of role
  const comparison = compareFingerprints(localFingerprint, remoteFingerprint);

  const combined = new Uint8Array(64);
  if (comparison >= 0) {
    combined.set(localFingerprint, 0);
    combined.set(remoteFingerprint, 32);
  } else {
    combined.set(remoteFingerprint, 0);
    combined.set(localFingerprint, 32);
  }

  // Hash the combined fingerprints
  const hash = await crypto.subtle.digest('SHA-256', combined as unknown as ArrayBuffer);
  const hashBytes = new Uint8Array(hash);

  // Use first 2 bytes as a 4-digit number (0000-9999)
  const value = (hashBytes[0] << 8) | hashBytes[1];
  const sasNumber = value % 10000;

  // Pad to 4 digits
  return sasNumber.toString().padStart(4, '0');
}
