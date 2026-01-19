/**
 * QWBP Packet Decoder
 *
 * Decodes binary QWBP packets into fingerprint and ICE candidates
 *
 * @category Decoder
 * @packageDocumentation
 */

import {
  MAGIC_BYTE,
  FINGERPRINT_SIZE,
  HEADER_SIZE,
  MIN_PACKET_SIZE,
} from './constants.js';
import { QWBPDecodeError } from './errors.js';
import type { QWBPPacket, QWBPCandidate } from './types.js';

export { QWBPDecodeError };

/**
 * Decodes a QWBP packet from binary data
 *
 * @category Decoder
 *
 * @param data - Binary packet data
 * @returns Decoded packet with fingerprint and candidates
 * @throws {@link QWBPDecodeError} if packet is invalid, too short, has wrong magic byte,
 * unsupported version, or truncated candidate data
 *
 * @example
 * ```typescript
 * const packet = QWBPDecoder.decode(scannedQRData);
 * console.log(packet.fingerprint); // Uint8Array(32)
 * console.log(packet.candidates);  // QWBPCandidate[]
 * ```
 */
export function decode(data: Uint8Array): QWBPPacket {
  // Validate minimum size
  if (data.length < MIN_PACKET_SIZE) {
    throw new QWBPDecodeError(
      `Packet too short: expected at least ${MIN_PACKET_SIZE} bytes, got ${data.length}`
    );
  }

  // Validate magic byte
  if (data[0] !== MAGIC_BYTE) {
    throw new QWBPDecodeError(
      `Invalid magic byte: expected 0x${MAGIC_BYTE.toString(16)}, got 0x${data[0].toString(16)}`
    );
  }

  // Parse version (bits 0-2 of byte 1)
  const version = data[1] & 0b111;

  // Only version 0 is supported
  if (version !== 0) {
    throw new QWBPDecodeError(`Unsupported protocol version: ${version}`);
  }

  // Extract fingerprint
  const fingerprint = data.slice(HEADER_SIZE, HEADER_SIZE + FINGERPRINT_SIZE);

  // Parse candidates
  const candidates: QWBPCandidate[] = [];
  let offset = HEADER_SIZE + FINGERPRINT_SIZE;

  while (offset < data.length) {
    const result = decodeCandidate(data, offset);
    candidates.push(result.candidate);
    offset += result.bytesRead;
  }

  return {
    version,
    fingerprint,
    candidates,
  };
}

/**
 * Decodes a single candidate from the packet
 */
function decodeCandidate(
  data: Uint8Array,
  offset: number
): { candidate: QWBPCandidate; bytesRead: number } {
  if (offset >= data.length) {
    throw new QWBPDecodeError('Unexpected end of packet while reading candidate');
  }

  const flags = data[offset];

  // Parse flags
  const addressFamily = flags & 0b11;
  const protocol = (flags >> 2) & 0b1;
  const type = (flags >> 3) & 0b1;
  const tcpType = (flags >> 4) & 0b11;

  // Determine address length and parse
  let addressLength: number;
  let ip: string;

  switch (addressFamily) {
    case 0b00: // IPv4
      addressLength = 4;
      if (offset + 1 + addressLength + 2 > data.length) {
        throw new QWBPDecodeError('Packet truncated: incomplete IPv4 candidate');
      }
      ip = formatIPv4(data.slice(offset + 1, offset + 1 + addressLength));
      break;

    case 0b01: // IPv6
      addressLength = 16;
      if (offset + 1 + addressLength + 2 > data.length) {
        throw new QWBPDecodeError('Packet truncated: incomplete IPv6 candidate');
      }
      ip = formatIPv6(data.slice(offset + 1, offset + 1 + addressLength));
      break;

    case 0b10: // mDNS
      addressLength = 16;
      if (offset + 1 + addressLength + 2 > data.length) {
        throw new QWBPDecodeError('Packet truncated: incomplete mDNS candidate');
      }
      ip = formatMdns(data.slice(offset + 1, offset + 1 + addressLength));
      break;

    default:
      throw new QWBPDecodeError(`Unknown address family: ${addressFamily}`);
  }

  // Parse port (big-endian)
  const portOffset = offset + 1 + addressLength;
  const port = (data[portOffset] << 8) | data[portOffset + 1];

  // Build candidate object
  const candidate: QWBPCandidate = {
    ip,
    port,
    type: type === 1 ? 'srflx' : 'host',
    protocol: protocol === 1 ? 'tcp' : 'udp',
  };

  // Add TCP type if applicable
  if (protocol === 1) {
    switch (tcpType) {
      case 0b01:
        candidate.tcpType = 'active';
        break;
      case 0b10:
        candidate.tcpType = 'so';
        break;
      default:
        candidate.tcpType = 'passive';
    }
  }

  return {
    candidate,
    bytesRead: 1 + addressLength + 2,
  };
}

/**
 * Formats IPv4 bytes as dotted-decimal string
 */
function formatIPv4(bytes: Uint8Array): string {
  return Array.from(bytes).join('.');
}

/**
 * Formats IPv6 bytes as colon-separated hex string
 */
function formatIPv6(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    const value = (bytes[i] << 8) | bytes[i + 1];
    parts.push(value.toString(16));
  }

  // Compress consecutive zeros (simple implementation)
  let result = parts.join(':');

  // Find longest run of zeros for :: compression
  const zeroRuns = result.match(/(?:^|:)(0(?::0)+)(?::|$)/g);
  if (zeroRuns) {
    const longest = zeroRuns.reduce((a, b) => (a.length > b.length ? a : b));
    result = result.replace(longest, '::');
  }

  return result;
}

/**
 * Formats mDNS UUID bytes as hostname
 */
function formatMdns(bytes: Uint8Array): string {
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.local
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}.local`;
}

/**
 * Validates a QWBP packet without fully parsing it
 *
 * @category Decoder
 *
 * @param data - Binary data to validate
 * @returns true if the data appears to be a valid QWBP packet
 */
export function isValidPacket(data: Uint8Array): boolean {
  if (data.length < MIN_PACKET_SIZE) return false;
  if (data[0] !== MAGIC_BYTE) return false;

  const version = data[1] & 0b111;
  if (version !== 0) return false;

  return true;
}

// Export as namespace for convenient usage
export const QWBPDecoder = {
  decode,
  isValidPacket,
  QWBPDecodeError,
};
