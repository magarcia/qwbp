/**
 * QWBP Packet Encoder
 *
 * Encodes DTLS fingerprint and ICE candidates into binary QWBP format
 *
 * @category Encoder
 * @packageDocumentation
 */

import {
  MAGIC_BYTE,
  PROTOCOL_VERSION,
  FINGERPRINT_SIZE,
  HEADER_SIZE,
} from './constants.js';
import { QWBPEncodeError } from './errors.js';
import type { QWBPCandidate } from './types.js';

export { QWBPEncodeError };

/**
 * Encodes a QWBP packet
 *
 * @category Encoder
 *
 * @param fingerprint - 32-byte DTLS fingerprint
 * @param candidates - Array of ICE candidates to encode
 * @returns Encoded binary packet
 * @throws {@link QWBPEncodeError} if fingerprint is not 32 bytes or IP addresses are invalid
 *
 * @example
 * ```typescript
 * const packet = QWBPEncoder.encode(fingerprint, [
 *   { ip: '192.168.1.5', port: 54321, type: 'host', protocol: 'udp' },
 *   { ip: '203.0.113.50', port: 54322, type: 'srflx', protocol: 'udp' },
 * ]);
 * ```
 */
export function encode(
  fingerprint: Uint8Array,
  candidates: QWBPCandidate[]
): Uint8Array {
  if (fingerprint.length !== FINGERPRINT_SIZE) {
    throw new QWBPEncodeError(
      `Invalid fingerprint length: expected ${FINGERPRINT_SIZE}, got ${fingerprint.length}`
    );
  }

  // Calculate total size
  let candidatesSize = 0;
  for (const candidate of candidates) {
    candidatesSize += getCandidateSize(candidate);
  }

  const totalSize = HEADER_SIZE + FINGERPRINT_SIZE + candidatesSize;
  const packet = new Uint8Array(totalSize);
  let offset = 0;

  // Write header
  packet[offset++] = MAGIC_BYTE;
  packet[offset++] = PROTOCOL_VERSION; // Version in bits 0-2, reserved bits 3-7

  // Write fingerprint
  packet.set(fingerprint, offset);
  offset += FINGERPRINT_SIZE;

  // Write candidates
  for (const candidate of candidates) {
    const encoded = encodeCandidate(candidate);
    packet.set(encoded, offset);
    offset += encoded.length;
  }

  return packet;
}

/**
 * Gets the encoded size of a candidate
 */
function getCandidateSize(candidate: QWBPCandidate): number {
  if (isMdns(candidate.ip)) {
    return 19; // flags(1) + uuid(16) + port(2)
  } else if (isIPv6(candidate.ip)) {
    return 19; // flags(1) + ipv6(16) + port(2)
  } else {
    return 7; // flags(1) + ipv4(4) + port(2)
  }
}

/**
 * Encodes a single ICE candidate
 */
function encodeCandidate(candidate: QWBPCandidate): Uint8Array {
  const isMdnsAddr = isMdns(candidate.ip);
  const isIPv6Addr = !isMdnsAddr && isIPv6(candidate.ip);

  // Determine address family
  let addressFamily: number;
  let addressBytes: Uint8Array;

  if (isMdnsAddr) {
    addressFamily = 0b10; // mDNS
    addressBytes = parseMdnsUUID(candidate.ip);
  } else if (isIPv6Addr) {
    addressFamily = 0b01; // IPv6
    addressBytes = parseIPv6(candidate.ip);
  } else {
    addressFamily = 0b00; // IPv4
    addressBytes = parseIPv4(candidate.ip);
  }

  // Build flags byte
  const protocol = candidate.protocol === 'tcp' ? 1 : 0;
  const type = candidate.type === 'srflx' ? 1 : 0;

  let tcpType = 0;
  if (candidate.protocol === 'tcp' && candidate.tcpType) {
    switch (candidate.tcpType) {
      case 'active':
        tcpType = 0b01;
        break;
      case 'so':
        tcpType = 0b10;
        break;
      default:
        tcpType = 0b00; // passive
    }
  }

  const flags =
    addressFamily | (protocol << 2) | (type << 3) | (tcpType << 4);

  // Build result
  const result = new Uint8Array(1 + addressBytes.length + 2);
  result[0] = flags;
  result.set(addressBytes, 1);

  // Port in big-endian
  result[result.length - 2] = (candidate.port >> 8) & 0xff;
  result[result.length - 1] = candidate.port & 0xff;

  return result;
}

/**
 * Checks if an address is mDNS format
 */
function isMdns(ip: string): boolean {
  return ip.endsWith('.local');
}

/**
 * Checks if an address is IPv6
 */
function isIPv6(ip: string): boolean {
  return ip.includes(':');
}

/**
 * Parses IPv4 address string to bytes
 */
function parseIPv4(ip: string): Uint8Array {
  const parts = ip.split('.');
  if (parts.length !== 4) {
    throw new QWBPEncodeError(`Invalid IPv4 address: ${ip}`);
  }

  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const value = parseInt(parts[i], 10);
    if (isNaN(value) || value < 0 || value > 255) {
      throw new QWBPEncodeError(`Invalid IPv4 address: ${ip}`);
    }
    bytes[i] = value;
  }

  return bytes;
}

/**
 * Validates IPv6 address format
 */
function isValidIPv6Format(ip: string): boolean {
  // Remove brackets if present
  const cleaned = ip.replace(/^\[|\]$/g, '');

  // Check for IPv4-mapped format (::ffff:x.x.x.x)
  if (/^::ffff:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/i.test(cleaned)) {
    return true;
  }

  // Basic IPv6 validation: only hex digits, colons, and at most one ::
  if (!/^[0-9a-fA-F:]+$/.test(cleaned)) {
    return false;
  }

  // Cannot have more than one ::
  const doubleColonCount = (cleaned.match(/::/g) || []).length;
  if (doubleColonCount > 1) {
    return false;
  }

  // Cannot start or end with single colon (unless part of ::)
  if (
    (cleaned.startsWith(':') && !cleaned.startsWith('::')) ||
    (cleaned.endsWith(':') && !cleaned.endsWith('::'))
  ) {
    return false;
  }

  return true;
}

/**
 * Parses IPv6 address string to bytes
 *
 * Handles:
 * - Standard format (2001:db8::1)
 * - Compressed format (::1, fe80::)
 * - IPv4-mapped format (::ffff:192.168.1.1)
 * - Bracketed format ([2001:db8::1])
 */
function parseIPv6(ip: string): Uint8Array {
  // Remove brackets if present
  const cleaned = ip.replace(/^\[|\]$/g, '');

  if (!isValidIPv6Format(cleaned)) {
    throw new QWBPEncodeError(`Invalid IPv6 address: ${ip}`);
  }

  const bytes = new Uint8Array(16);

  // Handle IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
  const ipv4MappedMatch = cleaned.match(
    /^::ffff:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/i
  );
  if (ipv4MappedMatch) {
    // Set the ::ffff: prefix
    bytes[10] = 0xff;
    bytes[11] = 0xff;
    // Set the IPv4 portion
    for (let i = 0; i < 4; i++) {
      const octet = parseInt(ipv4MappedMatch[i + 1], 10);
      if (octet > 255) {
        throw new QWBPEncodeError(`Invalid IPv4-mapped IPv6 address: ${ip}`);
      }
      bytes[12 + i] = octet;
    }
    return bytes;
  }

  // Handle :: expansion
  const parts = cleaned.split('::');
  if (parts.length > 2) {
    throw new QWBPEncodeError(`Invalid IPv6 address: ${ip}`);
  }

  let leftParts: string[] = [];
  let rightParts: string[] = [];

  if (parts[0]) {
    leftParts = parts[0].split(':').filter((p) => p !== '');
  }
  if (parts.length > 1 && parts[1]) {
    rightParts = parts[1].split(':').filter((p) => p !== '');
  }

  // Validate total parts count
  const totalParts = leftParts.length + rightParts.length;
  if (totalParts > 8 || (parts.length === 1 && totalParts !== 8)) {
    throw new QWBPEncodeError(`Invalid IPv6 address: ${ip}`);
  }

  // Calculate how many zero groups we need to fill
  const zeroGroups = 8 - totalParts;

  // Build the full 8-part address
  const allParts: string[] = [
    ...leftParts,
    ...Array(zeroGroups).fill('0'),
    ...rightParts,
  ];

  // Convert to bytes
  for (let i = 0; i < 8; i++) {
    const hexPart = allParts[i] || '0';

    // Validate hex part (max 4 hex digits)
    if (hexPart.length > 4) {
      throw new QWBPEncodeError(`Invalid IPv6 address: ${ip}`);
    }

    const value = parseInt(hexPart, 16);
    if (isNaN(value) || value > 0xffff) {
      throw new QWBPEncodeError(`Invalid IPv6 address: ${ip}`);
    }

    bytes[i * 2] = (value >> 8) & 0xff;
    bytes[i * 2 + 1] = value & 0xff;
  }

  return bytes;
}

/**
 * Parses mDNS hostname to UUID bytes
 *
 * Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.local
 */
function parseMdnsUUID(hostname: string): Uint8Array {
  // Remove .local suffix
  const uuid = hostname.replace('.local', '').replace(/-/g, '');

  if (uuid.length !== 32) {
    throw new QWBPEncodeError(`Invalid mDNS UUID: ${hostname}`);
  }

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(uuid.substring(i * 2, i * 2 + 2), 16);
  }

  return bytes;
}

/**
 * Extracts and encodes candidates from SDP
 *
 * Uses smart selection to ensure NAT traversal capability:
 * - Always includes at least one srflx candidate if available
 * - Fills remaining slots with host candidates (prioritizing IPv4)
 *
 * @category Encoder
 *
 * @param sdp - SDP string containing candidate lines
 * @param maxCandidates - Maximum number of candidates to extract (default: 4)
 * @returns Array of QWBP candidates
 */
export function extractCandidatesFromSDP(
  sdp: string,
  maxCandidates = 4
): QWBPCandidate[] {
  const allCandidates: QWBPCandidate[] = [];
  const lines = sdp.split('\n');

  for (const line of lines) {
    if (!line.startsWith('a=candidate:')) continue;

    const candidate = parseCandidateLine(line);
    if (candidate) {
      allCandidates.push(candidate);
    }
  }

  // Separate candidates by type
  const hostCandidates = allCandidates.filter((c) => c.type === 'host');
  const srflxCandidates = allCandidates.filter((c) => c.type === 'srflx');

  // Sort each group: IPv4 before IPv6/mDNS
  const sortByAddressType = (a: QWBPCandidate, b: QWBPCandidate): number => {
    const aIsIPv4 = !a.ip.includes(':') && !a.ip.endsWith('.local');
    const bIsIPv4 = !b.ip.includes(':') && !b.ip.endsWith('.local');
    if (aIsIPv4 !== bIsIPv4) {
      return aIsIPv4 ? -1 : 1;
    }
    return 0;
  };

  hostCandidates.sort(sortByAddressType);
  srflxCandidates.sort(sortByAddressType);

  // Smart selection: ensure at least one srflx if available
  const result: QWBPCandidate[] = [];

  if (srflxCandidates.length > 0) {
    // Reserve one slot for srflx, fill the rest with host candidates
    const hostSlots = maxCandidates - 1;
    result.push(...hostCandidates.slice(0, hostSlots));
    result.push(srflxCandidates[0]);
  } else {
    // No srflx available, use all host candidates
    result.push(...hostCandidates.slice(0, maxCandidates));
  }

  return result;
}

/**
 * Parses a single SDP candidate line
 *
 * Supports both UDP and TCP candidates per the specification
 */
function parseCandidateLine(line: string): QWBPCandidate | null {
  // a=candidate:foundation component protocol priority ip port typ type [extensions]
  const match = line.match(
    /a=candidate:\S+\s+\d+\s+(\w+)\s+\d+\s+(\S+)\s+(\d+)\s+typ\s+(\w+)/
  );

  if (!match) return null;

  const [, protocol, ip, portStr, type] = match;
  const protocolLower = protocol.toLowerCase();
  const typeLower = type.toLowerCase();

  // Support UDP and TCP, and host/srflx types
  if (protocolLower !== 'udp' && protocolLower !== 'tcp') return null;
  if (typeLower !== 'host' && typeLower !== 'srflx') return null;

  const port = parseInt(portStr, 10);
  if (isNaN(port) || port < 1 || port > 65535) return null;

  const candidate: QWBPCandidate = {
    ip,
    port,
    type: typeLower as 'host' | 'srflx',
    protocol: protocolLower as 'udp' | 'tcp',
  };

  // Extract TCP type if present
  if (protocolLower === 'tcp') {
    const tcpTypeMatch = line.match(/tcptype\s+(\w+)/);
    if (tcpTypeMatch) {
      const tcpType = tcpTypeMatch[1].toLowerCase();
      if (tcpType === 'active' || tcpType === 'passive' || tcpType === 'so') {
        candidate.tcpType = tcpType;
      }
    }
  }

  return candidate;
}

// Export as namespace for convenient usage
export const QWBPEncoder = {
  encode,
  extractCandidatesFromSDP,
};
