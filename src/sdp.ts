/**
 * QWBP SDP Reconstruction
 *
 * Reconstructs valid WebRTC SDP from QWBP packet data
 *
 * @category SDP
 * @packageDocumentation
 */

import { SDP_TEMPLATE, CANDIDATE_PRIORITIES } from './constants.js';
import {
  formatFingerprint,
  generateSessionId,
  deriveCredentials,
} from './crypto.js';
import type { QWBPCandidate, IceCredentials } from './types.js';

/**
 * Generates a deterministic foundation from candidate data
 *
 * Foundation should be unique per candidate but deterministic
 */
async function generateFoundation(
  type: string,
  protocol: string,
  ip: string,
  port: number
): Promise<string> {
  const data = `${type}${protocol}${ip}${port}`;
  const encoded = new TextEncoder().encode(data);
  const hash = await crypto.subtle.digest('SHA-256', encoded);
  const bytes = new Uint8Array(hash);

  // Use first 4 bytes as hex string
  return Array.from(bytes.slice(0, 4))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Gets the priority for a candidate based on type and protocol
 */
function getCandidatePriority(
  type: 'host' | 'srflx',
  protocol: 'udp' | 'tcp'
): number {
  if (type === 'srflx') {
    return CANDIDATE_PRIORITIES.SRFLX;
  }
  return protocol === 'udp'
    ? CANDIDATE_PRIORITIES.HOST_UDP
    : CANDIDATE_PRIORITIES.HOST_TCP;
}

/**
 * Builds a candidate string for use with RTCPeerConnection.addIceCandidate()
 *
 * @category SDP
 *
 * @param candidate - QWBP candidate data
 * @returns Candidate string (without "a=" prefix)
 */
export async function buildCandidateString(
  candidate: QWBPCandidate
): Promise<string> {
  const foundation = await generateFoundation(
    candidate.type,
    candidate.protocol,
    candidate.ip,
    candidate.port
  );

  const priority = getCandidatePriority(candidate.type, candidate.protocol);

  let str = `candidate:${foundation} 1 ${candidate.protocol} ${priority} ${candidate.ip} ${candidate.port} typ ${candidate.type}`;

  // For srflx candidates, add raddr/rport (required by browsers)
  if (candidate.type === 'srflx') {
    str += ` raddr ${candidate.ip} rport ${candidate.port}`;
  }

  // Add TCP type if applicable
  if (candidate.protocol === 'tcp' && candidate.tcpType) {
    str += ` tcptype ${candidate.tcpType}`;
  }

  return str;
}

/**
 * Reconstructs a minimal SDP from QWBP data (without candidates)
 *
 * Candidates should be added separately via RTCPeerConnection.addIceCandidate()
 * to avoid browser-specific SDP parsing issues with IPv6, mDNS, etc.
 *
 * @category SDP
 *
 * @param fingerprint - 32-byte DTLS fingerprint
 * @param isOffer - Whether this is an offer (true) or answer (false)
 * @param credentials - Optional pre-computed credentials (if not provided, will derive)
 * @returns Reconstructed SDP string (without candidates)
 *
 * @example
 * ```typescript
 * const sdp = await reconstructSDP(remoteFingerprint, true);
 * await pc.setRemoteDescription({ type: 'offer', sdp });
 * // Then add candidates via addIceCandidate()
 * ```
 */
export async function reconstructSDP(
  fingerprint: Uint8Array,
  isOffer: boolean,
  credentials?: IceCredentials
): Promise<string> {
  // Derive credentials if not provided
  const creds = credentials || (await deriveCredentials(fingerprint));

  // Generate session ID from fingerprint
  const sessionId = await generateSessionId(fingerprint);

  // Format fingerprint for SDP
  const fingerprintStr = formatFingerprint(fingerprint);

  // Determine setup value
  // Offer: actpass (can be either active or passive)
  // Answer: active (will initiate DTLS connection)
  const setup = isOffer ? 'actpass' : 'active';

  // Build SDP from template WITHOUT candidates
  // Candidates will be added via addIceCandidate() to avoid browser parsing issues
  // with IPv6, mDNS, and srflx candidate formats
  let sdp = SDP_TEMPLATE.replace('{sessionId}', sessionId)
    .replace('{ufrag}', creds.ufrag)
    .replace('{pwd}', creds.pwd)
    .replace('{fingerprint}', fingerprintStr)
    .replace('{setup}', setup)
    .replace('{candidates}', '');

  // Ensure proper line endings
  sdp = sdp.replace(/\r?\n/g, '\r\n');

  return sdp;
}

/**
 * Validates that an SDP can be used for QWBP
 *
 * @category SDP
 *
 * @param sdp - SDP string to validate
 * @returns true if SDP contains required fields
 */
export function validateSDP(sdp: string): boolean {
  const required = [
    /a=fingerprint:sha-256/i,
    /a=ice-ufrag:/,
    /a=ice-pwd:/,
    /m=application/,
  ];

  return required.every((pattern) => pattern.test(sdp));
}

// Export as namespace
export const SDPReconstructor = {
  reconstructSDP,
  buildCandidateString,
  validateSDP,
};
