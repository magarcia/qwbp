/**
 * QWBP - QR-WebRTC Bootstrap Protocol
 *
 * A binary protocol for establishing WebRTC DataChannel connections
 * using QR codes as the signaling channel.
 *
 * @packageDocumentation
 */

// Main connection class
export { QWBPConnection } from './connection.js';

// Error types
export {
  QWBPError,
  QWBPEncodeError,
  QWBPDecodeError,
  QWBPConnectionError,
  QWBPTimeoutError,
  QWBPSelfConnectionError,
  QWBPIceError,
} from './errors.js';

// Encoder/Decoder
export { encode, extractCandidatesFromSDP, QWBPEncoder } from './encoder.js';
export { decode, isValidPacket, QWBPDecoder } from './decoder.js';

// Crypto utilities
export {
  deriveCredentials,
  extractFingerprintFromSDP,
  formatFingerprint,
  compareFingerprints,
  generateSessionId,
  generateSAS,
  base64urlEncode,
  base64urlDecode,
} from './crypto.js';

// SDP reconstruction
export {
  reconstructSDP,
  buildCandidateString,
  validateSDP,
  SDPReconstructor,
} from './sdp.js';

// Types
export {
  AddressFamily,
  Protocol,
  CandidateType,
  TcpType,
  Role,
  ConnectionState,
} from './types.js';

export type {
  QWBPCandidate,
  QWBPPacket,
  IceCredentials,
  PeerInfo,
  QWBPOptions,
  ReconstructedSDP,
} from './types.js';

// Constants
export {
  MAGIC_BYTE,
  PROTOCOL_VERSION,
  FINGERPRINT_SIZE,
  HEADER_SIZE,
  MIN_PACKET_SIZE,
  IPV4_CANDIDATE_SIZE,
  IPV6_CANDIDATE_SIZE,
  DEFAULT_TIMEOUT,
  DEFAULT_MAX_CANDIDATES,
  DEFAULT_ICE_SERVERS,
  CANDIDATE_PRIORITIES,
  QR_ERROR_CORRECTION_LEVEL,
} from './constants.js';
