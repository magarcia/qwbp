/**
 * QWBP Protocol Constants
 */

/** Magic byte identifying QWBP packets */
export const MAGIC_BYTE = 0x51; // 'Q' ASCII

/** Current protocol version */
export const PROTOCOL_VERSION = 0;

/** Size of DTLS fingerprint in bytes (SHA-256) */
export const FINGERPRINT_SIZE = 32;

/** Size of packet header (magic + version) */
export const HEADER_SIZE = 2;

/** Minimum packet size (header + fingerprint + 1 IPv4 candidate) */
export const MIN_PACKET_SIZE = HEADER_SIZE + FINGERPRINT_SIZE + 7;

/** Size of an IPv4 candidate (flags + ip + port) */
export const IPV4_CANDIDATE_SIZE = 1 + 4 + 2; // 7 bytes

/** Size of an IPv6/mDNS candidate (flags + ip/uuid + port) */
export const IPV6_CANDIDATE_SIZE = 1 + 16 + 2; // 19 bytes

/** HKDF info string for ufrag derivation */
export const HKDF_INFO_UFRAG = 'QWBP-ICE-UFRAG-v1';

/** HKDF info string for password derivation */
export const HKDF_INFO_PWD = 'QWBP-ICE-PWD-v1';

/** Output length for ufrag (produces 6 base64url chars) */
export const HKDF_UFRAG_LENGTH = 4;

/** Output length for password (produces 24 base64url chars) */
export const HKDF_PWD_LENGTH = 18;

/** Default session timeout in milliseconds */
export const DEFAULT_TIMEOUT = 30000;

/** Default maximum candidates to include */
export const DEFAULT_MAX_CANDIDATES = 4;

/** ICE candidate priorities (RFC 8445) */
export const CANDIDATE_PRIORITIES = {
  HOST_UDP: 2122260223,
  HOST_TCP: 2105524223,
  SRFLX: 1686052607,
} as const;

/** Default STUN servers */
export const DEFAULT_ICE_SERVERS: RTCIceServer[] = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
];

/**
 * Recommended QR code error correction level
 *
 * Level L (7% recovery) is optimal for QWBP because:
 * - Screen-displayed QRs have perfect contrast and no physical damage
 * - Higher levels (M=15%, Q=25%, H=30%) increase QR size/version
 * - Using H would push v4 codes back to v5-6, defeating optimization work
 */
export const QR_ERROR_CORRECTION_LEVEL = 'L' as const;

/** SDP template for DataChannel-only connection */
export const SDP_TEMPLATE = `v=0
o=- {sessionId} 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=mid:0
a=ice-ufrag:{ufrag}
a=ice-pwd:{pwd}
a=ice-options:trickle
a=fingerprint:sha-256 {fingerprint}
a=setup:{setup}
a=sctp-port:5000
{candidates}`;
