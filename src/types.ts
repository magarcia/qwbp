/**
 * QWBP TypeScript Type Definitions
 */

/**
 * Address family for ICE candidates
 */
export enum AddressFamily {
  IPv4 = 0b00,
  IPv6 = 0b01,
  mDNS = 0b10,
}

/**
 * Transport protocol
 */
export enum Protocol {
  UDP = 0,
  TCP = 1,
}

/**
 * ICE candidate type
 */
export enum CandidateType {
  Host = 0,
  ServerReflexive = 1,
}

/**
 * TCP candidate type (only relevant for TCP candidates)
 */
export enum TcpType {
  Passive = 0b00,
  Active = 0b01,
  SimultaneousOpen = 0b10,
}

/**
 * Role in WebRTC connection (determined by fingerprint comparison)
 */
export enum Role {
  Offerer = 'offerer',
  Answerer = 'answerer',
}

/**
 * Connection state
 */
export enum ConnectionState {
  Idle = 'idle',
  Gathering = 'gathering',
  Displaying = 'displaying',
  ScannedOne = 'scanned-one',
  Connecting = 'connecting',
  Connected = 'connected',
  Failed = 'failed',
  Closed = 'closed',
}

/**
 * Represents an ICE candidate in QWBP format
 */
export interface QWBPCandidate {
  /** IP address or mDNS hostname */
  ip: string;

  /** Port number (1-65535) */
  port: number;

  /** Candidate type: host or server-reflexive */
  type: 'host' | 'srflx';

  /** Transport protocol */
  protocol: 'udp' | 'tcp';

  /** TCP type (only for TCP candidates) */
  tcpType?: 'passive' | 'active' | 'so';
}

/**
 * Decoded QWBP packet
 */
export interface QWBPPacket {
  /** Protocol version (currently 0) */
  version: number;

  /** 32-byte DTLS fingerprint */
  fingerprint: Uint8Array;

  /** ICE candidates */
  candidates: QWBPCandidate[];
}

/**
 * ICE credentials derived via HKDF
 */
export interface IceCredentials {
  /** ICE username fragment (6 chars) */
  ufrag: string;

  /** ICE password (24 chars) */
  pwd: string;
}

/**
 * Peer information after QR scan
 */
export interface PeerInfo {
  /** 32-byte DTLS fingerprint */
  fingerprint: Uint8Array;

  /** ICE candidates */
  candidates: QWBPCandidate[];

  /** Derived ICE credentials */
  credentials: IceCredentials;
}

/**
 * Configuration options for QWBPConnection
 */
export interface QWBPOptions {
  /** ICE servers for STUN/TURN */
  iceServers?: RTCIceServer[];

  /** Maximum number of candidates to include (default: 4) */
  maxCandidates?: number;

  /** Session timeout in milliseconds (default: 30000) */
  timeout?: number;

  /** Callback when state changes */
  onStateChange?: (state: ConnectionState) => void;

  /** Callback when DataChannel is ready */
  onDataChannel?: (channel: RTCDataChannel) => void;

  /** Callback when error occurs */
  onError?: (error: Error) => void;
}

/**
 * Result of SDP reconstruction
 */
export interface ReconstructedSDP {
  /** The SDP string */
  sdp: string;

  /** SDP type: offer or answer */
  type: RTCSdpType;
}
