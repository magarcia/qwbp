/**
 * QWBP Connection Manager
 *
 * High-level API for establishing WebRTC connections via QR codes
 *
 * Uses derived ICE credentials (HKDF from fingerprint) to enable
 * signaling-free WebRTC establishment. The same PC is reused from
 * gathering through connection, with SDP patching to inject derived
 * credentials.
 *
 * @category Connection
 * @packageDocumentation
 */

import {
  DEFAULT_ICE_SERVERS,
  DEFAULT_TIMEOUT,
  DEFAULT_MAX_CANDIDATES,
} from './constants.js';
import { encode, extractCandidatesFromSDP } from './encoder.js';
import { decode, isValidPacket } from './decoder.js';
import {
  QWBPConnectionError,
  QWBPTimeoutError,
  QWBPSelfConnectionError,
  QWBPIceError,
} from './errors.js';
import {
  extractFingerprintFromSDP,
  deriveCredentials,
  compareFingerprints,
  generateSAS,
} from './crypto.js';
import { reconstructSDP, buildCandidateString } from './sdp.js';
import {
  ConnectionState,
  Role,
  type QWBPOptions,
  type QWBPCandidate,
  type PeerInfo,
  type IceCredentials,
} from './types.js';

/**
 * Patches ice-ufrag and ice-pwd in an SDP string
 */
function patchSdpCredentials(
  sdp: string,
  ufrag: string,
  pwd: string
): string {
  return sdp
    .replace(/a=ice-ufrag:\S+/g, `a=ice-ufrag:${ufrag}`)
    .replace(/a=ice-pwd:\S+/g, `a=ice-pwd:${pwd}`);
}

/**
 * High-level connection manager for QWBP
 *
 * Handles the complete flow from QR generation to DataChannel establishment
 *
 * @category Connection
 *
 * @example
 * ```typescript
 * // Device A
 * const connA = new QWBPConnection();
 * await connA.initialize();
 * const qrDataA = connA.getQRPayload();
 * // Display qrDataA as QR code
 *
 * // After scanning Device B's QR:
 * connA.processScannedPayload(scannedData);
 *
 * connA.onDataChannel((channel) => {
 *   channel.send('Hello!');
 * });
 * ```
 */
export class QWBPConnection {
  private pc: RTCPeerConnection | null = null;
  private dataChannel: RTCDataChannel | null = null;
  private state: ConnectionState = ConnectionState.Idle;
  private localFingerprint: Uint8Array | null = null;
  private localCredentials: IceCredentials | null = null;
  private localCandidates: QWBPCandidate[] = [];
  private remoteInfo: PeerInfo | null = null;
  private role: Role | null = null;
  private timeoutId: ReturnType<typeof setTimeout> | null = null;
  private certificate: RTCCertificate | null = null;

  private readonly options: Required<
    Pick<QWBPOptions, 'iceServers' | 'maxCandidates' | 'timeout'>
  > &
    QWBPOptions;

  private dataChannelCallback: ((channel: RTCDataChannel) => void) | null =
    null;

  constructor(options: QWBPOptions = {}) {
    this.options = {
      iceServers: options.iceServers || DEFAULT_ICE_SERVERS,
      maxCandidates: options.maxCandidates || DEFAULT_MAX_CANDIDATES,
      timeout: options.timeout || DEFAULT_TIMEOUT,
      ...options,
    };
  }

  /**
   * Current connection state
   */
  get connectionState(): ConnectionState {
    return this.state;
  }

  /**
   * Assigned role (offerer or answerer), null until both QRs scanned
   */
  get assignedRole(): Role | null {
    return this.role;
  }

  /**
   * Initialize the connection and gather ICE candidates
   *
   * Creates a PC with derived ICE credentials (HKDF from fingerprint).
   * The same PC is reused for the actual connection after role assignment.
   *
   * Must be called before getQRPayload()
   *
   * @throws {@link QWBPConnectionError} if called in wrong state or ICE gathering fails
   */
  async initialize(): Promise<void> {
    if (this.state !== ConnectionState.Idle) {
      throw new QWBPConnectionError(`Cannot initialize in state: ${this.state}`, this.state);
    }

    this.setState(ConnectionState.Gathering);

    // Generate a certificate for this session
    this.certificate = await RTCPeerConnection.generateCertificate({
      name: 'ECDSA',
      namedCurve: 'P-256',
    } as EcKeyGenParams);

    // Create PC with our certificate - this will be reused for connection
    this.pc = new RTCPeerConnection({
      iceServers: this.options.iceServers,
      certificates: [this.certificate],
    });

    // Create a data channel to trigger ICE gathering
    // This channel will be replaced after role assignment
    this.pc.createDataChannel('init');

    // Create offer to trigger ICE gathering
    const offer = await this.pc.createOffer();

    // Extract fingerprint from the offer
    this.localFingerprint = extractFingerprintFromSDP(offer.sdp!);

    // Derive ICE credentials from fingerprint using HKDF
    // This ensures both peers can compute the same credentials
    this.localCredentials = await deriveCredentials(this.localFingerprint);

    // Patch the offer to use derived credentials instead of browser-random ones
    const patchedOffer = patchSdpCredentials(
      offer.sdp!,
      this.localCredentials.ufrag,
      this.localCredentials.pwd
    );

    // Set the patched offer as local description
    await this.pc.setLocalDescription({
      type: 'offer',
      sdp: patchedOffer,
    });

    // Wait for ICE gathering to complete
    await this.waitForIceGathering(this.pc);

    // Extract candidates from complete SDP
    const completeSdp = this.pc.localDescription!.sdp;
    this.localCandidates = extractCandidatesFromSDP(
      completeSdp,
      this.options.maxCandidates
    );

    this.setState(ConnectionState.Displaying);

    // Start session timeout
    this.startTimeout();
  }

  /**
   * Gets the binary payload for QR code generation
   *
   * @returns Uint8Array to encode as QR code (use Byte mode)
   * @throws {@link QWBPConnectionError} if called in wrong state or connection not initialized
   */
  getQRPayload(): Uint8Array {
    if (
      this.state !== ConnectionState.Displaying &&
      this.state !== ConnectionState.ScannedOne
    ) {
      throw new QWBPConnectionError(`Cannot get QR payload in state: ${this.state}`, this.state);
    }

    if (!this.localFingerprint) {
      throw new QWBPConnectionError('Connection not initialized', this.state);
    }

    return encode(this.localFingerprint, this.localCandidates);
  }

  /**
   * Process a scanned QR payload from the remote peer
   *
   * @param data - Binary data from QR code scan
   * @throws {@link QWBPConnectionError} if called in wrong state or packet is invalid
   * @throws {@link QWBPSelfConnectionError} if the scanned QR is from this device
   */
  async processScannedPayload(data: Uint8Array): Promise<void> {
    if (
      this.state !== ConnectionState.Displaying &&
      this.state !== ConnectionState.ScannedOne
    ) {
      throw new QWBPConnectionError(`Cannot process payload in state: ${this.state}`, this.state);
    }

    // Prevent overwriting existing peer info
    if (this.remoteInfo) {
      throw new QWBPConnectionError('Peer already scanned', this.state);
    }

    if (!isValidPacket(data)) {
      throw new QWBPConnectionError('Invalid QWBP packet', this.state);
    }

    const packet = decode(data);

    // Store remote info
    const credentials = await deriveCredentials(packet.fingerprint);
    this.remoteInfo = {
      fingerprint: packet.fingerprint,
      candidates: packet.candidates,
      credentials,
    };

    // Check if we scanned our own QR
    if (
      this.localFingerprint &&
      compareFingerprints(this.localFingerprint, packet.fingerprint) === 0
    ) {
      throw new QWBPSelfConnectionError();
    }

    // Update state if this is our first scan
    if (this.state === ConnectionState.Displaying) {
      this.setState(ConnectionState.ScannedOne);
    }

    // Try to establish connection if we have everything
    await this.tryEstablishConnection();
  }

  /**
   * Attempt to establish the WebRTC connection
   *
   * Reuses the existing PC from initialization. The approach differs by role:
   * - Offerer: PC already has local offer set, just set remote answer
   * - Answerer: Rollback to stable, set remote offer, create/patch answer
   */
  private async tryEstablishConnection(): Promise<void> {
    if (
      !this.localFingerprint ||
      !this.localCredentials ||
      !this.remoteInfo ||
      !this.pc
    ) {
      return;
    }

    // Determine role by fingerprint comparison
    const comparison = compareFingerprints(
      this.localFingerprint,
      this.remoteInfo.fingerprint
    );

    if (comparison === 0) {
      this.handleError(new QWBPSelfConnectionError());
      return;
    }

    this.role = comparison > 0 ? Role.Offerer : Role.Answerer;
    this.setState(ConnectionState.Connecting);

    try {
      // Derive remote peer's credentials from their fingerprint
      const remoteCredentials = await deriveCredentials(
        this.remoteInfo.fingerprint
      );

      if (this.role === Role.Offerer) {
        // OFFERER PATH
        // Our PC already has local offer set (with derived credentials)
        // We just need to set the remote answer

        // Create the data channel for communication
        this.dataChannel = this.pc.createDataChannel('qwbp', {
          ordered: true,
        });
        this.setupDataChannelListeners(this.dataChannel);

        // Reconstruct remote's answer SDP (without candidates)
        const remoteAnswer = await reconstructSDP(
          this.remoteInfo.fingerprint,
          false, // isOffer = false (this is an answer)
          remoteCredentials
        );

        await this.pc.setRemoteDescription({
          type: 'answer',
          sdp: remoteAnswer,
        });

        // Add remote candidates via addIceCandidate (avoids SDP parsing issues)
        await this.addRemoteCandidates(this.remoteInfo.candidates);
      } else {
        // ANSWERER PATH
        // Our PC has local offer set, but we need to be the answerer
        // Use rollback to return to stable state

        await this.pc.setLocalDescription({ type: 'rollback' });

        // Handle incoming data channel from offerer
        this.pc.ondatachannel = (event) => {
          this.dataChannel = event.channel;
          this.setupDataChannelListeners(this.dataChannel);
        };

        // Reconstruct remote's offer SDP (without candidates)
        const remoteOffer = await reconstructSDP(
          this.remoteInfo.fingerprint,
          true, // isOffer = true
          remoteCredentials
        );

        await this.pc.setRemoteDescription({
          type: 'offer',
          sdp: remoteOffer,
        });

        // Add remote candidates via addIceCandidate (avoids SDP parsing issues)
        await this.addRemoteCandidates(this.remoteInfo.candidates);

        // Create answer - browser generates random credentials
        const answer = await this.pc.createAnswer();

        // Patch the answer to use our derived credentials
        const patchedAnswer = patchSdpCredentials(
          answer.sdp!,
          this.localCredentials.ufrag,
          this.localCredentials.pwd
        );

        await this.pc.setLocalDescription({
          type: 'answer',
          sdp: patchedAnswer,
        });
      }

      // Connection should now be establishing via ICE/DTLS
      this.setupConnectionListeners();
    } catch (error) {
      this.handleError(error as Error);
    }
  }

  /**
   * Register callback for when DataChannel is ready
   */
  onDataChannel(callback: (channel: RTCDataChannel) => void): void {
    this.dataChannelCallback = callback;

    // If channel already open, call immediately
    if (this.dataChannel?.readyState === 'open') {
      callback(this.dataChannel);
    }
  }

  /**
   * Get the established DataChannel
   */
  getDataChannel(): RTCDataChannel | null {
    return this.dataChannel;
  }

  /**
   * Get the Short Authentication String (SAS) for visual verification
   *
   * Both peers should display this code and users should verify they match.
   * This detects active MITM attacks where an attacker substitutes their own QR.
   *
   * @returns 4-digit verification code, or null if not yet connected
   *
   * @example
   * ```typescript
   * const sas = await connection.getSAS();
   * if (sas) {
   *   console.log(`Verify this code matches: ${sas}`);
   * }
   * ```
   */
  async getSAS(): Promise<string | null> {
    if (!this.localFingerprint || !this.remoteInfo) {
      return null;
    }

    return generateSAS(this.localFingerprint, this.remoteInfo.fingerprint);
  }

  /**
   * Close the connection and clean up resources
   */
  close(): void {
    this.clearTimeout();

    if (this.dataChannel) {
      this.dataChannel.close();
      this.dataChannel = null;
    }

    if (this.pc) {
      this.pc.close();
      this.pc = null;
    }

    this.localCredentials = null;
    this.setState(ConnectionState.Closed);
  }

  // ---- Private methods ----

  private setState(state: ConnectionState): void {
    this.state = state;
    this.options.onStateChange?.(state);
  }

  private handleError(error: Error): void {
    this.setState(ConnectionState.Failed);
    this.options.onError?.(error);
  }

  /**
   * Adds remote ICE candidates via addIceCandidate()
   *
   * This avoids SDP parsing issues with IPv6, mDNS, and srflx candidates
   * by letting the browser handle candidate parsing through its API.
   */
  private async addRemoteCandidates(candidates: QWBPCandidate[]): Promise<void> {
    if (!this.pc) return;

    for (const candidate of candidates) {
      try {
        const candidateStr = await buildCandidateString(candidate);
        await this.pc.addIceCandidate(
          new RTCIceCandidate({
            candidate: candidateStr,
            sdpMid: '0',
            sdpMLineIndex: 0,
          })
        );
      } catch (error) {
        // Log but don't fail - some candidates may be invalid for this network
        console.warn('Failed to add candidate:', candidate, error);
      }
    }
  }

  private waitForIceGathering(pc: RTCPeerConnection): Promise<void> {
    return new Promise((resolve, reject) => {
      if (pc.iceGatheringState === 'complete') {
        resolve();
        return;
      }

      let candidateCount = 0;
      let completed = false;

      const timeout = setTimeout(() => {
        if (completed) return;
        completed = true;

        // Check if connection was closed during gathering
        if (this.state === ConnectionState.Closed) {
          resolve();
          return;
        }

        // If we have candidates but gathering didn't complete, that's OK
        if (candidateCount > 0) {
          resolve();
        } else {
          reject(new QWBPConnectionError('ICE gathering timeout - no candidates found', ConnectionState.Gathering));
        }
      }, 10000);

      const complete = () => {
        if (completed) return;
        completed = true;
        clearTimeout(timeout);
        resolve();
      };

      // Listen for state change to 'complete'
      pc.onicegatheringstatechange = () => {
        if (pc.iceGatheringState === 'complete') {
          complete();
        }
      };

      // Also listen for null candidate (end-of-candidates signal)
      // This is more reliable on some networks
      pc.onicecandidate = (event) => {
        if (event.candidate) {
          candidateCount++;
        } else {
          // null candidate = end of gathering
          complete();
        }
      };
    });
  }

  private setupDataChannelListeners(channel: RTCDataChannel): void {
    channel.onopen = () => {
      this.setState(ConnectionState.Connected);
      this.clearTimeout();
      this.dataChannelCallback?.(channel);
      this.options.onDataChannel?.(channel);
    };

    channel.onerror = (event) => {
      this.handleError(new QWBPConnectionError(`DataChannel error: ${event}`, this.state));
    };

    channel.onclose = () => {
      if (this.state === ConnectionState.Connected) {
        this.setState(ConnectionState.Closed);
      }
    };
  }

  private setupConnectionListeners(): void {
    if (!this.pc) return;

    this.pc.oniceconnectionstatechange = () => {
      const iceState = this.pc?.iceConnectionState;

      if (iceState === 'failed' || iceState === 'disconnected') {
        this.handleError(new QWBPIceError(iceState, this.state));
      }
    };

    this.pc.onconnectionstatechange = () => {
      const connState = this.pc?.connectionState;

      if (connState === 'failed') {
        this.handleError(new QWBPConnectionError('Connection failed', this.state));
      }
    };
  }

  private startTimeout(): void {
    this.timeoutId = setTimeout(() => {
      if (
        this.state !== ConnectionState.Connected &&
        this.state !== ConnectionState.Closed
      ) {
        this.handleError(new QWBPTimeoutError(this.state));
        this.close();
      }
    }, this.options.timeout);
  }

  private clearTimeout(): void {
    if (this.timeoutId) {
      clearTimeout(this.timeoutId);
      this.timeoutId = null;
    }
  }
}
