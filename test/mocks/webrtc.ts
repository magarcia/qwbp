/**
 * WebRTC API Mocks for Testing
 *
 * Provides mock implementations of WebRTC APIs for unit testing
 * QWBPConnection without requiring a real browser environment.
 */

import { TEST_FINGERPRINT } from '../fixtures.js';

/** Configuration for mock behavior */
export interface MockPeerConnectionConfig {
  /** Fingerprint to use in generated SDP */
  fingerprint?: Uint8Array;
  /** ICE candidates to generate */
  candidates?: Array<{ ip: string; port: number; type: string }>;
  /** Whether to simulate successful connection */
  simulateSuccess?: boolean;
  /** Delay before opening data channel (ms) */
  openDelay?: number;
  /** Whether to simulate ICE failure */
  simulateIceFailure?: boolean;
}

/** Default mock configuration */
const defaultConfig: MockPeerConnectionConfig = {
  fingerprint: TEST_FINGERPRINT,
  candidates: [
    { ip: '192.168.1.5', port: 54321, type: 'host' },
  ],
  simulateSuccess: true,
  openDelay: 10,
  simulateIceFailure: false,
};

/** Global mock configuration (can be changed per test) */
let globalMockConfig: MockPeerConnectionConfig = { ...defaultConfig };

/** Set mock configuration for tests */
export function setMockConfig(config: Partial<MockPeerConnectionConfig>): void {
  globalMockConfig = { ...defaultConfig, ...config };
}

/** Reset mock configuration to defaults */
export function resetMockConfig(): void {
  globalMockConfig = { ...defaultConfig };
}

/** Format fingerprint as hex string with colons */
function formatFingerprintHex(fp: Uint8Array): string {
  return Array.from(fp)
    .map(b => b.toString(16).toUpperCase().padStart(2, '0'))
    .join(':');
}

/** Generate a mock SDP string */
function generateMockSDP(fingerprintHex: string, isOffer: boolean): string {
  const sessionId = '1234567890123456789';
  const setup = isOffer ? 'actpass' : 'active';

  const candidates = globalMockConfig.candidates ?? [];
  const candidateLines = candidates.map((c, i) => {
    const foundation = `${i + 1}`;
    return `a=candidate:${foundation} 1 udp 2122260223 ${c.ip} ${c.port} typ ${c.type}`;
  }).join('\r\n');

  return `v=0\r
o=- ${sessionId} 2 IN IP4 127.0.0.1\r
s=-\r
t=0 0\r
a=group:BUNDLE 0\r
a=extmap-allow-mixed\r
a=msid-semantic: WMS\r
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r
c=IN IP4 0.0.0.0\r
a=ice-ufrag:mock1\r
a=ice-pwd:mockpassword123456789012\r
a=ice-options:trickle\r
a=fingerprint:sha-256 ${fingerprintHex}\r
a=setup:${setup}\r
a=mid:0\r
a=sctp-port:5000\r
a=max-message-size:262144\r
${candidateLines}\r
`;
}

/** Mock RTCDataChannel */
class MockDataChannel {
  label: string;
  readyState: RTCDataChannelState = 'connecting';
  ordered = true;
  id: number | null = 1;

  onopen: ((this: RTCDataChannel, ev: Event) => unknown) | null = null;
  onclose: ((this: RTCDataChannel, ev: Event) => unknown) | null = null;
  onerror: ((this: RTCDataChannel, ev: Event) => unknown) | null = null;
  onmessage: ((this: RTCDataChannel, ev: MessageEvent) => unknown) | null = null;

  constructor(label: string) {
    this.label = label;
  }

  close(): void {
    this.readyState = 'closed';
    if (this.onclose) {
      this.onclose.call(this as unknown as RTCDataChannel, new Event('close'));
    }
  }

  send(_data: string | ArrayBuffer): void {
    // Mock send
  }

  _simulateOpen(): void {
    this.readyState = 'open';
    if (this.onopen) {
      this.onopen.call(this as unknown as RTCDataChannel, new Event('open'));
    }
  }
}

/** Mock RTCPeerConnection */
class MockPeerConnection {
  connectionState: RTCPeerConnectionState = 'new';
  iceConnectionState: RTCIceConnectionState = 'new';
  iceGatheringState: RTCIceGatheringState = 'new';
  signalingState: RTCSignalingState = 'stable';
  localDescription: RTCSessionDescription | null = null;
  remoteDescription: RTCSessionDescription | null = null;

  onconnectionstatechange: ((this: RTCPeerConnection, ev: Event) => unknown) | null = null;
  ondatachannel: ((this: RTCPeerConnection, ev: RTCDataChannelEvent) => unknown) | null = null;
  onicecandidate: ((this: RTCPeerConnection, ev: RTCPeerConnectionIceEvent) => unknown) | null = null;
  oniceconnectionstatechange: ((this: RTCPeerConnection, ev: Event) => unknown) | null = null;
  onicegatheringstatechange: ((this: RTCPeerConnection, ev: Event) => unknown) | null = null;

  private _dataChannels: MockDataChannel[] = [];
  private _config: RTCConfiguration;

  constructor(config?: RTCConfiguration) {
    this._config = config ?? {};
  }

  static async generateCertificate(_keygenAlgorithm: AlgorithmIdentifier): Promise<RTCCertificate> {
    return {
      expires: Date.now() + 86400000,
      getFingerprints: () => [{
        algorithm: 'sha-256',
        value: formatFingerprintHex(globalMockConfig.fingerprint ?? TEST_FINGERPRINT),
      }],
    } as RTCCertificate;
  }

  addIceCandidate(_candidate?: RTCIceCandidateInit | null): Promise<void> {
    return Promise.resolve();
  }

  close(): void {
    this.connectionState = 'closed';
    this.iceConnectionState = 'closed';
    this.signalingState = 'closed';
    this._dataChannels.forEach(dc => dc.close());
  }

  createAnswer(): Promise<RTCSessionDescriptionInit> {
    const fp = globalMockConfig.fingerprint ?? TEST_FINGERPRINT;
    const fpHex = formatFingerprintHex(fp);

    return Promise.resolve({
      type: 'answer' as RTCSdpType,
      sdp: generateMockSDP(fpHex, false),
    });
  }

  createDataChannel(label: string): RTCDataChannel {
    const channel = new MockDataChannel(label);
    this._dataChannels.push(channel);
    return channel as unknown as RTCDataChannel;
  }

  createOffer(): Promise<RTCSessionDescriptionInit> {
    const fp = globalMockConfig.fingerprint ?? TEST_FINGERPRINT;
    const fpHex = formatFingerprintHex(fp);

    return Promise.resolve({
      type: 'offer' as RTCSdpType,
      sdp: generateMockSDP(fpHex, true),
    });
  }

  getConfiguration(): RTCConfiguration {
    return this._config;
  }

  async setLocalDescription(description?: RTCLocalSessionDescriptionInit): Promise<void> {
    if (description?.type === 'rollback') {
      this.signalingState = 'stable';
      this.localDescription = null;
      return;
    }

    this.localDescription = description as RTCSessionDescription;
    this.signalingState = description?.type === 'offer' ? 'have-local-offer' : 'stable';

    // Simulate ICE gathering
    this.iceGatheringState = 'gathering';
    if (this.onicegatheringstatechange) {
      this.onicegatheringstatechange.call(this as unknown as RTCPeerConnection, new Event('icegatheringstatechange'));
    }

    // Generate candidates asynchronously
    setTimeout(() => {
      const candidates = globalMockConfig.candidates ?? [];
      for (const cand of candidates) {
        const candidateStr = `candidate:1 1 udp 2122260223 ${cand.ip} ${cand.port} typ ${cand.type}`;
        if (this.onicecandidate) {
          this.onicecandidate.call(this as unknown as RTCPeerConnection, {
            candidate: { candidate: candidateStr, sdpMid: '0', sdpMLineIndex: 0 },
          } as RTCPeerConnectionIceEvent);
        }
      }

      // Signal end of candidates
      if (this.onicecandidate) {
        this.onicecandidate.call(this as unknown as RTCPeerConnection, { candidate: null } as RTCPeerConnectionIceEvent);
      }
      this.iceGatheringState = 'complete';
      if (this.onicegatheringstatechange) {
        this.onicegatheringstatechange.call(this as unknown as RTCPeerConnection, new Event('icegatheringstatechange'));
      }
    }, 1);
  }

  async setRemoteDescription(description: RTCSessionDescriptionInit): Promise<void> {
    this.remoteDescription = description as RTCSessionDescription;

    if (this.signalingState === 'have-local-offer' && description.type === 'answer') {
      this.signalingState = 'stable';
    } else if (description.type === 'offer') {
      this.signalingState = 'have-remote-offer';
    }

    // Simulate connection establishment
    if (globalMockConfig.simulateSuccess) {
      setTimeout(() => {
        this.iceConnectionState = 'checking';
        if (this.oniceconnectionstatechange) {
          this.oniceconnectionstatechange.call(this as unknown as RTCPeerConnection, new Event('iceconnectionstatechange'));
        }

        setTimeout(() => {
          if (globalMockConfig.simulateIceFailure) {
            this.iceConnectionState = 'failed';
            this.connectionState = 'failed';
            if (this.oniceconnectionstatechange) {
              this.oniceconnectionstatechange.call(this as unknown as RTCPeerConnection, new Event('iceconnectionstatechange'));
            }
            if (this.onconnectionstatechange) {
              this.onconnectionstatechange.call(this as unknown as RTCPeerConnection, new Event('connectionstatechange'));
            }
          } else {
            this.iceConnectionState = 'connected';
            this.connectionState = 'connected';
            if (this.oniceconnectionstatechange) {
              this.oniceconnectionstatechange.call(this as unknown as RTCPeerConnection, new Event('iceconnectionstatechange'));
            }
            if (this.onconnectionstatechange) {
              this.onconnectionstatechange.call(this as unknown as RTCPeerConnection, new Event('connectionstatechange'));
            }

            // Open data channels
            const delay = globalMockConfig.openDelay ?? 10;
            setTimeout(() => {
              this._dataChannels.forEach(dc => dc._simulateOpen());
            }, delay);
          }
        }, 5);
      }, 1);
    }
  }
}

/** Mock RTCIceCandidate */
class MockIceCandidate {
  candidate: string;
  sdpMid: string | null;
  sdpMLineIndex: number | null;

  constructor(init?: RTCIceCandidateInit) {
    this.candidate = init?.candidate ?? '';
    this.sdpMid = init?.sdpMid ?? null;
    this.sdpMLineIndex = init?.sdpMLineIndex ?? null;
  }

  toJSON(): RTCIceCandidateInit {
    return {
      candidate: this.candidate,
      sdpMid: this.sdpMid,
      sdpMLineIndex: this.sdpMLineIndex,
    };
  }
}

/** Install mocks globally */
export function installMocks(): void {
  (globalThis as Record<string, unknown>).RTCPeerConnection = MockPeerConnection;
  (globalThis as Record<string, unknown>).RTCIceCandidate = MockIceCandidate;
  (globalThis as Record<string, unknown>).RTCSessionDescription = class {
    type: RTCSdpType;
    sdp: string;
    constructor(init: RTCSessionDescriptionInit) {
      this.type = init.type!;
      this.sdp = init.sdp!;
    }
    toJSON() {
      return { type: this.type, sdp: this.sdp };
    }
  };
}

/** Uninstall mocks */
export function uninstallMocks(): void {
  delete (globalThis as Record<string, unknown>).RTCPeerConnection;
  delete (globalThis as Record<string, unknown>).RTCIceCandidate;
  delete (globalThis as Record<string, unknown>).RTCSessionDescription;
}

export { MockPeerConnection, MockDataChannel, MockIceCandidate };
