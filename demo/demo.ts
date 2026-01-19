/**
 * QWBP Demo Application
 *
 * Demonstrates QR-based WebRTC signaling for peer-to-peer image sharing
 * with detailed protocol logging for testing and debugging
 */

import QRCode from 'qrcode';
import jsQR from 'jsqr';

import {
  QWBPConnection,
  ConnectionState,
  isValidPacket,
  decode,
  formatFingerprint,
} from '../src/index.js';

// ---- Protocol Logger ----

type LogLevel = 'info' | 'success' | 'warning' | 'error' | 'data' | 'crypto' | 'ice' | 'sdp' | 'qr';

interface LogEntry {
  timestamp: Date;
  level: LogLevel;
  message: string;
}

class ProtocolLogger {
  private entries: LogEntry[] = [];
  private startTime: number = 0;
  private logEntriesEl: HTMLElement | null = null;
  private logStatsEl: HTMLElement | null = null;

  init(): void {
    this.logEntriesEl = document.getElementById('log-entries');
    this.logStatsEl = document.getElementById('log-stats-text');
  }

  start(): void {
    this.startTime = performance.now();
    this.entries = [];
    if (this.logEntriesEl) {
      this.logEntriesEl.innerHTML = '';
    }
    this.updateStats();
  }

  log(level: LogLevel, message: string): void {
    const entry: LogEntry = {
      timestamp: new Date(),
      level,
      message,
    };
    this.entries.push(entry);
    this.renderEntry(entry);
    this.updateStats();

    // Also log to console for debugging
    console.log(`[${level.toUpperCase()}]`, message.replace(/<[^>]*>/g, ''));
  }

  private renderEntry(entry: LogEntry): void {
    if (!this.logEntriesEl) return;

    const elapsed = this.startTime ? (performance.now() - this.startTime) / 1000 : 0;
    const timeStr = elapsed.toFixed(3) + 's';

    const entryEl = document.createElement('div');
    entryEl.className = 'log-entry';
    entryEl.innerHTML = `
      <span class="log-timestamp">${timeStr}</span>
      <span class="log-level ${entry.level}">${entry.level}</span>
      <span class="log-message">${entry.message}</span>
    `;

    this.logEntriesEl.appendChild(entryEl);
    this.logEntriesEl.scrollTop = this.logEntriesEl.scrollHeight;
  }

  private updateStats(): void {
    if (!this.logStatsEl) return;
    const elapsed = this.startTime ? ((performance.now() - this.startTime) / 1000).toFixed(1) : '0.0';
    this.logStatsEl.textContent = `${this.entries.length} events | ${elapsed}s elapsed`;
  }

  clear(): void {
    this.entries = [];
    this.startTime = 0;
    if (this.logEntriesEl) {
      this.logEntriesEl.innerHTML = '';
    }
    if (this.logStatsEl) {
      this.logStatsEl.textContent = 'Ready to start';
    }
  }
}

const logger = new ProtocolLogger();

// ---- Helper Functions ----

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`;
  return `${(bytes / 1024).toFixed(2)} KB`;
}

function formatHex(data: Uint8Array, maxLen = 8): string {
  const hex = Array.from(data.slice(0, maxLen))
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ');
  return data.length > maxLen ? `${hex}...` : hex;
}

function formatIP(ip: string): string {
  return `<span class="ip-address">${ip}</span>`;
}

// ---- DOM Elements ----

interface Elements {
  status: HTMLElement;
  statusText: Element;
  sectionStart: HTMLElement;
  sectionQR: HTMLElement;
  sectionConnected: HTMLElement;
  sectionError: HTMLElement;
  btnStart: HTMLElement;
  btnDisconnect: HTMLElement;
  btnRetry: HTMLElement;
  btnCancel: HTMLElement;
  btnClearLog: HTMLElement;
  btnToggleLog: HTMLElement;
  toggleIcon: HTMLElement;
  protocolLog: HTMLElement;
  qrCode: HTMLElement;
  qrInfo: HTMLElement;
  scannerVideo: HTMLVideoElement;
  scanStatus: HTMLElement;
  chatMessages: HTMLElement;
  chatForm: HTMLFormElement;
  chatInput: HTMLInputElement;
  errorMessage: HTMLElement;
  sasCode: HTMLElement;
}

let elements: Elements;

function initElements(): boolean {
  try {
    elements = {
      status: document.getElementById('status')!,
      statusText: document.querySelector('.status-text')!,
      sectionStart: document.getElementById('section-start')!,
      sectionQR: document.getElementById('section-qr')!,
      sectionConnected: document.getElementById('section-connected')!,
      sectionError: document.getElementById('section-error')!,
      btnStart: document.getElementById('btn-start')!,
      btnDisconnect: document.getElementById('btn-disconnect')!,
      btnRetry: document.getElementById('btn-retry')!,
      btnCancel: document.getElementById('btn-cancel')!,
      btnClearLog: document.getElementById('btn-clear-log')!,
      btnToggleLog: document.getElementById('btn-toggle-log')!,
      toggleIcon: document.getElementById('toggle-icon')!,
      protocolLog: document.getElementById('protocol-log')!,
      qrCode: document.getElementById('qr-code')!,
      qrInfo: document.getElementById('qr-info')!,
      scannerVideo: document.getElementById('scanner-video') as HTMLVideoElement,
      scanStatus: document.getElementById('scan-status')!,
      chatMessages: document.getElementById('chat-messages')!,
      chatForm: document.getElementById('chat-form') as HTMLFormElement,
      chatInput: document.getElementById('chat-input') as HTMLInputElement,
      errorMessage: document.getElementById('error-message')!,
      sasCode: document.getElementById('sas-code')!,
    };
    return true;
  } catch (e) {
    console.error('Failed to initialize DOM elements:', e);
    return false;
  }
}

// ---- State ----

let connection: QWBPConnection | null = null;
let videoStream: MediaStream | null = null;
let scannerActive = false;
let scannedRemote = false;
let scanFrameCount = 0;
let lastScanTime = 0;
const SCAN_INTERVAL_MS = 250;

// ---- UI Functions ----

function showSection(sectionId: string): void {
  document.querySelectorAll('.section').forEach((section) => {
    section.classList.remove('active');
  });
  document.getElementById(sectionId)?.classList.add('active');
}

function updateStatus(state: ConnectionState): void {
  const statusElement = elements.status;
  const textElement = elements.statusText;

  statusElement.className = 'status';

  const statusMap: Record<ConnectionState, { text: string; className: string }> = {
    [ConnectionState.Idle]: { text: 'Ready', className: 'status-idle' },
    [ConnectionState.Gathering]: { text: 'Gathering network candidates...', className: 'status-gathering' },
    [ConnectionState.Displaying]: { text: 'Scan QR codes', className: 'status-displaying' },
    [ConnectionState.ScannedOne]: { text: 'Waiting for peer...', className: 'status-scanned-one' },
    [ConnectionState.Connecting]: { text: 'Connecting...', className: 'status-connecting' },
    [ConnectionState.Connected]: { text: 'Connected', className: 'status-connected' },
    [ConnectionState.Failed]: { text: 'Failed', className: 'status-failed' },
    [ConnectionState.Closed]: { text: 'Disconnected', className: 'status-idle' },
  };

  const info = statusMap[state] || { text: state, className: 'status-idle' };
  statusElement.classList.add(info.className);
  textElement.textContent = info.text;
}

function showError(message: string): void {
  // Provide helpful troubleshooting for common errors
  let displayMessage = message;

  if (message.includes('ICE gathering timeout')) {
    displayMessage = `${message}

Troubleshooting:
• Check your network connection
• Disable VPN if active
• Try a different network (e.g., mobile hotspot)
• Corporate firewalls may block WebRTC`;
  }

  elements.errorMessage.textContent = displayMessage;
  elements.errorMessage.style.whiteSpace = 'pre-line';
  showSection('section-error');
  updateStatus(ConnectionState.Failed);
}

// ---- QR Code Functions ----

async function generateQRCode(data: Uint8Array): Promise<void> {
  elements.qrCode.innerHTML = '';

  const canvas = document.createElement('canvas');
  elements.qrCode.appendChild(canvas);

  // Use segments API for binary mode
  await QRCode.toCanvas(canvas, [{ data, mode: 'byte' }], {
    width: 200,
    margin: 2,
    errorCorrectionLevel: 'L',
  });

  logger.log('qr', `Generated QR code: <code>${formatBytes(data.length)}</code> payload`);
}

function displayQRInfo(payload: Uint8Array): void {
  try {
    const packet = decode(payload);
    const fingerprint = formatFingerprint(packet.fingerprint);
    const shortFP = fingerprint.substring(0, 23) + '...';

    let candidateSummary = '';
    packet.candidates.forEach((c, i) => {
      const typeLabel = c.type === 'srflx' ? '(STUN)' : '(local)';
      candidateSummary += `<div class="qr-info-row">
        <span class="qr-info-label">Candidate ${i + 1}:</span>
        <span class="qr-info-value">${c.ip}:${c.port} ${typeLabel}</span>
      </div>`;
    });

    elements.qrInfo.innerHTML = `
      <div class="qr-info-row">
        <span class="qr-info-label">Size:</span>
        <span class="qr-info-value">${payload.length} bytes</span>
      </div>
      <div class="qr-info-row">
        <span class="qr-info-label">Fingerprint:</span>
        <span class="qr-info-value">${shortFP}</span>
      </div>
      ${candidateSummary}
    `;
  } catch {
    elements.qrInfo.innerHTML = '';
  }
}

// ---- Scanner Functions ----

async function startScanner(): Promise<void> {
  logger.log('info', 'Requesting camera access...');

  // Check if we're in a secure context (HTTPS or localhost)
  if (!window.isSecureContext) {
    logger.log('error', 'Camera requires HTTPS. Use localhost or enable HTTPS.');
    elements.scanStatus.innerHTML = `
      <strong>Camera requires HTTPS</strong><br>
      <small>Use localhost:PORT or serve with HTTPS</small>
    `;
    elements.scanStatus.className = 'scan-status';
    return;
  }

  try {
    videoStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' },
    });

    elements.scannerVideo.srcObject = videoStream;
    scannerActive = true;
    scanFrameCount = 0;
    lastScanTime = 0;

    const tracks = videoStream.getVideoTracks();
    if (tracks.length > 0) {
      const settings = tracks[0].getSettings();
      logger.log('success', `Camera active: ${settings.width}x${settings.height}`);
    }

    logger.log('info', 'Starting QR code scanner loop...');
    requestAnimationFrame(scanFrame);
  } catch (error) {
    const err = error as Error;
    logger.log('error', `Camera access failed: ${err.message}`);

    let message = 'Camera access denied';
    if (err.name === 'NotAllowedError') {
      message = 'Camera permission denied. Please allow camera access.';
    } else if (err.name === 'NotFoundError') {
      message = 'No camera found on this device.';
    } else if (err.name === 'NotReadableError') {
      message = 'Camera is in use by another application.';
    }

    elements.scanStatus.textContent = message;
    elements.scanStatus.className = 'scan-status';
  }
}

function stopScanner(): void {
  scannerActive = false;
  if (videoStream) {
    videoStream.getTracks().forEach((track) => track.stop());
    videoStream = null;
    logger.log('info', `Scanner stopped after ${scanFrameCount} frames analyzed`);
  }
}

function scanFrame(): void {
  if (!scannerActive || !videoStream) return;

  const video = elements.scannerVideo;
  const now = performance.now();

  // Throttle QR detection to reduce CPU/battery usage
  if (video.readyState === video.HAVE_ENOUGH_DATA && now - lastScanTime >= SCAN_INTERVAL_MS) {
    lastScanTime = now;
    scanFrameCount++;

    const canvas = document.createElement('canvas');
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;

    const ctx = canvas.getContext('2d')!;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, canvas.width, canvas.height);

    if (code && code.binaryData) {
      handleScannedData(new Uint8Array(code.binaryData));
    }
  }

  if (scannerActive) {
    requestAnimationFrame(scanFrame);
  }
}

async function handleScannedData(data: Uint8Array): Promise<void> {
  if (!isValidPacket(data)) {
    return;
  }

  if (scannedRemote) return;
  scannedRemote = true;

  logger.log('qr', `QR code detected! Payload: <code>${formatBytes(data.length)}</code>`);
  logger.log('data', `Raw data: <span class="hex-data">${formatHex(data, 12)}</span>`);

  elements.scanStatus.textContent = 'QR code scanned!';
  elements.scanStatus.className = 'scan-status success';

  try {
    const packet = decode(data);
    const shortFP = formatFingerprint(packet.fingerprint).substring(0, 23);
    logger.log('crypto', `Remote fingerprint: <code>${shortFP}...</code>`);

    packet.candidates.forEach((c, i) => {
      const proto = c.protocol.toUpperCase();
      const type = c.type === 'srflx' ? 'server-reflexive' : 'host';
      logger.log('ice', `Remote candidate ${i + 1}: ${formatIP(c.ip)}:${c.port} (${proto}, ${type})`);
    });

    await connection?.processScannedPayload(data);
  } catch (error) {
    logger.log('error', `Failed to process payload: ${(error as Error).message}`);
    showError((error as Error).message);
  }
}

// ---- Connection Functions ----

async function startConnection(): Promise<void> {
  try {
    scannedRemote = false;
    logger.start();

    logger.log('info', 'Starting QWBP connection...');
    logger.log('info', 'Protocol version: 0 (QWBP v1.0)');

    connection = new QWBPConnection({
      onStateChange: async (state) => {
        logger.log('info', `State changed: <span class="highlight">${state}</span>`);
        updateStatus(state);

        if (state === ConnectionState.Gathering) {
          logger.log('crypto', 'Generating ECDSA P-256 certificate...');
        }

        if (state === ConnectionState.Displaying) {
          showSection('section-qr');
          elements.btnCancel.classList.add('hidden');
          logger.log('success', 'ICE gathering complete');
        } else if (state === ConnectionState.ScannedOne) {
          elements.btnCancel.classList.remove('hidden');
          logger.log('info', 'Waiting for mutual scan to complete...');
        } else if (state === ConnectionState.Connecting) {
          elements.btnCancel.classList.add('hidden');
          const role = connection?.assignedRole;
          logger.log('info', `Role assigned: <span class="highlight">${role}</span>`);
          logger.log('sdp', 'Generating synthetic SDP from QWBP data...');
          logger.log('ice', 'Starting ICE connectivity checks...');
        } else if (state === ConnectionState.Connected) {
          stopScanner();
          showSection('section-connected');
          logger.log('success', 'DTLS handshake complete!');
          logger.log('success', 'DataChannel established - connection ready');

          if (connection) {
            const sas = await connection.getSAS();
            if (sas) {
              elements.sasCode.textContent = sas;
              logger.log('crypto', `SAS verification code: <span class="highlight">${sas}</span>`);
            }
          }
        } else if (state === ConnectionState.Failed) {
          stopScanner();
          logger.log('error', 'Connection failed');
        }
      },
      onDataChannel: (channel) => {
        logger.log('data', `DataChannel "${channel.label}" opened`);
        logger.log('data', `Channel config: ordered=${channel.ordered}, protocol="${channel.protocol}"`);
        setupDataChannel(channel);
      },
      onError: (error) => {
        logger.log('error', `Error: ${error.message}`);
        showError(error.message);
      },
    });

    logger.log('crypto', 'Calling RTCPeerConnection.generateCertificate()...');
    await connection.initialize();
    logger.log('crypto', 'Certificate generated successfully');

    const payload = connection.getQRPayload();

    logger.log('qr', 'Encoding QWBP packet:');
    logger.log('data', `Magic byte: <code>0x51</code> ('Q')`);
    logger.log('data', `Version: <code>0x00</code>`);
    logger.log('data', `Header size: 2 bytes`);
    logger.log('data', `Fingerprint: 32 bytes (SHA-256)`);

    const packet = decode(payload);
    const shortFP = formatFingerprint(packet.fingerprint).substring(0, 23);
    logger.log('crypto', `Local fingerprint: <code>${shortFP}...</code>`);

    packet.candidates.forEach((c, i) => {
      const proto = c.protocol.toUpperCase();
      const type = c.type === 'srflx' ? 'server-reflexive' : 'host';
      logger.log('ice', `Local candidate ${i + 1}: ${formatIP(c.ip)}:${c.port} (${proto}, ${type})`);
    });

    logger.log('data', `Total payload: <code>${formatBytes(payload.length)}</code>`);

    await generateQRCode(payload);
    displayQRInfo(payload);

    await startScanner();

    elements.scanStatus.textContent = 'Point camera at other device\'s QR code...';
    elements.scanStatus.className = 'scan-status waiting';
  } catch (error) {
    logger.log('error', `Failed to start: ${(error as Error).message}`);
    showError((error as Error).message);
  }
}

function disconnect(): void {
  logger.log('info', 'Disconnecting...');
  stopScanner();
  connection?.close();
  connection = null;
  scannedRemote = false;
  elements.btnCancel.classList.add('hidden');
  elements.sasCode.textContent = '----';
  elements.qrInfo.innerHTML = '';
  elements.chatMessages.innerHTML = '';
  showSection('section-start');
  updateStatus(ConnectionState.Idle);
  logger.log('info', 'Connection closed');
}

function cancelConnection(): void {
  logger.log('info', 'Connection cancelled by user');
  disconnect();
}

// ---- Data Channel Functions ----

function setupDataChannel(channel: RTCDataChannel): void {
  channel.binaryType = 'arraybuffer';

  channel.onmessage = (event) => {
    handleReceivedMessage(event.data);
  };

  channel.onerror = () => {
    logger.log('error', 'DataChannel error');
  };

  channel.onclose = () => {
    logger.log('info', 'DataChannel closed');
  };
}

function handleReceivedMessage(data: ArrayBuffer | string): void {
  if (typeof data === 'string') {
    logger.log('data', `Received: "${data.substring(0, 50)}${data.length > 50 ? '...' : ''}"`);
    addChatMessage(data, 'received');
  } else {
    logger.log('data', `Received binary: ${formatBytes(data.byteLength)}`);
  }
}

// ---- Chat Functions ----

function addChatMessage(text: string, type: 'sent' | 'received'): void {
  const messageEl = document.createElement('div');
  messageEl.className = `chat-message ${type}`;
  messageEl.textContent = text;
  elements.chatMessages.appendChild(messageEl);
  elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;
}

function sendChatMessage(text: string): void {
  const channel = connection?.getDataChannel();
  if (!channel || channel.readyState !== 'open') {
    logger.log('error', 'Data channel not ready');
    return;
  }

  try {
    channel.send(text);
    addChatMessage(text, 'sent');
    logger.log('data', `Sent: "${text.substring(0, 50)}${text.length > 50 ? '...' : ''}"`);
  } catch (error) {
    logger.log('error', `Failed to send: ${(error as Error).message}`);
  }
}

function handleChatSubmit(event: Event): void {
  event.preventDefault();
  const text = elements.chatInput.value.trim();
  if (text) {
    sendChatMessage(text);
    elements.chatInput.value = '';
  }
}

// ---- Log Panel Controls ----

function toggleLogPanel(): void {
  elements.protocolLog.classList.toggle('collapsed');
  elements.toggleIcon.textContent = elements.protocolLog.classList.contains('collapsed') ? '+' : '−';
}

function clearLog(): void {
  logger.clear();
}

// ---- Initialize ----

function initializeApp(): void {
  console.log('QWBP Demo: Initializing...');

  if (!initElements()) {
    console.error('Failed to initialize DOM elements');
    return;
  }

  logger.init();

  // Set up event listeners
  elements.btnStart.addEventListener('click', startConnection);
  elements.btnDisconnect.addEventListener('click', disconnect);
  elements.btnRetry.addEventListener('click', () => {
    showSection('section-start');
    updateStatus(ConnectionState.Idle);
  });
  elements.btnCancel.addEventListener('click', cancelConnection);

  elements.btnClearLog.addEventListener('click', clearLog);
  elements.btnToggleLog.addEventListener('click', toggleLogPanel);

  // Chat event listener
  elements.chatForm.addEventListener('submit', handleChatSubmit);

  // Show start section
  showSection('section-start');
  updateStatus(ConnectionState.Idle);

  console.log('QWBP Demo: Ready');
}

// Start the app when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeApp);
} else {
  initializeApp();
}
