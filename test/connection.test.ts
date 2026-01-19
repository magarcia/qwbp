/**
 * QWBPConnection Unit Tests
 *
 * Tests the connection manager with WebRTC mocks.
 */

import { describe, it, expect, vi } from 'vitest';
import { QWBPConnection } from '../src/connection.js';
import {
  QWBPConnectionError,
  QWBPSelfConnectionError,
  QWBPIceError,
} from '../src/errors.js';
import { encode } from '../src/encoder.js';
import { ConnectionState, Role } from '../src/types.js';
import { TEST_FINGERPRINT, TEST_PEER_FINGERPRINT, TEST_PEER_CANDIDATES } from './fixtures.js';
import { setMockConfig } from './mocks/webrtc.js';

describe('QWBPConnection', () => {
  describe('Initialization', () => {
    it('should start in Idle state', () => {
      const conn = new QWBPConnection();
      expect(conn.connectionState).toBe(ConnectionState.Idle);
    });

    it('should transition to Displaying after initialize()', async () => {
      const conn = new QWBPConnection();
      await conn.initialize();
      expect(conn.connectionState).toBe(ConnectionState.Displaying);
      conn.close();
    });

    it('should reject double initialization', async () => {
      const conn = new QWBPConnection();
      await conn.initialize();

      await expect(conn.initialize()).rejects.toThrow(QWBPConnectionError);
      conn.close();
    });

    it('should accept custom ICE servers', async () => {
      const customIceServers = [
        { urls: 'stun:custom.stun.server:3478' },
      ];
      const conn = new QWBPConnection({ iceServers: customIceServers });
      await conn.initialize();

      expect(conn.connectionState).toBe(ConnectionState.Displaying);
      conn.close();
    });
  });

  describe('QR Payload', () => {
    it('should return Uint8Array payload', async () => {
      const conn = new QWBPConnection();
      await conn.initialize();

      const payload = conn.getQRPayload();
      expect(payload).toBeInstanceOf(Uint8Array);
      expect(payload.length).toBeGreaterThan(0);
      conn.close();
    });

    it('should throw in wrong state', () => {
      const conn = new QWBPConnection();
      expect(() => conn.getQRPayload()).toThrow(QWBPConnectionError);
    });

    it('should be able to get payload before processing peer', async () => {
      // Get payload before processing any peer data
      const conn = new QWBPConnection();
      await conn.initialize();

      // Should be able to get our payload in Displaying state
      const payload = conn.getQRPayload();
      expect(payload).toBeInstanceOf(Uint8Array);

      // Even after getting the payload, we can get it again
      const payload2 = conn.getQRPayload();
      expect(payload2).toEqual(payload);

      conn.close();
    });
  });

  describe('Role Assignment', () => {
    it('should assign Offerer role when local fingerprint is higher', async () => {
      // TEST_FINGERPRINT (0xe7...) > TEST_PEER_FINGERPRINT (0xa1...)
      const conn = new QWBPConnection();
      await conn.initialize();

      const peerPayload = encode(TEST_PEER_FINGERPRINT, TEST_PEER_CANDIDATES);
      await conn.processScannedPayload(peerPayload);

      // Wait for role assignment
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(conn.assignedRole).toBe(Role.Offerer);
      conn.close();
    });

    it('should assign Answerer role when local fingerprint is lower', async () => {
      // Configure mock to use the lower fingerprint as our local fingerprint
      setMockConfig({ fingerprint: TEST_PEER_FINGERPRINT });

      const conn = new QWBPConnection();
      await conn.initialize();

      // Peer has higher fingerprint
      const peerPayload = encode(TEST_FINGERPRINT, TEST_PEER_CANDIDATES);
      await conn.processScannedPayload(peerPayload);

      // Wait for role assignment
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(conn.assignedRole).toBe(Role.Answerer);
      conn.close();
    });
  });

  describe('Self-Connection Prevention', () => {
    it('should throw when scanning own QR code', async () => {
      const conn = new QWBPConnection();
      await conn.initialize();

      // Create payload with the same fingerprint as our mock
      const selfPayload = encode(TEST_FINGERPRINT, TEST_PEER_CANDIDATES);

      await expect(conn.processScannedPayload(selfPayload)).rejects.toThrow(QWBPSelfConnectionError);
      conn.close();
    });
  });

  describe('Connection Lifecycle', () => {
    it('should transition through states correctly', async () => {
      const stateChanges: ConnectionState[] = [];
      const conn = new QWBPConnection({
        onStateChange: (state) => stateChanges.push(state),
      });

      await conn.initialize();
      expect(stateChanges).toContain(ConnectionState.Gathering);
      expect(stateChanges).toContain(ConnectionState.Displaying);

      const peerPayload = encode(TEST_PEER_FINGERPRINT, TEST_PEER_CANDIDATES);
      await conn.processScannedPayload(peerPayload);

      // Wait for state transitions
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(stateChanges).toContain(ConnectionState.ScannedOne);
      expect(stateChanges).toContain(ConnectionState.Connecting);

      conn.close();
    });

    it('should call onDataChannel callback when connected', async () => {
      const onDataChannel = vi.fn();
      const conn = new QWBPConnection({ onDataChannel });

      await conn.initialize();

      const peerPayload = encode(TEST_PEER_FINGERPRINT, TEST_PEER_CANDIDATES);
      await conn.processScannedPayload(peerPayload);

      // Wait for connection and channel open
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(onDataChannel).toHaveBeenCalled();
      expect(conn.connectionState).toBe(ConnectionState.Connected);

      conn.close();
    });

    it('should provide DataChannel via getDataChannel()', async () => {
      const conn = new QWBPConnection();
      await conn.initialize();

      // Initially null
      expect(conn.getDataChannel()).toBeNull();

      const peerPayload = encode(TEST_PEER_FINGERPRINT, TEST_PEER_CANDIDATES);
      await conn.processScannedPayload(peerPayload);

      // Wait for connection
      await new Promise(resolve => setTimeout(resolve, 100));

      const channel = conn.getDataChannel();
      expect(channel).not.toBeNull();
      expect(channel?.readyState).toBe('open');

      conn.close();
    });
  });

  describe('Error Handling', () => {
    it('should call onError callback on ICE failure', async () => {
      setMockConfig({
        simulateSuccess: true,
        simulateIceFailure: true,
      });

      const onError = vi.fn();
      const conn = new QWBPConnection({ onError });

      await conn.initialize();

      const peerPayload = encode(TEST_PEER_FINGERPRINT, TEST_PEER_CANDIDATES);
      await conn.processScannedPayload(peerPayload);

      // Wait for ICE failure simulation
      await new Promise(resolve => setTimeout(resolve, 50));

      expect(onError).toHaveBeenCalled();
      expect(onError.mock.calls[0][0]).toBeInstanceOf(QWBPIceError);
      expect(conn.connectionState).toBe(ConnectionState.Failed);

      conn.close();
    });

    it('should throw on invalid packet', async () => {
      const conn = new QWBPConnection();
      await conn.initialize();

      const invalidPayload = new Uint8Array([0x00, 0x01, 0x02]);

      await expect(conn.processScannedPayload(invalidPayload)).rejects.toThrow(QWBPConnectionError);
      conn.close();
    });

    it('should throw when processing payload in wrong state', async () => {
      const conn = new QWBPConnection();

      const peerPayload = encode(TEST_PEER_FINGERPRINT, TEST_PEER_CANDIDATES);
      await expect(conn.processScannedPayload(peerPayload)).rejects.toThrow(QWBPConnectionError);
    });
  });

  describe('SAS Generation', () => {
    it('should return null before connection', async () => {
      const conn = new QWBPConnection();
      await conn.initialize();

      const sas = await conn.getSAS();
      expect(sas).toBeNull();

      conn.close();
    });

    it('should return 4-digit code after scanning peer', async () => {
      const conn = new QWBPConnection();
      await conn.initialize();

      const peerPayload = encode(TEST_PEER_FINGERPRINT, TEST_PEER_CANDIDATES);
      await conn.processScannedPayload(peerPayload);

      const sas = await conn.getSAS();
      expect(sas).not.toBeNull();
      expect(sas).toMatch(/^\d{4}$/);

      conn.close();
    });

    it('should generate consistent SAS for same fingerprints', async () => {
      const conn1 = new QWBPConnection();
      await conn1.initialize();
      const peerPayload1 = encode(TEST_PEER_FINGERPRINT, TEST_PEER_CANDIDATES);
      await conn1.processScannedPayload(peerPayload1);
      const sas1 = await conn1.getSAS();

      // Create second connection with same fingerprints
      setMockConfig({ fingerprint: TEST_FINGERPRINT });
      const conn2 = new QWBPConnection();
      await conn2.initialize();
      const peerPayload2 = encode(TEST_PEER_FINGERPRINT, TEST_PEER_CANDIDATES);
      await conn2.processScannedPayload(peerPayload2);
      const sas2 = await conn2.getSAS();

      expect(sas1).toBe(sas2);

      conn1.close();
      conn2.close();
    });
  });

  describe('Resource Cleanup', () => {
    it('should transition to Closed on close()', async () => {
      const conn = new QWBPConnection();
      await conn.initialize();

      conn.close();

      expect(conn.connectionState).toBe(ConnectionState.Closed);
    });

    it('should clear resources on close()', async () => {
      const conn = new QWBPConnection();
      await conn.initialize();

      const peerPayload = encode(TEST_PEER_FINGERPRINT, TEST_PEER_CANDIDATES);
      await conn.processScannedPayload(peerPayload);

      // Wait for connection
      await new Promise(resolve => setTimeout(resolve, 100));

      conn.close();

      expect(conn.connectionState).toBe(ConnectionState.Closed);
      expect(conn.getDataChannel()).toBeNull();
    });
  });

  describe('onDataChannel callback', () => {
    it('should call callback immediately if channel already open', async () => {
      const conn = new QWBPConnection();
      await conn.initialize();

      const peerPayload = encode(TEST_PEER_FINGERPRINT, TEST_PEER_CANDIDATES);
      await conn.processScannedPayload(peerPayload);

      // Wait for connection
      await new Promise(resolve => setTimeout(resolve, 100));

      // Register callback after channel is open
      const callback = vi.fn();
      conn.onDataChannel(callback);

      expect(callback).toHaveBeenCalled();

      conn.close();
    });
  });
});
