/**
 * QWBP Error Classes
 *
 * Provides a hierarchy of error types for programmatic error handling.
 *
 * @category Errors
 * @packageDocumentation
 */

import { ConnectionState } from './types.js';

/**
 * Base error class for all QWBP errors
 *
 * @category Errors
 *
 * @example
 * ```typescript
 * try {
 *   await connection.initialize();
 * } catch (error) {
 *   if (error instanceof QWBPError) {
 *     console.log('QWBP error:', error.message);
 *   }
 * }
 * ```
 */
export class QWBPError extends Error {
  override name = 'QWBPError';

  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Error thrown when encoding QWBP packets fails
 *
 * @category Errors
 *
 * @example
 * ```typescript
 * try {
 *   const packet = encode(fingerprint, candidates);
 * } catch (error) {
 *   if (error instanceof QWBPEncodeError) {
 *     console.log('Invalid input for encoding:', error.message);
 *   }
 * }
 * ```
 */
export class QWBPEncodeError extends QWBPError {
  override name = 'QWBPEncodeError';
}

/**
 * Error thrown when decoding invalid QWBP packets
 *
 * @category Errors
 *
 * @example
 * ```typescript
 * try {
 *   const packet = decode(data);
 * } catch (error) {
 *   if (error instanceof QWBPDecodeError) {
 *     console.log('Invalid packet:', error.message);
 *   }
 * }
 * ```
 */
export class QWBPDecodeError extends QWBPError {
  override name = 'QWBPDecodeError';
}

/**
 * Error thrown when WebRTC connection establishment fails
 *
 * @category Errors
 *
 * @example
 * ```typescript
 * connection.onError((error) => {
 *   if (error instanceof QWBPConnectionError) {
 *     console.log('Connection failed:', error.message);
 *     if (error.state) {
 *       console.log('State when error occurred:', error.state);
 *     }
 *   }
 * });
 * ```
 */
export class QWBPConnectionError extends QWBPError {
  override name = 'QWBPConnectionError';

  /**
   * @param message - Error message
   * @param state - Connection state when the error occurred
   */
  constructor(
    message: string,
    public readonly state?: ConnectionState | string
  ) {
    super(message);
  }
}

/**
 * Error thrown when connection times out
 *
 * This occurs when the connection is not established within the
 * configured timeout period (default: 30 seconds).
 *
 * @category Errors
 *
 * @example
 * ```typescript
 * connection.onError((error) => {
 *   if (error instanceof QWBPTimeoutError) {
 *     console.log('Connection timed out - try again');
 *   }
 * });
 * ```
 */
export class QWBPTimeoutError extends QWBPConnectionError {
  override name = 'QWBPTimeoutError';

  constructor(state?: string) {
    super('Session timeout', state);
  }
}

/**
 * Error thrown when attempting to connect to self
 *
 * This occurs when a device scans its own QR code. The fingerprints
 * match, making role assignment impossible.
 *
 * @category Errors
 *
 * @example
 * ```typescript
 * try {
 *   await connection.processScannedPayload(scannedData);
 * } catch (error) {
 *   if (error instanceof QWBPSelfConnectionError) {
 *     alert('You scanned your own QR code!');
 *   }
 * }
 * ```
 */
export class QWBPSelfConnectionError extends QWBPConnectionError {
  override name = 'QWBPSelfConnectionError';

  constructor() {
    super('Cannot connect to self');
  }
}

/**
 * Error thrown when ICE connection fails
 *
 * This occurs when WebRTC ICE negotiation fails, typically due to
 * network restrictions or NAT traversal issues.
 *
 * @category Errors
 *
 * @example
 * ```typescript
 * connection.onError((error) => {
 *   if (error instanceof QWBPIceError) {
 *     console.log('Network issue:', error.iceState);
 *   }
 * });
 * ```
 */
export class QWBPIceError extends QWBPConnectionError {
  override name = 'QWBPIceError';

  /**
   * @param iceState - The ICE connection state that triggered the error
   * @param connectionState - The connection state when the error occurred
   */
  constructor(
    public readonly iceState: string,
    connectionState?: string
  ) {
    super(`ICE connection ${iceState}`, connectionState);
  }
}
