/**
 * Vitest Test Setup
 *
 * Installs WebRTC mocks globally before tests run.
 */

import { beforeEach } from 'vitest';
import { installMocks, resetMockConfig } from './mocks/webrtc.js';

// Install WebRTC mocks
installMocks();

// Reset mock configuration before each test
beforeEach(() => {
  resetMockConfig();
});
