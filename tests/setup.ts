/**
 * JEST TEST SETUP
 *
 * Global test configuration and initialization.
 * Runs before all test suites.
 */

import { config } from "dotenv";

// Load environment variables
config({ path: ".env.test" });

// Set test environment defaults
process.env.NODE_ENV = "test";
process.env.API_URL = process.env.API_URL || "http://localhost:3000";
process.env.WS_URL = process.env.WS_URL || "http://localhost:3001";
process.env.REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";
process.env.DATABASE_URL = process.env.DATABASE_URL || "postgresql://dex_user:dex_password@localhost:5432/dex_db_test";
process.env.TEST_API_KEY = process.env.TEST_API_KEY || "test-api-key-12345";

// Increase timeout for integration tests
jest.setTimeout(30000);

// Mock console methods to reduce noise in test output
const originalConsole = { ...console };

beforeAll(() => {
  // Suppress certain console output during tests
  console.log = jest.fn();
  console.info = jest.fn();
  // Keep error and warn for debugging
});

afterAll(() => {
  // Restore console
  console.log = originalConsole.log;
  console.info = originalConsole.info;
});

// Global error handler for unhandled rejections
process.on("unhandledRejection", (reason: any) => {
  console.error("Unhandled Rejection in test:", reason);
});

// Extend Jest matchers
expect.extend({
  toBeBetween(received: number, min: number, max: number) {
    const pass = received >= min && received <= max;
    return {
      message: () => `expected ${received} to be between ${min} and ${max}`,
      pass,
    };
  },
  toBeValidAddress(received: string) {
    const pass = /^0x[a-fA-F0-9]{40}$/.test(received);
    return {
      message: () => `expected ${received} to be a valid Ethereum address`,
      pass,
    };
  },
  toBeValidTxHash(received: string) {
    const pass = /^0x[a-fA-F0-9]{64}$/.test(received);
    return {
      message: () => `expected ${received} to be a valid transaction hash`,
      pass,
    };
  },
});

// Type declarations for custom matchers
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeBetween(min: number, max: number): R;
      toBeValidAddress(): R;
      toBeValidTxHash(): R;
    }
  }
}

export {};
