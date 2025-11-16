/**
 * TEST DATA FIXTURES
 *
 * Shared test data and utilities for the DEX infrastructure test suite.
 * Provides consistent, well-defined test scenarios.
 */

import { ethers } from "ethers";

// ═══════════════════════════════════════════════════════════════════
//                        TOKEN CONFIGURATIONS
// ═══════════════════════════════════════════════════════════════════

export const TOKENS = {
  WETH: {
    address: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
    symbol: "WETH",
    name: "Wrapped Ether",
    decimals: 18,
  },
  USDC: {
    address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    symbol: "USDC",
    name: "USD Coin",
    decimals: 6,
  },
  WBTC: {
    address: "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
    symbol: "WBTC",
    name: "Wrapped Bitcoin",
    decimals: 8,
  },
  LINK: {
    address: "0x514910771AF9Ca656af840dff83E8264EcF986CA",
    symbol: "LINK",
    name: "Chainlink",
    decimals: 18,
  },
  UNI: {
    address: "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
    symbol: "UNI",
    name: "Uniswap",
    decimals: 18,
  },
};

// ═══════════════════════════════════════════════════════════════════
//                          TRADING PAIRS
// ═══════════════════════════════════════════════════════════════════

export const TRADING_PAIRS = [
  { symbol: "WETH/USDC", base: TOKENS.WETH, quote: TOKENS.USDC },
  { symbol: "WBTC/USDC", base: TOKENS.WBTC, quote: TOKENS.USDC },
  { symbol: "LINK/USDC", base: TOKENS.LINK, quote: TOKENS.USDC },
  { symbol: "UNI/USDC", base: TOKENS.UNI, quote: TOKENS.USDC },
];

// ═══════════════════════════════════════════════════════════════════
//                        SAMPLE ORDERS
// ═══════════════════════════════════════════════════════════════════

export const SAMPLE_ORDERS = {
  limitBuyWETH: {
    pair: "WETH/USDC",
    side: "buy",
    orderType: "limit",
    price: 2000,
    amount: 1.5,
    timeInForce: "GTC",
  },
  limitSellWETH: {
    pair: "WETH/USDC",
    side: "sell",
    orderType: "limit",
    price: 2050,
    amount: 2.0,
    timeInForce: "GTC",
  },
  marketBuyWETH: {
    pair: "WETH/USDC",
    side: "buy",
    orderType: "market",
    amount: 1.0,
  },
  fokOrder: {
    pair: "WETH/USDC",
    side: "buy",
    orderType: "fill_or_kill",
    price: 2000,
    amount: 5.0,
  },
  iocOrder: {
    pair: "WETH/USDC",
    side: "sell",
    orderType: "immediate_or_cancel",
    price: 2010,
    amount: 3.0,
  },
  icebergOrder: {
    pair: "WETH/USDC",
    side: "sell",
    orderType: "iceberg",
    price: 2020,
    totalAmount: 100,
    visibleAmount: 10,
  },
  twapOrder: {
    pair: "WETH/USDC",
    side: "buy",
    orderType: "twap",
    totalAmount: 50,
    numSlices: 10,
    intervalSeconds: 300,
    maxPrice: 2100,
  },
  bracketOrder: {
    pair: "WETH/USDC",
    side: "buy",
    orderType: "bracket",
    entryPrice: 2000,
    takeProfitPrice: 2200,
    stopLossPrice: 1800,
    amount: 5,
  },
};

// ═══════════════════════════════════════════════════════════════════
//                        SAMPLE TRANSACTIONS
// ═══════════════════════════════════════════════════════════════════

export const SAMPLE_TRANSACTIONS = {
  legitimateSwap: {
    hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    from: "0xLegitUser123456789012345678901234567890",
    to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    value: ethers.parseEther("5"),
    gasPrice: ethers.parseUnits("50", "gwei"),
    gasLimit: 250000n,
    nonce: 42,
    data: "0x7ff36ab5", // swapExactETHForTokens
    timestamp: Date.now(),
  },
  sandwichFrontrun: {
    hash: "0xfrontrunhash000000000000000000000000000000000000000000000000000",
    from: "0xAttackerAddress1234567890123456789012",
    to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    value: ethers.parseEther("100"),
    gasPrice: ethers.parseUnits("60", "gwei"),
    gasLimit: 300000n,
    nonce: 1,
    data: "0x7ff36ab5",
    timestamp: Date.now() - 100,
  },
  sandwichBackrun: {
    hash: "0xbackrunhash0000000000000000000000000000000000000000000000000000",
    from: "0xAttackerAddress1234567890123456789012",
    to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    value: 0n,
    gasPrice: ethers.parseUnits("45", "gwei"),
    gasLimit: 300000n,
    nonce: 2,
    data: "0x38ed1739", // swapExactTokensForTokens
    timestamp: Date.now() + 100,
  },
};

// ═══════════════════════════════════════════════════════════════════
//                        TEST USER PROFILES
// ═══════════════════════════════════════════════════════════════════

export const TEST_USERS = {
  retailTrader: {
    address: "0xRetailTrader12345678901234567890123456",
    apiKey: "retail-api-key-12345",
    typicalOrderSize: ethers.parseEther("1"),
    riskTolerance: "medium",
  },
  institutionalTrader: {
    address: "0xInstitution1234567890123456789012345",
    apiKey: "institutional-api-key-67890",
    typicalOrderSize: ethers.parseEther("100"),
    riskTolerance: "low",
  },
  marketMaker: {
    address: "0xMarketMaker123456789012345678901234",
    apiKey: "mm-api-key-abcde",
    typicalOrderSize: ethers.parseEther("500"),
    riskTolerance: "high",
  },
  hftTrader: {
    address: "0xHFTTrader123456789012345678901234567",
    apiKey: "hft-api-key-fghij",
    typicalOrderSize: ethers.parseEther("10"),
    riskTolerance: "high",
  },
};

// ═══════════════════════════════════════════════════════════════════
//                        ORDERBOOK SNAPSHOTS
// ═══════════════════════════════════════════════════════════════════

export const SAMPLE_ORDERBOOKS = {
  "WETH/USDC": {
    pair: "WETH/USDC",
    timestamp: Date.now(),
    bids: [
      { price: 1999, amount: 10.5, orders: 3 },
      { price: 1998, amount: 25.0, orders: 7 },
      { price: 1995, amount: 50.0, orders: 12 },
      { price: 1990, amount: 100.0, orders: 20 },
      { price: 1985, amount: 150.0, orders: 25 },
    ],
    asks: [
      { price: 2001, amount: 8.0, orders: 2 },
      { price: 2002, amount: 20.0, orders: 5 },
      { price: 2005, amount: 45.0, orders: 10 },
      { price: 2010, amount: 80.0, orders: 15 },
      { price: 2020, amount: 120.0, orders: 22 },
    ],
    spread: 2,
    midPrice: 2000,
  },
};

// ═══════════════════════════════════════════════════════════════════
//                        ANOMALY SCENARIOS
// ═══════════════════════════════════════════════════════════════════

export const ANOMALY_SCENARIOS = {
  flashCrash: {
    type: "PRICE_CRASH",
    originalPrice: ethers.parseUnits("2000", 6),
    anomalyPrice: ethers.parseUnits("1400", 6), // 30% drop
    duration: 60, // seconds
    expectedSeverity: "CRITICAL",
  },
  volumeSpike: {
    type: "VOLUME_SPIKE",
    normalVolume: ethers.parseEther("1000"),
    spikeVolume: ethers.parseEther("10000"), // 10x
    duration: 300,
    expectedSeverity: "HIGH",
  },
  gasSpike: {
    type: "GAS_SPIKE",
    normalGas: ethers.parseUnits("50", "gwei"),
    spikeGas: ethers.parseUnits("500", "gwei"), // 10x
    duration: 120,
    expectedSeverity: "HIGH",
  },
  mevAttackSpike: {
    type: "MEV_ATTACK_SPIKE",
    normalRate: 2, // attacks per minute
    spikeRate: 50,
    duration: 180,
    expectedSeverity: "CRITICAL",
  },
};

// ═══════════════════════════════════════════════════════════════════
//                      CIRCUIT BREAKER SCENARIOS
// ═══════════════════════════════════════════════════════════════════

export const CIRCUIT_BREAKER_SCENARIOS = {
  singleGuardianPause: {
    guardianCount: 4,
    threshold: 2,
    trigger: "SINGLE_GUARDIAN",
    expectedOutcome: "PAUSED",
  },
  multiSigLift: {
    guardianCount: 4,
    threshold: 2,
    signaturesRequired: 2,
    expectedOutcome: "UNPAUSED",
  },
  emergencyWithdrawal: {
    timeDelay: 24 * 60 * 60, // 24 hours
    token: TOKENS.USDC,
    amount: ethers.parseUnits("10000", 6),
    expectedOutcome: "WITHDRAWN",
  },
};

// ═══════════════════════════════════════════════════════════════════
//                        HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════

export function generateRandomOrderId(): string {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return "0x" + Buffer.from(bytes).toString("hex");
}

export function generateRandomAddress(): string {
  const bytes = new Uint8Array(20);
  for (let i = 0; i < 20; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return "0x" + Buffer.from(bytes).toString("hex");
}

export function generateRandomPrice(base: number, variance: number): number {
  return base + (Math.random() - 0.5) * variance * 2;
}

export function generateRandomAmount(min: number, max: number): string {
  const amount = min + Math.random() * (max - min);
  return ethers.parseEther(amount.toString()).toString();
}

export function createOrderbookEntry(price: number, amount: number, orders: number) {
  return { price, amount, orders };
}

export function calculateSlippage(expectedPrice: number, actualPrice: number): number {
  return Math.abs((actualPrice - expectedPrice) / expectedPrice) * 100;
}

export function estimateMEVProfit(
  frontrunAmount: bigint,
  victimAmount: bigint,
  priceImpact: number
): bigint {
  // Simplified MEV profit calculation
  const totalAmount = frontrunAmount + victimAmount;
  const profitPercentage = priceImpact * 100; // basis points
  return (totalAmount * BigInt(profitPercentage)) / 10000n;
}

// ═══════════════════════════════════════════════════════════════════
//                       PERFORMANCE BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

export const PERFORMANCE_TARGETS = {
  orderSubmissionLatency: {
    p50: 10, // ms
    p90: 25,
    p95: 50,
    p99: 100,
  },
  orderMatchingLatency: {
    p50: 5,
    p90: 15,
    p95: 30,
    p99: 50,
  },
  websocketBroadcastLatency: {
    p50: 2,
    p90: 10,
    p95: 15,
    p99: 25,
  },
  mevDetectionLatency: {
    p50: 10,
    p90: 25,
    p95: 50,
    p99: 100,
  },
  throughput: {
    minOrdersPerSecond: 1000,
    targetOrdersPerSecond: 10000,
    maxOrdersPerSecond: 50000,
  },
  availability: {
    minUptime: 99.9, // percentage
    targetUptime: 99.99,
  },
};

// ═══════════════════════════════════════════════════════════════════
//                       SECURITY TEST VECTORS
// ═══════════════════════════════════════════════════════════════════

export const SECURITY_VECTORS = {
  sqlInjection: [
    "'; DROP TABLE orders; --",
    "1' OR '1'='1",
    "admin'--",
    "1; DELETE FROM users",
  ],
  xssPayloads: [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg/onload=alert('XSS')>",
  ],
  invalidInputs: {
    negativePrice: -1,
    zeroAmount: 0,
    maxUint: ethers.MaxUint256,
    emptyString: "",
    nullValue: null,
    undefinedValue: undefined,
  },
  pathTraversal: [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32",
    "....//....//etc/passwd",
  ],
};

export default {
  TOKENS,
  TRADING_PAIRS,
  SAMPLE_ORDERS,
  SAMPLE_TRANSACTIONS,
  TEST_USERS,
  SAMPLE_ORDERBOOKS,
  ANOMALY_SCENARIOS,
  CIRCUIT_BREAKER_SCENARIOS,
  PERFORMANCE_TARGETS,
  SECURITY_VECTORS,
  generateRandomOrderId,
  generateRandomAddress,
  generateRandomPrice,
  generateRandomAmount,
  createOrderbookEntry,
  calculateSlippage,
  estimateMEVProfit,
};
