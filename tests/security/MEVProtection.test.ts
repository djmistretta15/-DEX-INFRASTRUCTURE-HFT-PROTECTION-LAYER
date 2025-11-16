import { expect } from "chai";
import { SandwichAttackDetector, PendingTransaction, DetectionResult } from "../../security/sandwich-attack-detector";
import Redis from "ioredis";
import { ethers } from "ethers";

/**
 * MEV PROTECTION TEST SUITE
 *
 * Tests for the sandwich attack detection system:
 * - Pattern recognition accuracy
 * - False positive rate (target: <5%)
 * - Detection latency (target: <100ms)
 * - Multi-victim attack detection
 * - Confidence scoring algorithm
 * - Protection mechanisms
 */

describe("MEV Protection - Sandwich Attack Detection", function () {
  let detector: SandwichAttackDetector;
  let redis: Redis;

  before(async function () {
    redis = new Redis(process.env.REDIS_URL || "redis://localhost:6379");
    detector = new SandwichAttackDetector({
      provider: null as any, // Mock provider for tests
      mempoolSubscriptionUrl: "ws://localhost:8546",
      dexRouterAddresses: [
        "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", // Uniswap V2
        "0xE592427A0AEce92De3Edee1F18E0157C05861564", // Uniswap V3
      ],
      minProfitThreshold: ethers.parseEther("0.01"),
      maxBlocksAhead: 3,
      confidenceThreshold: 0.7,
    });
  });

  after(async function () {
    await redis.quit();
  });

  // ═══════════════════════════════════════════════════════════════════
  //                    PATTERN RECOGNITION TESTS
  // ═══════════════════════════════════════════════════════════════════

  describe("Pattern Recognition", function () {
    it("should detect classic sandwich attack pattern", async function () {
      // Victim: buys 10 ETH worth of tokens
      const victimTx: PendingTransaction = {
        hash: "0xvictim123",
        from: "0xVictimAddress",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("10"),
        gasPrice: ethers.parseUnits("50", "gwei"),
        gasLimit: 300000n,
        nonce: 100,
        data: "0x7ff36ab5", // swapExactETHForTokens
        timestamp: Date.now(),
      };

      // Frontrun: attacker buys just before victim
      const frontrunTx: PendingTransaction = {
        hash: "0xfrontrun456",
        from: "0xAttackerAddress",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("50"),
        gasPrice: ethers.parseUnits("60", "gwei"), // Higher gas to front-run
        gasLimit: 300000n,
        nonce: 1,
        data: "0x7ff36ab5",
        timestamp: Date.now() - 100,
      };

      // Backrun: attacker sells right after victim
      const backrunTx: PendingTransaction = {
        hash: "0xbackrun789",
        from: "0xAttackerAddress",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: 0n,
        gasPrice: ethers.parseUnits("49", "gwei"), // Lower gas, executes after
        gasLimit: 300000n,
        nonce: 2,
        data: "0x38ed1739", // swapExactTokensForTokens (sell)
        timestamp: Date.now() + 100,
      };

      const result = await detector.detectSandwich(victimTx, [frontrunTx, backrunTx]);

      expect(result.isSandwich).to.equal(true);
      expect(result.confidence).to.be.gte(0.8);
      expect(result.attackerAddress).to.equal("0xAttackerAddress");
    });

    it("should identify frontrun transaction by gas price pattern", async function () {
      const victimTx: PendingTransaction = {
        hash: "0xvictim",
        from: "0xVictim",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("5"),
        gasPrice: ethers.parseUnits("50", "gwei"),
        gasLimit: 250000n,
        nonce: 50,
        data: "0x7ff36ab5",
        timestamp: Date.now(),
      };

      const potentialFrontrun: PendingTransaction = {
        hash: "0xsuspect",
        from: "0xSuspect",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("20"),
        gasPrice: ethers.parseUnits("51", "gwei"), // Slightly higher
        gasLimit: 250000n,
        nonce: 1,
        data: "0x7ff36ab5",
        timestamp: Date.now() - 50,
      };

      const isFrontrun = detector.isFrontrunCandidate(victimTx, potentialFrontrun);

      expect(isFrontrun).to.equal(true);
    });

    it("should identify backrun transaction by timing and direction", async function () {
      const victimTx: PendingTransaction = {
        hash: "0xvictim",
        from: "0xVictim",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("5"),
        gasPrice: ethers.parseUnits("50", "gwei"),
        gasLimit: 250000n,
        nonce: 50,
        data: "0x7ff36ab5", // Buy
        timestamp: Date.now(),
      };

      const potentialBackrun: PendingTransaction = {
        hash: "0xbackrun",
        from: "0xAttacker",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: 0n,
        gasPrice: ethers.parseUnits("49", "gwei"), // Lower gas
        gasLimit: 250000n,
        nonce: 2,
        data: "0x38ed1739", // Sell (opposite direction)
        timestamp: Date.now() + 50,
      };

      const isBackrun = detector.isBackrunCandidate(victimTx, potentialBackrun);

      expect(isBackrun).to.equal(true);
    });

    it("should NOT flag normal sequential trades as sandwich", async function () {
      const normalTx1: PendingTransaction = {
        hash: "0xnormal1",
        from: "0xTrader1",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("2"),
        gasPrice: ethers.parseUnits("40", "gwei"),
        gasLimit: 200000n,
        nonce: 10,
        data: "0x7ff36ab5",
        timestamp: Date.now(),
      };

      const normalTx2: PendingTransaction = {
        hash: "0xnormal2",
        from: "0xTrader2", // Different sender
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("3"),
        gasPrice: ethers.parseUnits("41", "gwei"),
        gasLimit: 200000n,
        nonce: 20,
        data: "0x7ff36ab5",
        timestamp: Date.now() - 100,
      };

      const normalTx3: PendingTransaction = {
        hash: "0xnormal3",
        from: "0xTrader3", // Different sender again
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("1"),
        gasPrice: ethers.parseUnits("39", "gwei"),
        gasLimit: 200000n,
        nonce: 30,
        data: "0x7ff36ab5",
        timestamp: Date.now() + 100,
      };

      const result = await detector.detectSandwich(normalTx1, [normalTx2, normalTx3]);

      // Should have low confidence or not detect as sandwich
      expect(result.isSandwich).to.equal(false);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                    CONFIDENCE SCORING TESTS
  // ═══════════════════════════════════════════════════════════════════

  describe("Confidence Scoring", function () {
    it("should assign high confidence for clear sandwich pattern", async function () {
      const victimTx: PendingTransaction = {
        hash: "0xvictim",
        from: "0xVictim",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("20"),
        gasPrice: ethers.parseUnits("50", "gwei"),
        gasLimit: 300000n,
        nonce: 100,
        data: "0x7ff36ab5",
        timestamp: Date.now(),
      };

      const frontrun: PendingTransaction = {
        hash: "0xfront",
        from: "0xAttacker",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("100"),
        gasPrice: ethers.parseUnits("55", "gwei"), // 10% higher
        gasLimit: 300000n,
        nonce: 1,
        data: "0x7ff36ab5", // Same swap direction
        timestamp: Date.now() - 200,
      };

      const backrun: PendingTransaction = {
        hash: "0xback",
        from: "0xAttacker", // Same address as frontrun
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: 0n,
        gasPrice: ethers.parseUnits("45", "gwei"),
        gasLimit: 300000n,
        nonce: 2,
        data: "0x38ed1739", // Opposite direction
        timestamp: Date.now() + 200,
      };

      const result = await detector.detectSandwich(victimTx, [frontrun, backrun]);

      expect(result.confidence).to.be.gte(0.9); // Very high confidence
    });

    it("should assign lower confidence for ambiguous patterns", async function () {
      const victimTx: PendingTransaction = {
        hash: "0xvictim",
        from: "0xVictim",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("1"),
        gasPrice: ethers.parseUnits("50", "gwei"),
        gasLimit: 200000n,
        nonce: 100,
        data: "0x7ff36ab5",
        timestamp: Date.now(),
      };

      const ambiguousTx: PendingTransaction = {
        hash: "0xambiguous",
        from: "0xUnknown",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("2"),
        gasPrice: ethers.parseUnits("50", "gwei"), // Same gas (not clear frontrun)
        gasLimit: 200000n,
        nonce: 50,
        data: "0x7ff36ab5",
        timestamp: Date.now() - 1000, // Long time before (ambiguous)
      };

      const result = await detector.detectSandwich(victimTx, [ambiguousTx]);

      expect(result.confidence).to.be.lt(0.5); // Low confidence
    });

    it("should factor in profit estimation for confidence", async function () {
      const victimTx: PendingTransaction = {
        hash: "0xvictim",
        from: "0xVictim",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("100"), // Large trade
        gasPrice: ethers.parseUnits("50", "gwei"),
        gasLimit: 300000n,
        nonce: 100,
        data: "0x7ff36ab5",
        timestamp: Date.now(),
      };

      const frontrun: PendingTransaction = {
        hash: "0xfront",
        from: "0xAttacker",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("200"), // Proportionally large
        gasPrice: ethers.parseUnits("55", "gwei"),
        gasLimit: 300000n,
        nonce: 1,
        data: "0x7ff36ab5",
        timestamp: Date.now() - 100,
      };

      const backrun: PendingTransaction = {
        hash: "0xback",
        from: "0xAttacker",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: 0n,
        gasPrice: ethers.parseUnits("45", "gwei"),
        gasLimit: 300000n,
        nonce: 2,
        data: "0x38ed1739",
        timestamp: Date.now() + 100,
      };

      const result = await detector.detectSandwich(victimTx, [frontrun, backrun]);

      // High profit potential increases confidence
      expect(result.estimatedProfit).to.be.gt(0n);
      expect(result.confidence).to.be.gte(0.85);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                    FALSE POSITIVE RATE TESTS
  // ═══════════════════════════════════════════════════════════════════

  describe("False Positive Prevention", function () {
    it("should not flag arbitrage bots as sandwich attacks", async function () {
      // Arbitrage: buy on DEX A, sell on DEX B (different routers)
      const victimTx: PendingTransaction = {
        hash: "0xvictim",
        from: "0xNormalUser",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("5"),
        gasPrice: ethers.parseUnits("50", "gwei"),
        gasLimit: 200000n,
        nonce: 10,
        data: "0x7ff36ab5",
        timestamp: Date.now(),
      };

      const arbBuy: PendingTransaction = {
        hash: "0xarb1",
        from: "0xArbBot",
        to: "0xE592427A0AEce92De3Edee1F18E0157C05861564", // Different DEX
        value: ethers.parseEther("100"),
        gasPrice: ethers.parseUnits("55", "gwei"),
        gasLimit: 300000n,
        nonce: 1,
        data: "0x414bf389",
        timestamp: Date.now() - 50,
      };

      const arbSell: PendingTransaction = {
        hash: "0xarb2",
        from: "0xArbBot",
        to: "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", // Another DEX
        value: 0n,
        gasPrice: ethers.parseUnits("45", "gwei"),
        gasLimit: 300000n,
        nonce: 2,
        data: "0x38ed1739",
        timestamp: Date.now() + 50,
      };

      const result = await detector.detectSandwich(victimTx, [arbBuy, arbSell]);

      // Should recognize different DEXes mean not sandwich
      expect(result.isSandwich).to.equal(false);
    });

    it("should not flag market makers providing liquidity", async function () {
      const victimTx: PendingTransaction = {
        hash: "0xvictim",
        from: "0xRetailTrader",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("2"),
        gasPrice: ethers.parseUnits("45", "gwei"),
        gasLimit: 200000n,
        nonce: 5,
        data: "0x7ff36ab5",
        timestamp: Date.now(),
      };

      const mmAddLiquidity: PendingTransaction = {
        hash: "0xmm",
        from: "0xMarketMaker",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("50"),
        gasPrice: ethers.parseUnits("50", "gwei"),
        gasLimit: 400000n,
        nonce: 100,
        data: "0xe8e33700", // addLiquidity (not swap)
        timestamp: Date.now() - 100,
      };

      const result = await detector.detectSandwich(victimTx, [mmAddLiquidity]);

      // Adding liquidity is not sandwiching
      expect(result.isSandwich).to.equal(false);
    });

    it("should maintain false positive rate below 5%", async function () {
      this.timeout(30000); // Longer timeout for bulk test

      let falsePositives = 0;
      const totalTests = 100;

      for (let i = 0; i < totalTests; i++) {
        // Generate random legitimate transactions
        const tx1: PendingTransaction = {
          hash: `0xlegit${i}_1`,
          from: `0xUser${i % 10}`,
          to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
          value: ethers.parseEther((Math.random() * 10).toString()),
          gasPrice: ethers.parseUnits(Math.floor(40 + Math.random() * 20).toString(), "gwei"),
          gasLimit: BigInt(200000 + Math.floor(Math.random() * 100000)),
          nonce: i,
          data: "0x7ff36ab5",
          timestamp: Date.now() + i * 1000,
        };

        const tx2: PendingTransaction = {
          hash: `0xlegit${i}_2`,
          from: `0xUser${(i + 5) % 10}`, // Different user
          to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
          value: ethers.parseEther((Math.random() * 10).toString()),
          gasPrice: ethers.parseUnits(Math.floor(40 + Math.random() * 20).toString(), "gwei"),
          gasLimit: BigInt(200000 + Math.floor(Math.random() * 100000)),
          nonce: i + 100,
          data: "0x7ff36ab5",
          timestamp: Date.now() + i * 1000 + 500,
        };

        const result = await detector.detectSandwich(tx1, [tx2]);

        if (result.isSandwich && result.confidence > 0.7) {
          falsePositives++;
        }
      }

      const falsePositiveRate = (falsePositives / totalTests) * 100;
      console.log(`False positive rate: ${falsePositiveRate.toFixed(2)}%`);

      expect(falsePositiveRate).to.be.lt(5);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                    MULTI-VICTIM DETECTION TESTS
  // ═══════════════════════════════════════════════════════════════════

  describe("Multi-Victim Attack Detection", function () {
    it("should detect multiple victims in same sandwich", async function () {
      const victim1: PendingTransaction = {
        hash: "0xvictim1",
        from: "0xVictim1",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("5"),
        gasPrice: ethers.parseUnits("50", "gwei"),
        gasLimit: 250000n,
        nonce: 10,
        data: "0x7ff36ab5",
        timestamp: Date.now(),
      };

      const victim2: PendingTransaction = {
        hash: "0xvictim2",
        from: "0xVictim2",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("8"),
        gasPrice: ethers.parseUnits("51", "gwei"),
        gasLimit: 250000n,
        nonce: 20,
        data: "0x7ff36ab5",
        timestamp: Date.now() + 50,
      };

      const frontrun: PendingTransaction = {
        hash: "0xfront",
        from: "0xAttacker",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("100"),
        gasPrice: ethers.parseUnits("60", "gwei"), // Higher than both victims
        gasLimit: 300000n,
        nonce: 1,
        data: "0x7ff36ab5",
        timestamp: Date.now() - 100,
      };

      const backrun: PendingTransaction = {
        hash: "0xback",
        from: "0xAttacker",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: 0n,
        gasPrice: ethers.parseUnits("45", "gwei"), // Lower than both victims
        gasLimit: 300000n,
        nonce: 2,
        data: "0x38ed1739",
        timestamp: Date.now() + 100,
      };

      const result = await detector.detectMultiVictimSandwich([victim1, victim2], [frontrun, backrun]);

      expect(result.isMultiVictimSandwich).to.equal(true);
      expect(result.victimCount).to.equal(2);
      expect(result.totalVictimLoss).to.be.gt(0n);
    });

    it("should calculate aggregate victim losses", async function () {
      const victims: PendingTransaction[] = [];

      for (let i = 0; i < 3; i++) {
        victims.push({
          hash: `0xvictim${i}`,
          from: `0xVictim${i}`,
          to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
          value: ethers.parseEther("5"),
          gasPrice: ethers.parseUnits("50", "gwei"),
          gasLimit: 250000n,
          nonce: 10 + i,
          data: "0x7ff36ab5",
          timestamp: Date.now() + i * 10,
        });
      }

      const frontrun: PendingTransaction = {
        hash: "0xfront",
        from: "0xAttacker",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("150"),
        gasPrice: ethers.parseUnits("60", "gwei"),
        gasLimit: 300000n,
        nonce: 1,
        data: "0x7ff36ab5",
        timestamp: Date.now() - 100,
      };

      const backrun: PendingTransaction = {
        hash: "0xback",
        from: "0xAttacker",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: 0n,
        gasPrice: ethers.parseUnits("40", "gwei"),
        gasLimit: 300000n,
        nonce: 2,
        data: "0x38ed1739",
        timestamp: Date.now() + 100,
      };

      const result = await detector.detectMultiVictimSandwich(victims, [frontrun, backrun]);

      // Aggregate loss should be sum of all victim losses
      expect(result.totalVictimLoss).to.be.gt(result.victimLosses[0]);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                    DETECTION LATENCY TESTS
  // ═══════════════════════════════════════════════════════════════════

  describe("Detection Latency", function () {
    it("should detect sandwich within 100ms", async function () {
      const victimTx: PendingTransaction = {
        hash: "0xvictim",
        from: "0xVictim",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("10"),
        gasPrice: ethers.parseUnits("50", "gwei"),
        gasLimit: 300000n,
        nonce: 100,
        data: "0x7ff36ab5",
        timestamp: Date.now(),
      };

      const frontrun: PendingTransaction = {
        hash: "0xfront",
        from: "0xAttacker",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("50"),
        gasPrice: ethers.parseUnits("55", "gwei"),
        gasLimit: 300000n,
        nonce: 1,
        data: "0x7ff36ab5",
        timestamp: Date.now() - 100,
      };

      const backrun: PendingTransaction = {
        hash: "0xback",
        from: "0xAttacker",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: 0n,
        gasPrice: ethers.parseUnits("45", "gwei"),
        gasLimit: 300000n,
        nonce: 2,
        data: "0x38ed1739",
        timestamp: Date.now() + 100,
      };

      const startTime = process.hrtime.bigint();
      const result = await detector.detectSandwich(victimTx, [frontrun, backrun]);
      const endTime = process.hrtime.bigint();

      const latencyMs = Number(endTime - startTime) / 1_000_000;
      console.log(`Detection latency: ${latencyMs.toFixed(2)}ms`);

      expect(latencyMs).to.be.lt(100);
      expect(result.isSandwich).to.equal(true);
    });

    it("should handle high transaction volumes efficiently", async function () {
      this.timeout(10000);

      const victimTx: PendingTransaction = {
        hash: "0xvictim",
        from: "0xVictim",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("10"),
        gasPrice: ethers.parseUnits("50", "gwei"),
        gasLimit: 300000n,
        nonce: 100,
        data: "0x7ff36ab5",
        timestamp: Date.now(),
      };

      // Generate 1000 pending transactions to analyze
      const pendingTxs: PendingTransaction[] = [];
      for (let i = 0; i < 1000; i++) {
        pendingTxs.push({
          hash: `0xtx${i}`,
          from: `0xAddress${i % 100}`,
          to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
          value: ethers.parseEther((Math.random() * 10).toString()),
          gasPrice: ethers.parseUnits(Math.floor(40 + Math.random() * 30).toString(), "gwei"),
          gasLimit: BigInt(200000 + Math.floor(Math.random() * 100000)),
          nonce: i,
          data: "0x7ff36ab5",
          timestamp: Date.now() + (Math.random() - 0.5) * 1000,
        });
      }

      const startTime = process.hrtime.bigint();
      const result = await detector.detectSandwich(victimTx, pendingTxs);
      const endTime = process.hrtime.bigint();

      const latencyMs = Number(endTime - startTime) / 1_000_000;
      console.log(`Bulk detection latency (1000 txs): ${latencyMs.toFixed(2)}ms`);

      // Should complete within reasonable time even with many transactions
      expect(latencyMs).to.be.lt(1000); // 1 second max
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                    PROTECTION MECHANISM TESTS
  // ═══════════════════════════════════════════════════════════════════

  describe("Protection Mechanisms", function () {
    it("should calculate optimal gas price to avoid sandwich", async function () {
      const victimTx: PendingTransaction = {
        hash: "0xvictim",
        from: "0xVictim",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("10"),
        gasPrice: ethers.parseUnits("50", "gwei"),
        gasLimit: 300000n,
        nonce: 100,
        data: "0x7ff36ab5",
        timestamp: Date.now(),
      };

      const frontrun: PendingTransaction = {
        hash: "0xfront",
        from: "0xAttacker",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("50"),
        gasPrice: ethers.parseUnits("55", "gwei"),
        gasLimit: 300000n,
        nonce: 1,
        data: "0x7ff36ab5",
        timestamp: Date.now() - 100,
      };

      const optimalGasPrice = await detector.calculateSafeGasPrice(victimTx, [frontrun]);

      // Should recommend gas price higher than attacker's frontrun
      expect(optimalGasPrice).to.be.gt(ethers.parseUnits("55", "gwei"));
    });

    it("should suggest slippage tolerance to mitigate attack", async function () {
      const tradeAmount = ethers.parseEther("10");
      const currentPrice = ethers.parseUnits("2000", 6);

      const recommendedSlippage = await detector.calculateSafeSlippage(tradeAmount, currentPrice);

      // Should recommend appropriate slippage (e.g., 0.5% to 2%)
      expect(recommendedSlippage).to.be.gte(0.5);
      expect(recommendedSlippage).to.be.lte(5);
    });

    it("should recommend transaction bundling for protection", async function () {
      const victimTx: PendingTransaction = {
        hash: "0xvictim",
        from: "0xVictim",
        to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        value: ethers.parseEther("100"), // Large trade
        gasPrice: ethers.parseUnits("50", "gwei"),
        gasLimit: 300000n,
        nonce: 100,
        data: "0x7ff36ab5",
        timestamp: Date.now(),
      };

      const protection = await detector.getProtectionRecommendation(victimTx);

      expect(protection).toHaveProperty("useBundler");
      expect(protection).toHaveProperty("recommendedSlippage");
      expect(protection).toHaveProperty("optimalGasPrice");
      expect(protection).toHaveProperty("splitTrade");

      // For large trades, should recommend bundler
      if (victimTx.value > ethers.parseEther("50")) {
        expect(protection.useBundler).to.equal(true);
      }
    });
  });
});

export {};
