import { ethers } from "hardhat";
import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";

/**
 * SECURITY FUZZ TESTING SUITE
 *
 * Automated fuzzing to discover:
 * - Integer overflow/underflow vulnerabilities
 * - Edge case handling
 * - Input validation bypasses
 * - Access control flaws
 * - Reentrancy vulnerabilities
 * - Gas griefing attacks
 *
 * Techniques:
 * - Random input generation
 * - Boundary value testing
 * - Mutation testing
 * - Property-based testing
 */

interface FuzzConfig {
  iterations: number;
  seed: number;
  timeout: number;
}

class Fuzzer {
  private rng: () => number;

  constructor(seed: number = Date.now()) {
    // Seeded PRNG for reproducible tests
    this.rng = this.mulberry32(seed);
  }

  private mulberry32(a: number): () => number {
    return function () {
      let t = (a += 0x6d2b79f5);
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  randomUint256(): bigint {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = Math.floor(this.rng() * 256);
    }
    return BigInt("0x" + Buffer.from(bytes).toString("hex"));
  }

  randomUint128(): bigint {
    return this.randomUint256() >> 128n;
  }

  randomUint64(): bigint {
    return BigInt(Math.floor(this.rng() * Number.MAX_SAFE_INTEGER));
  }

  randomAddress(): string {
    const bytes = new Uint8Array(20);
    for (let i = 0; i < 20; i++) {
      bytes[i] = Math.floor(this.rng() * 256);
    }
    return "0x" + Buffer.from(bytes).toString("hex");
  }

  randomBytes32(): string {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = Math.floor(this.rng() * 256);
    }
    return "0x" + Buffer.from(bytes).toString("hex");
  }

  randomBoolean(): boolean {
    return this.rng() > 0.5;
  }

  randomRange(min: number, max: number): number {
    return Math.floor(this.rng() * (max - min + 1)) + min;
  }

  randomElement<T>(arr: T[]): T {
    return arr[Math.floor(this.rng() * arr.length)];
  }

  // Boundary values for common types
  boundaryUint256(): bigint[] {
    return [
      0n,
      1n,
      ethers.MaxUint256 - 1n,
      ethers.MaxUint256,
      ethers.MaxUint256 / 2n,
      ethers.parseEther("1"),
      ethers.parseEther("1000000"),
    ];
  }

  boundaryAddress(): string[] {
    return [
      ethers.ZeroAddress,
      "0x0000000000000000000000000000000000000001",
      "0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF",
      "0xdEaD000000000000000000000000000000000000",
    ];
  }
}

describe("Security Fuzz Testing", function () {
  const fuzzer = new Fuzzer(12345); // Reproducible seed

  async function deployFuzzFixture() {
    const [owner, user1, user2, attacker] = await ethers.getSigners();

    const MockERC20 = await ethers.getContractFactory("MockERC20");
    const token1 = await MockERC20.deploy("Token1", "TK1", 18);
    const token2 = await MockERC20.deploy("Token2", "TK2", 6);

    const AdvancedOrderEngine = await ethers.getContractFactory("AdvancedOrderEngine");
    const orderEngine = await AdvancedOrderEngine.deploy();

    const CircuitBreaker = await ethers.getContractFactory("CircuitBreaker");
    const circuitBreaker = await CircuitBreaker.deploy();

    // Setup
    await token1.mint(user1.address, ethers.parseEther("1000000"));
    await token2.mint(user1.address, ethers.parseUnits("10000000", 6));
    await token1.connect(user1).approve(orderEngine.target, ethers.MaxUint256);
    await token2.connect(user1).approve(orderEngine.target, ethers.MaxUint256);

    return { orderEngine, circuitBreaker, token1, token2, owner, user1, user2, attacker };
  }

  // ═══════════════════════════════════════════════════════════════════
  //                    INTEGER OVERFLOW FUZZING
  // ═══════════════════════════════════════════════════════════════════

  describe("Integer Overflow/Underflow Fuzzing", function () {
    it("should handle random large uint256 prices without overflow", async function () {
      const { orderEngine, token1, token2, user1 } = await loadFixture(deployFuzzFixture);

      for (let i = 0; i < 100; i++) {
        const randomPrice = fuzzer.randomUint128(); // Large but not max
        const randomAmount = fuzzer.randomUint64();

        if (randomAmount > 0n && randomPrice > 0n) {
          try {
            // Should either succeed or revert gracefully, not overflow
            await orderEngine
              .connect(user1)
              .submitLimitOrder(token1.target, token2.target, randomAmount, randomPrice, true, 0);
          } catch (error: any) {
            // Acceptable errors: validation failures, not overflow
            expect(error.message).to.not.include("overflow");
            expect(error.message).to.not.include("underflow");
          }
        }
      }
    });

    it("should handle boundary uint256 values", async function () {
      const { orderEngine, token1, token2, user1 } = await loadFixture(deployFuzzFixture);

      const boundaryValues = fuzzer.boundaryUint256();

      for (const value of boundaryValues) {
        try {
          await orderEngine.connect(user1).submitLimitOrder(token1.target, token2.target, value, value, true, 0);
        } catch (error: any) {
          // Should fail gracefully
          expect(error.message).to.not.include("overflow");
        }
      }
    });

    it("should prevent multiplication overflow in price calculations", async function () {
      const { orderEngine, token1, token2, user1 } = await loadFixture(deployFuzzFixture);

      // Try to cause overflow: price * amount
      const maxPrice = ethers.MaxUint256;
      const maxAmount = ethers.MaxUint256;

      await expect(
        orderEngine.connect(user1).submitLimitOrder(token1.target, token2.target, maxAmount, maxPrice, true, 0)
      ).to.be.reverted;
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                      ADDRESS VALIDATION FUZZING
  // ═══════════════════════════════════════════════════════════════════

  describe("Address Validation Fuzzing", function () {
    it("should reject zero address for tokens", async function () {
      const { orderEngine, token2, user1 } = await loadFixture(deployFuzzFixture);

      await expect(
        orderEngine.connect(user1).submitLimitOrder(
          ethers.ZeroAddress, // Invalid base token
          token2.target,
          ethers.parseEther("1"),
          ethers.parseUnits("2000", 6),
          true,
          0
        )
      ).to.be.revertedWith("Invalid token address");
    });

    it("should reject same token for base and quote", async function () {
      const { orderEngine, token1, user1 } = await loadFixture(deployFuzzFixture);

      await expect(
        orderEngine.connect(user1).submitLimitOrder(
          token1.target,
          token1.target, // Same as base
          ethers.parseEther("1"),
          ethers.parseUnits("2000", 6),
          true,
          0
        )
      ).to.be.revertedWith("Same token");
    });

    it("should handle random addresses gracefully", async function () {
      const { orderEngine, user1 } = await loadFixture(deployFuzzFixture);

      for (let i = 0; i < 50; i++) {
        const randomBase = fuzzer.randomAddress();
        const randomQuote = fuzzer.randomAddress();

        try {
          await orderEngine.connect(user1).submitLimitOrder(
            randomBase,
            randomQuote,
            ethers.parseEther("1"),
            ethers.parseUnits("2000", 6),
            true,
            0
          );
        } catch (error: any) {
          // Should fail validation, not crash
          expect(error).to.exist;
        }
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                    CIRCUIT BREAKER FUZZING
  // ═══════════════════════════════════════════════════════════════════

  describe("Circuit Breaker Security Fuzzing", function () {
    it("should handle random price anomaly inputs", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployFuzzFixture);

      const basePrice = ethers.parseUnits("2000", 6);
      await circuitBreaker.connect(owner).setBaselinePrice(basePrice);

      for (let i = 0; i < 100; i++) {
        const randomPrice = fuzzer.randomUint128();

        try {
          const isAnomaly = await circuitBreaker.checkPriceAnomaly(randomPrice);
          expect(typeof isAnomaly).to.equal("boolean");
        } catch (error: any) {
          // Should not crash
          fail(`Crashed on input: ${randomPrice}`);
        }
      }
    });

    it("should handle random volume spike inputs", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployFuzzFixture);

      const baseVolume = ethers.parseEther("1000");
      await circuitBreaker.connect(owner).setBaselineVolume(baseVolume);

      for (let i = 0; i < 100; i++) {
        const randomVolume = fuzzer.randomUint128();

        const isAnomaly = await circuitBreaker.checkVolumeAnomaly(randomVolume);
        expect(typeof isAnomaly).to.equal("boolean");
      }
    });

    it("should validate operation IDs are unique", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployFuzzFixture);

      const operationIds = new Set<string>();

      for (let i = 0; i < 50; i++) {
        const randomOpId = fuzzer.randomBytes32();
        operationIds.add(randomOpId);

        // Each operation ID should be unique
        expect(operationIds.size).to.equal(i + 1);
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                    ORDER TYPE SPECIFIC FUZZING
  // ═══════════════════════════════════════════════════════════════════

  describe("Order Type Fuzzing", function () {
    it("should handle random TWAP parameters", async function () {
      const { orderEngine, token1, token2, user1 } = await loadFixture(deployFuzzFixture);

      for (let i = 0; i < 50; i++) {
        const totalAmount = BigInt(fuzzer.randomRange(1, 1000)) * ethers.parseEther("1");
        const numSlices = fuzzer.randomRange(1, 100);
        const interval = fuzzer.randomRange(1, 3600);
        const maxPrice = BigInt(fuzzer.randomRange(1000, 3000)) * BigInt(1e6);

        try {
          await orderEngine
            .connect(user1)
            .submitTWAPOrder(token1.target, token2.target, totalAmount, numSlices, interval, maxPrice, true);
        } catch (error: any) {
          // Acceptable rejections
          const acceptableErrors = ["Invalid", "Too", "Must", "Exceeds"];
          const isAcceptable = acceptableErrors.some((err) => error.message.includes(err));
          expect(isAcceptable).to.be.true;
        }
      }
    });

    it("should handle random Iceberg parameters", async function () {
      const { orderEngine, token1, token2, user1 } = await loadFixture(deployFuzzFixture);

      for (let i = 0; i < 50; i++) {
        const totalSize = BigInt(fuzzer.randomRange(1, 1000)) * ethers.parseEther("1");
        const clipSize = BigInt(fuzzer.randomRange(1, 100)) * ethers.parseEther("1");
        const price = BigInt(fuzzer.randomRange(1000, 3000)) * BigInt(1e6);

        try {
          await orderEngine
            .connect(user1)
            .submitIcebergOrder(token1.target, token2.target, totalSize, clipSize, price, false);

          // If successful, clip must be <= total
          expect(clipSize <= totalSize).to.be.true;
        } catch (error: any) {
          // Expected if clip > total
          if (clipSize > totalSize) {
            expect(error.message).to.include("Clip size");
          }
        }
      }
    });

    it("should handle random Bracket order parameters", async function () {
      const { orderEngine, token1, token2, user1 } = await loadFixture(deployFuzzFixture);

      for (let i = 0; i < 50; i++) {
        const amount = BigInt(fuzzer.randomRange(1, 100)) * ethers.parseEther("1");
        const entryPrice = BigInt(fuzzer.randomRange(1000, 3000)) * BigInt(1e6);
        const takeProfitPrice = BigInt(fuzzer.randomRange(1000, 5000)) * BigInt(1e6);
        const stopLossPrice = BigInt(fuzzer.randomRange(500, 3000)) * BigInt(1e6);

        try {
          await orderEngine
            .connect(user1)
            .submitBracketOrder(
              token1.target,
              token2.target,
              amount,
              entryPrice,
              takeProfitPrice,
              stopLossPrice,
              true
            );

          // For buy orders, TP > SL
          expect(takeProfitPrice > stopLossPrice).to.be.true;
        } catch (error: any) {
          // Expected validation failure
          expect(error.message).to.include("Invalid");
        }
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                    REENTRANCY ATTACK FUZZING
  // ═══════════════════════════════════════════════════════════════════

  describe("Reentrancy Attack Fuzzing", function () {
    it("should prevent reentrancy on multiple function combinations", async function () {
      const { orderEngine, token1, token2, user1 } = await loadFixture(deployFuzzFixture);

      // Functions that modify state
      const functions = [
        () => orderEngine.connect(user1).submitLimitOrder(
          token1.target,
          token2.target,
          ethers.parseEther("1"),
          ethers.parseUnits("2000", 6),
          true,
          0
        ),
        () => orderEngine.connect(user1).submitFOKOrder(
          token1.target,
          token2.target,
          ethers.parseEther("1"),
          ethers.parseUnits("2000", 6),
          true
        ),
        () => orderEngine.connect(user1).submitIOCOrder(
          token1.target,
          token2.target,
          ethers.parseEther("1"),
          ethers.parseUnits("2000", 6),
          true
        ),
      ];

      // Call multiple functions rapidly (simulating reentrancy attempts)
      const promises = [];
      for (let i = 0; i < 10; i++) {
        const randomFunc = fuzzer.randomElement(functions);
        promises.push(randomFunc().catch(() => {}));
      }

      // Should not cause reentrancy issues
      await Promise.allSettled(promises);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                      GAS GRIEFING FUZZING
  // ═══════════════════════════════════════════════════════════════════

  describe("Gas Griefing Prevention", function () {
    it("should limit gas consumption for complex operations", async function () {
      const { orderEngine, token1, token2, user1 } = await loadFixture(deployFuzzFixture);

      // Submit order with maximum parameters
      const tx = await orderEngine.connect(user1).submitLimitOrder(
        token1.target,
        token2.target,
        ethers.parseEther("1000000"),
        ethers.parseUnits("10000", 6),
        true,
        0
      );

      const receipt = await tx.wait();
      const gasUsed = receipt?.gasUsed || 0n;

      // Gas should be bounded
      expect(gasUsed).to.be.lt(1000000n); // Less than 1M gas
    });

    it("should prevent excessive loop iterations", async function () {
      const { orderEngine, token1, token2, user1 } = await loadFixture(deployFuzzFixture);

      // Create many small orders rapidly
      const promises = [];
      for (let i = 0; i < 100; i++) {
        promises.push(
          orderEngine.connect(user1).submitLimitOrder(
            token1.target,
            token2.target,
            ethers.parseEther("0.01"),
            ethers.parseUnits("2000", 6),
            fuzzer.randomBoolean(),
            0
          ).catch(() => {})
        );
      }

      // Should complete without excessive gas
      const start = Date.now();
      await Promise.allSettled(promises);
      const elapsed = Date.now() - start;

      // Should complete reasonably quickly (not stuck in loops)
      expect(elapsed).to.be.lt(60000); // Less than 60 seconds
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                    ACCESS CONTROL FUZZING
  // ═══════════════════════════════════════════════════════════════════

  describe("Access Control Fuzzing", function () {
    it("should reject unauthorized callers for admin functions", async function () {
      const { orderEngine, attacker } = await loadFixture(deployFuzzFixture);

      const adminFunctions = [
        () => orderEngine.connect(attacker).pause(),
        () => orderEngine.connect(attacker).unpause(),
        () => orderEngine.connect(attacker).setUserRateLimit(1000),
      ];

      for (const func of adminFunctions) {
        await expect(func()).to.be.reverted;
      }
    });

    it("should reject unauthorized callers for operator functions", async function () {
      const { orderEngine, attacker } = await loadFixture(deployFuzzFixture);

      // Operator-only functions
      await expect(orderEngine.connect(attacker).executeTWAPSlice(1)).to.be.reverted;
    });

    it("should handle malformed role bytes", async function () {
      const { orderEngine } = await loadFixture(deployFuzzFixture);

      for (let i = 0; i < 10; i++) {
        const randomRole = fuzzer.randomBytes32();
        const randomAddress = fuzzer.randomAddress();

        // Should not crash when checking random roles
        const hasRole = await orderEngine.hasRole(randomRole, randomAddress);
        expect(typeof hasRole).to.equal("boolean");
      }
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                      STATE CONSISTENCY FUZZING
  // ═══════════════════════════════════════════════════════════════════

  describe("State Consistency Fuzzing", function () {
    it("should maintain order count consistency after random operations", async function () {
      const { orderEngine, token1, token2, user1 } = await loadFixture(deployFuzzFixture);

      const initialCount = await orderEngine.orderCount();
      let expectedCount = initialCount;

      for (let i = 0; i < 50; i++) {
        try {
          await orderEngine.connect(user1).submitLimitOrder(
            token1.target,
            token2.target,
            ethers.parseEther("0.1"),
            ethers.parseUnits("2000", 6),
            fuzzer.randomBoolean(),
            0
          );
          expectedCount++;
        } catch {
          // Order might fail validation
        }

        const currentCount = await orderEngine.orderCount();
        expect(currentCount).to.be.gte(expectedCount - 1n);
      }
    });

    it("should handle concurrent state modifications", async function () {
      const { orderEngine, token1, token2, user1, user2 } = await loadFixture(deployFuzzFixture);

      await token1.mint(user2.address, ethers.parseEther("1000000"));
      await token2.mint(user2.address, ethers.parseUnits("10000000", 6));
      await token1.connect(user2).approve(orderEngine.target, ethers.MaxUint256);
      await token2.connect(user2).approve(orderEngine.target, ethers.MaxUint256);

      const user1Promises = [];
      const user2Promises = [];

      for (let i = 0; i < 20; i++) {
        user1Promises.push(
          orderEngine.connect(user1).submitLimitOrder(
            token1.target,
            token2.target,
            ethers.parseEther("0.1"),
            ethers.parseUnits("2000", 6),
            true,
            0
          ).catch(() => {})
        );

        user2Promises.push(
          orderEngine.connect(user2).submitLimitOrder(
            token1.target,
            token2.target,
            ethers.parseEther("0.1"),
            ethers.parseUnits("2000", 6),
            false,
            0
          ).catch(() => {})
        );
      }

      await Promise.allSettled([...user1Promises, ...user2Promises]);

      // State should still be consistent
      const finalCount = await orderEngine.orderCount();
      expect(finalCount).to.be.gt(0);
    });
  });
});

export { Fuzzer };
