import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

/**
 * ADVANCED ORDER ENGINE TEST SUITE
 *
 * Test Coverage Goals:
 * - Unit tests: 95%+ code coverage
 * - Edge cases: All boundary conditions
 * - Gas optimization: Track gas usage
 * - Security: Reentrancy, access control, overflow protection
 *
 * Test Categories:
 * 1. Deployment & Configuration
 * 2. Fill-or-Kill (FOK) Orders
 * 3. Immediate-or-Cancel (IOC) Orders
 * 4. Post-Only Orders
 * 5. Iceberg Orders
 * 6. TWAP Orders
 * 7. Bracket Orders
 * 8. Rate Limiting
 * 9. Access Control
 * 10. Emergency Functions
 */

describe("AdvancedOrderEngine", function () {
  // Fixture to deploy contracts once and reset state between tests
  async function deployOrderEngineFixture() {
    const [owner, operator, trader1, trader2, trader3, circuitBreaker] = await ethers.getSigners();

    // Deploy mock ERC20 tokens
    const MockERC20 = await ethers.getContractFactory("MockERC20");
    const baseToken = await MockERC20.deploy("Wrapped Ether", "WETH", 18);
    const quoteToken = await MockERC20.deploy("USD Coin", "USDC", 6);

    // Deploy AdvancedOrderEngine
    const AdvancedOrderEngine = await ethers.getContractFactory("AdvancedOrderEngine");
    const orderEngine = await AdvancedOrderEngine.deploy();

    // Setup roles
    const OPERATOR_ROLE = await orderEngine.OPERATOR_ROLE();
    const CIRCUIT_BREAKER_ROLE = await orderEngine.CIRCUIT_BREAKER_ROLE();
    await orderEngine.grantRole(OPERATOR_ROLE, operator.address);
    await orderEngine.grantRole(CIRCUIT_BREAKER_ROLE, circuitBreaker.address);

    // Mint tokens to traders
    const mintAmount = ethers.parseEther("10000");
    const usdcMintAmount = ethers.parseUnits("10000000", 6); // 10M USDC

    await baseToken.mint(trader1.address, mintAmount);
    await baseToken.mint(trader2.address, mintAmount);
    await baseToken.mint(trader3.address, mintAmount);
    await quoteToken.mint(trader1.address, usdcMintAmount);
    await quoteToken.mint(trader2.address, usdcMintAmount);
    await quoteToken.mint(trader3.address, usdcMintAmount);

    // Approve order engine
    const maxApproval = ethers.MaxUint256;
    await baseToken.connect(trader1).approve(orderEngine.target, maxApproval);
    await baseToken.connect(trader2).approve(orderEngine.target, maxApproval);
    await baseToken.connect(trader3).approve(orderEngine.target, maxApproval);
    await quoteToken.connect(trader1).approve(orderEngine.target, maxApproval);
    await quoteToken.connect(trader2).approve(orderEngine.target, maxApproval);
    await quoteToken.connect(trader3).approve(orderEngine.target, maxApproval);

    return {
      orderEngine,
      baseToken,
      quoteToken,
      owner,
      operator,
      trader1,
      trader2,
      trader3,
      circuitBreaker,
      OPERATOR_ROLE,
      CIRCUIT_BREAKER_ROLE,
    };
  }

  // ═══════════════════════════════════════════════════════════════════
  //                     1. DEPLOYMENT & CONFIGURATION
  // ═══════════════════════════════════════════════════════════════════

  describe("Deployment & Configuration", function () {
    it("should deploy with correct initial state", async function () {
      const { orderEngine, owner } = await loadFixture(deployOrderEngineFixture);

      expect(await orderEngine.paused()).to.equal(false);
      const DEFAULT_ADMIN_ROLE = await orderEngine.DEFAULT_ADMIN_ROLE();
      expect(await orderEngine.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.equal(true);
    });

    it("should grant operator role correctly", async function () {
      const { orderEngine, operator, OPERATOR_ROLE } = await loadFixture(deployOrderEngineFixture);

      expect(await orderEngine.hasRole(OPERATOR_ROLE, operator.address)).to.equal(true);
    });

    it("should grant circuit breaker role correctly", async function () {
      const { orderEngine, circuitBreaker, CIRCUIT_BREAKER_ROLE } = await loadFixture(deployOrderEngineFixture);

      expect(await orderEngine.hasRole(CIRCUIT_BREAKER_ROLE, circuitBreaker.address)).to.equal(true);
    });

    it("should track order count starting at zero", async function () {
      const { orderEngine } = await loadFixture(deployOrderEngineFixture);

      expect(await orderEngine.orderCount()).to.equal(0);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                     2. FILL-OR-KILL (FOK) ORDERS
  // ═══════════════════════════════════════════════════════════════════

  describe("Fill-or-Kill (FOK) Orders", function () {
    it("should submit FOK buy order successfully when liquidity available", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2, operator } = await loadFixture(
        deployOrderEngineFixture
      );

      // Trader2 places sell order first (provides liquidity)
      const sellAmount = ethers.parseEther("10"); // 10 WETH
      const price = ethers.parseUnits("2000", 6); // 2000 USDC per WETH
      await orderEngine
        .connect(trader2)
        .submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      // Trader1 places FOK buy order
      const buyAmount = ethers.parseEther("5"); // 5 WETH
      const tx = await orderEngine
        .connect(trader1)
        .submitFOKOrder(baseToken.target, quoteToken.target, buyAmount, price, true);

      const receipt = await tx.wait();
      expect(receipt?.status).to.equal(1);

      // Verify order was created
      const orderCount = await orderEngine.orderCount();
      expect(orderCount).to.be.gt(0);
    });

    it("should revert FOK order when insufficient liquidity", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2 } = await loadFixture(deployOrderEngineFixture);

      // Trader2 places small sell order
      const sellAmount = ethers.parseEther("2"); // Only 2 WETH available
      const price = ethers.parseUnits("2000", 6);
      await orderEngine
        .connect(trader2)
        .submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      // Trader1 tries FOK for 10 WETH - should fail
      const buyAmount = ethers.parseEther("10");
      await expect(
        orderEngine.connect(trader1).submitFOKOrder(baseToken.target, quoteToken.target, buyAmount, price, true)
      ).to.be.revertedWith("FOK: Insufficient liquidity");
    });

    it("should emit FOKOrderFilled event on success", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2 } = await loadFixture(deployOrderEngineFixture);

      const sellAmount = ethers.parseEther("10");
      const price = ethers.parseUnits("2000", 6);
      await orderEngine
        .connect(trader2)
        .submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      const buyAmount = ethers.parseEther("5");
      await expect(
        orderEngine.connect(trader1).submitFOKOrder(baseToken.target, quoteToken.target, buyAmount, price, true)
      ).to.emit(orderEngine, "FOKOrderFilled");
    });

    it("should transfer correct token amounts for FOK order", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2 } = await loadFixture(deployOrderEngineFixture);

      const sellAmount = ethers.parseEther("10");
      const price = ethers.parseUnits("2000", 6);
      await orderEngine
        .connect(trader2)
        .submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      const trader1InitialWETH = await baseToken.balanceOf(trader1.address);
      const trader1InitialUSDC = await quoteToken.balanceOf(trader1.address);

      const buyAmount = ethers.parseEther("5");
      const expectedCost = buyAmount * price / ethers.parseEther("1");

      await orderEngine
        .connect(trader1)
        .submitFOKOrder(baseToken.target, quoteToken.target, buyAmount, price, true);

      const trader1FinalWETH = await baseToken.balanceOf(trader1.address);
      const trader1FinalUSDC = await quoteToken.balanceOf(trader1.address);

      expect(trader1FinalWETH - trader1InitialWETH).to.equal(buyAmount);
      expect(trader1InitialUSDC - trader1FinalUSDC).to.be.closeTo(expectedCost, ethers.parseUnits("1", 6)); // 1 USDC tolerance
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                  3. IMMEDIATE-OR-CANCEL (IOC) ORDERS
  // ═══════════════════════════════════════════════════════════════════

  describe("Immediate-or-Cancel (IOC) Orders", function () {
    it("should fill partial IOC order and return unfilled portion", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2 } = await loadFixture(deployOrderEngineFixture);

      // Only 3 WETH available
      const sellAmount = ethers.parseEther("3");
      const price = ethers.parseUnits("2000", 6);
      await orderEngine
        .connect(trader2)
        .submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      // Request 10 WETH - should only fill 3
      const buyAmount = ethers.parseEther("10");
      const tx = await orderEngine
        .connect(trader1)
        .submitIOCOrder(baseToken.target, quoteToken.target, buyAmount, price, true);

      const receipt = await tx.wait();
      expect(receipt?.status).to.equal(1);

      // Check order status - should be partially filled
      const orderCount = await orderEngine.orderCount();
      const order = await orderEngine.getOrder(orderCount);
      expect(order.filledAmount).to.equal(sellAmount);
      expect(order.status).to.equal(5); // CANCELLED (remainder cancelled)
    });

    it("should complete full IOC when liquidity sufficient", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2 } = await loadFixture(deployOrderEngineFixture);

      const sellAmount = ethers.parseEther("20");
      const price = ethers.parseUnits("2000", 6);
      await orderEngine
        .connect(trader2)
        .submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      const buyAmount = ethers.parseEther("10");
      await orderEngine.connect(trader1).submitIOCOrder(baseToken.target, quoteToken.target, buyAmount, price, true);

      const orderCount = await orderEngine.orderCount();
      const order = await orderEngine.getOrder(orderCount);
      expect(order.filledAmount).to.equal(buyAmount);
      expect(order.status).to.equal(3); // FILLED
    });

    it("should cancel IOC order when no liquidity available", async function () {
      const { orderEngine, baseToken, quoteToken, trader1 } = await loadFixture(deployOrderEngineFixture);

      const buyAmount = ethers.parseEther("10");
      const price = ethers.parseUnits("2000", 6);

      const tx = await orderEngine
        .connect(trader1)
        .submitIOCOrder(baseToken.target, quoteToken.target, buyAmount, price, true);

      const receipt = await tx.wait();
      expect(receipt?.status).to.equal(1);

      const orderCount = await orderEngine.orderCount();
      const order = await orderEngine.getOrder(orderCount);
      expect(order.filledAmount).to.equal(0);
      expect(order.status).to.equal(4); // CANCELLED
    });

    it("should emit IOCOrderPartialFill event", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2 } = await loadFixture(deployOrderEngineFixture);

      const sellAmount = ethers.parseEther("5");
      const price = ethers.parseUnits("2000", 6);
      await orderEngine
        .connect(trader2)
        .submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      const buyAmount = ethers.parseEther("10");
      await expect(
        orderEngine.connect(trader1).submitIOCOrder(baseToken.target, quoteToken.target, buyAmount, price, true)
      ).to.emit(orderEngine, "IOCOrderPartialFill");
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                        4. POST-ONLY ORDERS
  // ═══════════════════════════════════════════════════════════════════

  describe("Post-Only Orders", function () {
    it("should accept Post-Only order that adds liquidity", async function () {
      const { orderEngine, baseToken, quoteToken, trader1 } = await loadFixture(deployOrderEngineFixture);

      // No existing orders at this price - this will be maker
      const amount = ethers.parseEther("10");
      const price = ethers.parseUnits("2000", 6);

      const tx = await orderEngine
        .connect(trader1)
        .submitPostOnlyOrder(baseToken.target, quoteToken.target, amount, price, true);

      const receipt = await tx.wait();
      expect(receipt?.status).to.equal(1);

      const orderCount = await orderEngine.orderCount();
      const order = await orderEngine.getOrder(orderCount);
      expect(order.status).to.equal(1); // OPEN
    });

    it("should reject Post-Only order that would take liquidity", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2 } = await loadFixture(deployOrderEngineFixture);

      // Existing sell order at 2000 USDC
      const sellAmount = ethers.parseEther("10");
      const price = ethers.parseUnits("2000", 6);
      await orderEngine
        .connect(trader2)
        .submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      // Post-Only buy at same price would take liquidity - should reject
      const buyAmount = ethers.parseEther("5");
      await expect(
        orderEngine.connect(trader1).submitPostOnlyOrder(baseToken.target, quoteToken.target, buyAmount, price, true)
      ).to.be.revertedWith("Post-Only: Would take liquidity");
    });

    it("should accept Post-Only at better maker price", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2 } = await loadFixture(deployOrderEngineFixture);

      // Existing sell at 2000
      const sellAmount = ethers.parseEther("10");
      const sellPrice = ethers.parseUnits("2000", 6);
      await orderEngine
        .connect(trader2)
        .submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, sellPrice, false, 0);

      // Post-Only buy at 1900 (better for maker, won't match existing)
      const buyAmount = ethers.parseEther("5");
      const buyPrice = ethers.parseUnits("1900", 6);

      const tx = await orderEngine
        .connect(trader1)
        .submitPostOnlyOrder(baseToken.target, quoteToken.target, buyAmount, buyPrice, true);

      const receipt = await tx.wait();
      expect(receipt?.status).to.equal(1);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                         5. ICEBERG ORDERS
  // ═══════════════════════════════════════════════════════════════════

  describe("Iceberg Orders", function () {
    it("should create iceberg order with correct visible size", async function () {
      const { orderEngine, baseToken, quoteToken, trader1 } = await loadFixture(deployOrderEngineFixture);

      const totalSize = ethers.parseEther("100"); // 100 WETH total
      const clipSize = ethers.parseEther("10"); // Show 10 WETH at a time
      const price = ethers.parseUnits("2000", 6);

      const tx = await orderEngine
        .connect(trader1)
        .submitIcebergOrder(baseToken.target, quoteToken.target, totalSize, clipSize, price, false);

      const receipt = await tx.wait();
      expect(receipt?.status).to.equal(1);

      const orderCount = await orderEngine.orderCount();
      const order = await orderEngine.getOrder(orderCount);
      expect(order.visibleSize).to.equal(clipSize);
      expect(order.totalHiddenSize).to.equal(totalSize);
    });

    it("should refill iceberg order after clip is consumed", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2, operator } = await loadFixture(
        deployOrderEngineFixture
      );

      const totalSize = ethers.parseEther("50");
      const clipSize = ethers.parseEther("10");
      const price = ethers.parseUnits("2000", 6);

      await orderEngine
        .connect(trader1)
        .submitIcebergOrder(baseToken.target, quoteToken.target, totalSize, clipSize, price, false);

      // Trader2 buys the visible clip
      const buyAmount = ethers.parseEther("10");
      await orderEngine.connect(trader2).submitLimitOrder(baseToken.target, quoteToken.target, buyAmount, price, true, 0);

      // Operator triggers refill
      const orderCount = await orderEngine.orderCount();
      await orderEngine.connect(operator).refillIcebergOrder(orderCount - 1n);

      // Check that visible size is refilled
      const order = await orderEngine.getOrder(orderCount - 1n);
      expect(order.visibleSize).to.equal(clipSize);
    });

    it("should emit IcebergOrderCreated event", async function () {
      const { orderEngine, baseToken, quoteToken, trader1 } = await loadFixture(deployOrderEngineFixture);

      const totalSize = ethers.parseEther("100");
      const clipSize = ethers.parseEther("10");
      const price = ethers.parseUnits("2000", 6);

      await expect(
        orderEngine.connect(trader1).submitIcebergOrder(baseToken.target, quoteToken.target, totalSize, clipSize, price, false)
      ).to.emit(orderEngine, "IcebergOrderCreated");
    });

    it("should validate clip size is less than total size", async function () {
      const { orderEngine, baseToken, quoteToken, trader1 } = await loadFixture(deployOrderEngineFixture);

      const totalSize = ethers.parseEther("10");
      const clipSize = ethers.parseEther("20"); // Invalid: clip > total
      const price = ethers.parseUnits("2000", 6);

      await expect(
        orderEngine.connect(trader1).submitIcebergOrder(baseToken.target, quoteToken.target, totalSize, clipSize, price, false)
      ).to.be.revertedWith("Iceberg: Clip size must be less than total");
    });

    it("should track remaining hidden size correctly", async function () {
      const { orderEngine, baseToken, quoteToken, trader1 } = await loadFixture(deployOrderEngineFixture);

      const totalSize = ethers.parseEther("100");
      const clipSize = ethers.parseEther("25");
      const price = ethers.parseUnits("2000", 6);

      await orderEngine
        .connect(trader1)
        .submitIcebergOrder(baseToken.target, quoteToken.target, totalSize, clipSize, price, false);

      const orderCount = await orderEngine.orderCount();
      const icebergState = await orderEngine.getIcebergState(orderCount);

      // Hidden = total - visible
      const expectedHidden = totalSize - clipSize;
      expect(icebergState.remainingHidden).to.equal(expectedHidden);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                           6. TWAP ORDERS
  // ═══════════════════════════════════════════════════════════════════

  describe("TWAP Orders", function () {
    it("should create TWAP order with correct parameters", async function () {
      const { orderEngine, baseToken, quoteToken, trader1 } = await loadFixture(deployOrderEngineFixture);

      const totalAmount = ethers.parseEther("100");
      const numSlices = 10; // 10 slices
      const intervalSeconds = 60; // Every 60 seconds
      const maxPrice = ethers.parseUnits("2100", 6);

      const tx = await orderEngine
        .connect(trader1)
        .submitTWAPOrder(baseToken.target, quoteToken.target, totalAmount, numSlices, intervalSeconds, maxPrice, true);

      const receipt = await tx.wait();
      expect(receipt?.status).to.equal(1);

      const orderCount = await orderEngine.orderCount();
      const order = await orderEngine.getOrder(orderCount);
      expect(order.twapSlices).to.equal(numSlices);
      expect(order.twapInterval).to.equal(intervalSeconds);
      expect(order.twapExecuted).to.equal(0);
    });

    it("should execute TWAP slice correctly", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2, operator } = await loadFixture(
        deployOrderEngineFixture
      );

      // Provide liquidity
      const sellAmount = ethers.parseEther("100");
      const price = ethers.parseUnits("2000", 6);
      await orderEngine.connect(trader2).submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      // Create TWAP order
      const totalAmount = ethers.parseEther("50");
      const numSlices = 5;
      const intervalSeconds = 60;
      const maxPrice = ethers.parseUnits("2100", 6);

      await orderEngine
        .connect(trader1)
        .submitTWAPOrder(baseToken.target, quoteToken.target, totalAmount, numSlices, intervalSeconds, maxPrice, true);

      const orderCount = await orderEngine.orderCount();

      // Execute first slice
      await orderEngine.connect(operator).executeTWAPSlice(orderCount);

      const order = await orderEngine.getOrder(orderCount);
      expect(order.twapExecuted).to.equal(1);

      const expectedSliceAmount = totalAmount / BigInt(numSlices);
      expect(order.filledAmount).to.equal(expectedSliceAmount);
    });

    it("should respect TWAP interval timing", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2, operator } = await loadFixture(
        deployOrderEngineFixture
      );

      const sellAmount = ethers.parseEther("100");
      const price = ethers.parseUnits("2000", 6);
      await orderEngine.connect(trader2).submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      const totalAmount = ethers.parseEther("50");
      const numSlices = 5;
      const intervalSeconds = 300; // 5 minutes
      const maxPrice = ethers.parseUnits("2100", 6);

      await orderEngine
        .connect(trader1)
        .submitTWAPOrder(baseToken.target, quoteToken.target, totalAmount, numSlices, intervalSeconds, maxPrice, true);

      const orderCount = await orderEngine.orderCount();

      // Execute first slice
      await orderEngine.connect(operator).executeTWAPSlice(orderCount);

      // Try to execute second slice immediately - should fail
      await expect(orderEngine.connect(operator).executeTWAPSlice(orderCount)).to.be.revertedWith(
        "TWAP: Too early for next slice"
      );

      // Advance time
      await time.increase(intervalSeconds);

      // Now should succeed
      await orderEngine.connect(operator).executeTWAPSlice(orderCount);

      const order = await orderEngine.getOrder(orderCount);
      expect(order.twapExecuted).to.equal(2);
    });

    it("should skip TWAP slice if price exceeds max", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2, operator } = await loadFixture(
        deployOrderEngineFixture
      );

      // Liquidity at high price
      const sellAmount = ethers.parseEther("100");
      const price = ethers.parseUnits("2500", 6); // 2500 USDC
      await orderEngine.connect(trader2).submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      const totalAmount = ethers.parseEther("50");
      const numSlices = 5;
      const intervalSeconds = 60;
      const maxPrice = ethers.parseUnits("2100", 6); // Max 2100

      await orderEngine
        .connect(trader1)
        .submitTWAPOrder(baseToken.target, quoteToken.target, totalAmount, numSlices, intervalSeconds, maxPrice, true);

      const orderCount = await orderEngine.orderCount();

      // Should skip execution due to high price
      await expect(orderEngine.connect(operator).executeTWAPSlice(orderCount)).to.emit(
        orderEngine,
        "TWAPSliceSkipped"
      );
    });

    it("should complete TWAP order after all slices", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2, operator } = await loadFixture(
        deployOrderEngineFixture
      );

      const sellAmount = ethers.parseEther("100");
      const price = ethers.parseUnits("2000", 6);
      await orderEngine.connect(trader2).submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      const totalAmount = ethers.parseEther("10");
      const numSlices = 2;
      const intervalSeconds = 60;
      const maxPrice = ethers.parseUnits("2100", 6);

      await orderEngine
        .connect(trader1)
        .submitTWAPOrder(baseToken.target, quoteToken.target, totalAmount, numSlices, intervalSeconds, maxPrice, true);

      const orderCount = await orderEngine.orderCount();

      // Execute all slices
      await orderEngine.connect(operator).executeTWAPSlice(orderCount);
      await time.increase(intervalSeconds);
      await orderEngine.connect(operator).executeTWAPSlice(orderCount);

      const order = await orderEngine.getOrder(orderCount);
      expect(order.status).to.equal(3); // FILLED
      expect(order.twapExecuted).to.equal(numSlices);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                         7. BRACKET ORDERS
  // ═══════════════════════════════════════════════════════════════════

  describe("Bracket Orders", function () {
    it("should create bracket order with take profit and stop loss", async function () {
      const { orderEngine, baseToken, quoteToken, trader1 } = await loadFixture(deployOrderEngineFixture);

      const amount = ethers.parseEther("10");
      const entryPrice = ethers.parseUnits("2000", 6);
      const takeProfitPrice = ethers.parseUnits("2200", 6); // +10%
      const stopLossPrice = ethers.parseUnits("1800", 6); // -10%

      const tx = await orderEngine
        .connect(trader1)
        .submitBracketOrder(
          baseToken.target,
          quoteToken.target,
          amount,
          entryPrice,
          takeProfitPrice,
          stopLossPrice,
          true
        );

      const receipt = await tx.wait();
      expect(receipt?.status).to.equal(1);

      const orderCount = await orderEngine.orderCount();
      const order = await orderEngine.getOrder(orderCount);
      expect(order.takeProfitPrice).to.equal(takeProfitPrice);
      expect(order.stopLossPrice).to.equal(stopLossPrice);
    });

    it("should validate take profit > stop loss for buy orders", async function () {
      const { orderEngine, baseToken, quoteToken, trader1 } = await loadFixture(deployOrderEngineFixture);

      const amount = ethers.parseEther("10");
      const entryPrice = ethers.parseUnits("2000", 6);
      const takeProfitPrice = ethers.parseUnits("1800", 6); // Invalid: TP < SL
      const stopLossPrice = ethers.parseUnits("2200", 6);

      await expect(
        orderEngine
          .connect(trader1)
          .submitBracketOrder(
            baseToken.target,
            quoteToken.target,
            amount,
            entryPrice,
            takeProfitPrice,
            stopLossPrice,
            true
          )
      ).to.be.revertedWith("Bracket: Invalid price levels");
    });

    it("should trigger take profit when price reaches target", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2, operator } = await loadFixture(
        deployOrderEngineFixture
      );

      // Setup: trader1 buys WETH
      const sellAmount = ethers.parseEther("20");
      const entryPrice = ethers.parseUnits("2000", 6);
      await orderEngine.connect(trader2).submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, entryPrice, false, 0);

      const amount = ethers.parseEther("10");
      const takeProfitPrice = ethers.parseUnits("2200", 6);
      const stopLossPrice = ethers.parseUnits("1800", 6);

      await orderEngine
        .connect(trader1)
        .submitBracketOrder(
          baseToken.target,
          quoteToken.target,
          amount,
          entryPrice,
          takeProfitPrice,
          stopLossPrice,
          true
        );

      const orderCount = await orderEngine.orderCount();

      // Oracle reports price reaching take profit
      await orderEngine.connect(operator).updatePriceOracle(baseToken.target, quoteToken.target, takeProfitPrice);

      // Execute bracket check
      await orderEngine.connect(operator).checkAndExecuteBracket(orderCount);

      // Verify take profit was triggered
      const order = await orderEngine.getOrder(orderCount);
      expect(order.status).to.equal(3); // FILLED
    });

    it("should trigger stop loss when price drops to level", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2, operator } = await loadFixture(
        deployOrderEngineFixture
      );

      const sellAmount = ethers.parseEther("20");
      const entryPrice = ethers.parseUnits("2000", 6);
      await orderEngine.connect(trader2).submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, entryPrice, false, 0);

      const amount = ethers.parseEther("10");
      const takeProfitPrice = ethers.parseUnits("2200", 6);
      const stopLossPrice = ethers.parseUnits("1800", 6);

      await orderEngine
        .connect(trader1)
        .submitBracketOrder(
          baseToken.target,
          quoteToken.target,
          amount,
          entryPrice,
          takeProfitPrice,
          stopLossPrice,
          true
        );

      const orderCount = await orderEngine.orderCount();

      // Price drops to stop loss level
      await orderEngine.connect(operator).updatePriceOracle(baseToken.target, quoteToken.target, stopLossPrice);

      // Execute bracket check
      await orderEngine.connect(operator).checkAndExecuteBracket(orderCount);

      const order = await orderEngine.getOrder(orderCount);
      expect(order.status).to.equal(4); // CANCELLED (stop loss triggered)
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                          8. RATE LIMITING
  // ═══════════════════════════════════════════════════════════════════

  describe("Rate Limiting", function () {
    it("should enforce per-user rate limits", async function () {
      const { orderEngine, baseToken, quoteToken, trader1 } = await loadFixture(deployOrderEngineFixture);

      const amount = ethers.parseEther("1");
      const price = ethers.parseUnits("2000", 6);

      // Submit orders up to rate limit
      const rateLimit = await orderEngine.userRateLimit();

      for (let i = 0; i < Number(rateLimit); i++) {
        await orderEngine.connect(trader1).submitLimitOrder(baseToken.target, quoteToken.target, amount, price, true, 0);
      }

      // Next order should fail
      await expect(
        orderEngine.connect(trader1).submitLimitOrder(baseToken.target, quoteToken.target, amount, price, true, 0)
      ).to.be.revertedWith("Rate limit exceeded");
    });

    it("should reset rate limit after time window", async function () {
      const { orderEngine, baseToken, quoteToken, trader1 } = await loadFixture(deployOrderEngineFixture);

      const amount = ethers.parseEther("1");
      const price = ethers.parseUnits("2000", 6);

      // Hit rate limit
      const rateLimit = await orderEngine.userRateLimit();
      for (let i = 0; i < Number(rateLimit); i++) {
        await orderEngine.connect(trader1).submitLimitOrder(baseToken.target, quoteToken.target, amount, price, true, 0);
      }

      // Advance time past rate limit window
      const windowDuration = await orderEngine.rateLimitWindow();
      await time.increase(Number(windowDuration) + 1);

      // Should succeed now
      await expect(
        orderEngine.connect(trader1).submitLimitOrder(baseToken.target, quoteToken.target, amount, price, true, 0)
      ).to.not.be.reverted;
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                         9. ACCESS CONTROL
  // ═══════════════════════════════════════════════════════════════════

  describe("Access Control", function () {
    it("should prevent non-operator from executing TWAP slice", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2 } = await loadFixture(deployOrderEngineFixture);

      const totalAmount = ethers.parseEther("50");
      const numSlices = 5;
      const intervalSeconds = 60;
      const maxPrice = ethers.parseUnits("2100", 6);

      await orderEngine
        .connect(trader1)
        .submitTWAPOrder(baseToken.target, quoteToken.target, totalAmount, numSlices, intervalSeconds, maxPrice, true);

      const orderCount = await orderEngine.orderCount();

      // trader2 (non-operator) tries to execute
      await expect(orderEngine.connect(trader2).executeTWAPSlice(orderCount)).to.be.reverted;
    });

    it("should prevent non-admin from pausing", async function () {
      const { orderEngine, trader1 } = await loadFixture(deployOrderEngineFixture);

      await expect(orderEngine.connect(trader1).pause()).to.be.reverted;
    });

    it("should allow admin to pause and unpause", async function () {
      const { orderEngine, owner } = await loadFixture(deployOrderEngineFixture);

      await orderEngine.connect(owner).pause();
      expect(await orderEngine.paused()).to.equal(true);

      await orderEngine.connect(owner).unpause();
      expect(await orderEngine.paused()).to.equal(false);
    });

    it("should prevent trading when paused", async function () {
      const { orderEngine, baseToken, quoteToken, owner, trader1 } = await loadFixture(deployOrderEngineFixture);

      await orderEngine.connect(owner).pause();

      const amount = ethers.parseEther("10");
      const price = ethers.parseUnits("2000", 6);

      await expect(
        orderEngine.connect(trader1).submitLimitOrder(baseToken.target, quoteToken.target, amount, price, true, 0)
      ).to.be.revertedWith("Pausable: paused");
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                      10. EMERGENCY FUNCTIONS
  // ═══════════════════════════════════════════════════════════════════

  describe("Emergency Functions", function () {
    it("should allow circuit breaker to emergency cancel order", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, circuitBreaker } = await loadFixture(
        deployOrderEngineFixture
      );

      const amount = ethers.parseEther("10");
      const price = ethers.parseUnits("2000", 6);

      await orderEngine.connect(trader1).submitLimitOrder(baseToken.target, quoteToken.target, amount, price, true, 0);

      const orderCount = await orderEngine.orderCount();

      await orderEngine.connect(circuitBreaker).emergencyCancelOrder(orderCount);

      const order = await orderEngine.getOrder(orderCount);
      expect(order.status).to.equal(4); // CANCELLED
    });

    it("should refund locked tokens on emergency cancel", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, circuitBreaker } = await loadFixture(
        deployOrderEngineFixture
      );

      const initialBalance = await quoteToken.balanceOf(trader1.address);

      const amount = ethers.parseEther("10");
      const price = ethers.parseUnits("2000", 6);

      await orderEngine.connect(trader1).submitLimitOrder(baseToken.target, quoteToken.target, amount, price, true, 0);

      const afterSubmitBalance = await quoteToken.balanceOf(trader1.address);
      expect(afterSubmitBalance).to.be.lt(initialBalance);

      const orderCount = await orderEngine.orderCount();
      await orderEngine.connect(circuitBreaker).emergencyCancelOrder(orderCount);

      const finalBalance = await quoteToken.balanceOf(trader1.address);
      expect(finalBalance).to.be.closeTo(initialBalance, ethers.parseUnits("1", 6));
    });

    it("should prevent non-circuit-breaker from emergency cancel", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2 } = await loadFixture(deployOrderEngineFixture);

      const amount = ethers.parseEther("10");
      const price = ethers.parseUnits("2000", 6);

      await orderEngine.connect(trader1).submitLimitOrder(baseToken.target, quoteToken.target, amount, price, true, 0);

      const orderCount = await orderEngine.orderCount();

      await expect(orderEngine.connect(trader2).emergencyCancelOrder(orderCount)).to.be.reverted;
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                        11. GAS OPTIMIZATION
  // ═══════════════════════════════════════════════════════════════════

  describe("Gas Optimization", function () {
    it("should measure gas for FOK order submission", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2 } = await loadFixture(deployOrderEngineFixture);

      const sellAmount = ethers.parseEther("100");
      const price = ethers.parseUnits("2000", 6);
      await orderEngine.connect(trader2).submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      const buyAmount = ethers.parseEther("10");
      const tx = await orderEngine
        .connect(trader1)
        .submitFOKOrder(baseToken.target, quoteToken.target, buyAmount, price, true);

      const receipt = await tx.wait();
      console.log(`FOK Order Gas Used: ${receipt?.gasUsed}`);

      // Gas should be reasonable (< 500k)
      expect(receipt?.gasUsed).to.be.lt(500000);
    });

    it("should measure gas for Iceberg order creation", async function () {
      const { orderEngine, baseToken, quoteToken, trader1 } = await loadFixture(deployOrderEngineFixture);

      const totalSize = ethers.parseEther("100");
      const clipSize = ethers.parseEther("10");
      const price = ethers.parseUnits("2000", 6);

      const tx = await orderEngine
        .connect(trader1)
        .submitIcebergOrder(baseToken.target, quoteToken.target, totalSize, clipSize, price, false);

      const receipt = await tx.wait();
      console.log(`Iceberg Order Gas Used: ${receipt?.gasUsed}`);

      expect(receipt?.gasUsed).to.be.lt(600000);
    });

    it("should measure gas for TWAP slice execution", async function () {
      const { orderEngine, baseToken, quoteToken, trader1, trader2, operator } = await loadFixture(
        deployOrderEngineFixture
      );

      const sellAmount = ethers.parseEther("100");
      const price = ethers.parseUnits("2000", 6);
      await orderEngine.connect(trader2).submitLimitOrder(baseToken.target, quoteToken.target, sellAmount, price, false, 0);

      const totalAmount = ethers.parseEther("50");
      await orderEngine
        .connect(trader1)
        .submitTWAPOrder(baseToken.target, quoteToken.target, totalAmount, 10, 60, ethers.parseUnits("2100", 6), true);

      const orderCount = await orderEngine.orderCount();

      const tx = await orderEngine.connect(operator).executeTWAPSlice(orderCount);

      const receipt = await tx.wait();
      console.log(`TWAP Slice Execution Gas Used: ${receipt?.gasUsed}`);

      expect(receipt?.gasUsed).to.be.lt(400000);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
//                        MOCK ERC20 CONTRACT
// ═══════════════════════════════════════════════════════════════════

/**
 * Mock ERC20 token for testing purposes
 * Deploy this alongside the main contracts in the fixture
 */
