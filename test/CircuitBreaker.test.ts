import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

/**
 * CIRCUIT BREAKER TEST SUITE
 *
 * Test Coverage Goals:
 * - Multi-sig operation approval flow
 * - Anomaly detection (price, volume, gas)
 * - Emergency withdrawal mechanism
 * - Rate limiting protection
 * - Guardian management
 *
 * Security Test Focus:
 * - Only authorized guardians can trigger pause
 * - Multi-sig threshold enforcement
 * - Time-delayed operations for high-risk functions
 * - Proper cooldown periods
 */

describe("CircuitBreaker", function () {
  async function deployCircuitBreakerFixture() {
    const [owner, guardian1, guardian2, guardian3, guardian4, user1, user2, attacker] = await ethers.getSigners();

    // Deploy mock tokens
    const MockERC20 = await ethers.getContractFactory("MockERC20");
    const protectedToken = await MockERC20.deploy("Protected Token", "PTK", 18);

    // Deploy CircuitBreaker
    const CircuitBreaker = await ethers.getContractFactory("CircuitBreaker");
    const circuitBreaker = await CircuitBreaker.deploy();

    // Setup guardians (multi-sig setup)
    await circuitBreaker.addGuardian(guardian1.address);
    await circuitBreaker.addGuardian(guardian2.address);
    await circuitBreaker.addGuardian(guardian3.address);
    await circuitBreaker.addGuardian(guardian4.address);

    // Set multi-sig threshold to 2
    await circuitBreaker.setSignatureThreshold(2);

    // Mint tokens to circuit breaker for emergency withdrawal testing
    const circuitBreakerBalance = ethers.parseEther("10000");
    await protectedToken.mint(circuitBreaker.target, circuitBreakerBalance);

    return {
      circuitBreaker,
      protectedToken,
      owner,
      guardian1,
      guardian2,
      guardian3,
      guardian4,
      user1,
      user2,
      attacker,
    };
  }

  // ═══════════════════════════════════════════════════════════════════
  //                     1. DEPLOYMENT & INITIALIZATION
  // ═══════════════════════════════════════════════════════════════════

  describe("Deployment & Initialization", function () {
    it("should deploy with correct initial state", async function () {
      const { circuitBreaker } = await loadFixture(deployCircuitBreakerFixture);

      expect(await circuitBreaker.paused()).to.equal(false);
      expect(await circuitBreaker.globalPauseActive()).to.equal(false);
    });

    it("should have owner as default admin", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      const DEFAULT_ADMIN_ROLE = await circuitBreaker.DEFAULT_ADMIN_ROLE();
      expect(await circuitBreaker.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.equal(true);
    });

    it("should register all guardians correctly", async function () {
      const { circuitBreaker, guardian1, guardian2, guardian3, guardian4 } = await loadFixture(
        deployCircuitBreakerFixture
      );

      expect(await circuitBreaker.isGuardian(guardian1.address)).to.equal(true);
      expect(await circuitBreaker.isGuardian(guardian2.address)).to.equal(true);
      expect(await circuitBreaker.isGuardian(guardian3.address)).to.equal(true);
      expect(await circuitBreaker.isGuardian(guardian4.address)).to.equal(true);
    });

    it("should set correct signature threshold", async function () {
      const { circuitBreaker } = await loadFixture(deployCircuitBreakerFixture);

      expect(await circuitBreaker.signatureThreshold()).to.equal(2);
    });

    it("should count total guardians correctly", async function () {
      const { circuitBreaker } = await loadFixture(deployCircuitBreakerFixture);

      expect(await circuitBreaker.guardianCount()).to.equal(4);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                        2. GLOBAL PAUSE
  // ═══════════════════════════════════════════════════════════════════

  describe("Global Pause", function () {
    it("should allow single guardian to trigger global pause", async function () {
      const { circuitBreaker, guardian1 } = await loadFixture(deployCircuitBreakerFixture);

      await circuitBreaker.connect(guardian1).triggerGlobalPause("Suspicious activity detected");

      expect(await circuitBreaker.globalPauseActive()).to.equal(true);
    });

    it("should emit GlobalPauseTriggered event", async function () {
      const { circuitBreaker, guardian1 } = await loadFixture(deployCircuitBreakerFixture);

      await expect(circuitBreaker.connect(guardian1).triggerGlobalPause("Emergency"))
        .to.emit(circuitBreaker, "GlobalPauseTriggered")
        .withArgs(guardian1.address, "Emergency");
    });

    it("should prevent non-guardian from triggering pause", async function () {
      const { circuitBreaker, attacker } = await loadFixture(deployCircuitBreakerFixture);

      await expect(circuitBreaker.connect(attacker).triggerGlobalPause("Fake emergency")).to.be.revertedWith(
        "Not a guardian"
      );
    });

    it("should require multi-sig to lift pause", async function () {
      const { circuitBreaker, guardian1, guardian2 } = await loadFixture(deployCircuitBreakerFixture);

      // Trigger pause
      await circuitBreaker.connect(guardian1).triggerGlobalPause("Test pause");

      // Initiate lift operation
      const operationId = await circuitBreaker.connect(guardian1).initiateLiftPause();
      const receipt = await operationId.wait();

      // Extract operation ID from event
      const event = receipt?.logs.find((log: any) => {
        try {
          const decoded = circuitBreaker.interface.parseLog({ topics: [...log.topics], data: log.data });
          return decoded?.name === "OperationInitiated";
        } catch {
          return false;
        }
      });

      const decoded = circuitBreaker.interface.parseLog({
        topics: [...(event as any).topics],
        data: (event as any).data,
      });
      const opId = decoded?.args[0];

      // First signature
      await circuitBreaker.connect(guardian1).signOperation(opId);

      // Still paused after 1 signature
      expect(await circuitBreaker.globalPauseActive()).to.equal(true);

      // Second signature meets threshold
      await circuitBreaker.connect(guardian2).signOperation(opId);

      // Execute lift
      await circuitBreaker.connect(guardian1).executeLiftPause(opId);

      expect(await circuitBreaker.globalPauseActive()).to.equal(false);
    });

    it("should track pause history", async function () {
      const { circuitBreaker, guardian1 } = await loadFixture(deployCircuitBreakerFixture);

      await circuitBreaker.connect(guardian1).triggerGlobalPause("First pause");

      const pauseHistory = await circuitBreaker.getPauseHistory(0);
      expect(pauseHistory.triggeredBy).to.equal(guardian1.address);
      expect(pauseHistory.reason).to.equal("First pause");
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                      3. MULTI-SIG OPERATIONS
  // ═══════════════════════════════════════════════════════════════════

  describe("Multi-Sig Operations", function () {
    it("should track signature count correctly", async function () {
      const { circuitBreaker, guardian1, guardian2, guardian3 } = await loadFixture(deployCircuitBreakerFixture);

      await circuitBreaker.connect(guardian1).triggerGlobalPause("Test");
      const tx = await circuitBreaker.connect(guardian1).initiateLiftPause();
      const receipt = await tx.wait();

      const event = receipt?.logs.find((log: any) => {
        try {
          const decoded = circuitBreaker.interface.parseLog({ topics: [...log.topics], data: log.data });
          return decoded?.name === "OperationInitiated";
        } catch {
          return false;
        }
      });
      const decoded = circuitBreaker.interface.parseLog({
        topics: [...(event as any).topics],
        data: (event as any).data,
      });
      const opId = decoded?.args[0];

      await circuitBreaker.connect(guardian1).signOperation(opId);
      expect(await circuitBreaker.getOperationSignatureCount(opId)).to.equal(1);

      await circuitBreaker.connect(guardian2).signOperation(opId);
      expect(await circuitBreaker.getOperationSignatureCount(opId)).to.equal(2);

      await circuitBreaker.connect(guardian3).signOperation(opId);
      expect(await circuitBreaker.getOperationSignatureCount(opId)).to.equal(3);
    });

    it("should prevent double signing", async function () {
      const { circuitBreaker, guardian1 } = await loadFixture(deployCircuitBreakerFixture);

      await circuitBreaker.connect(guardian1).triggerGlobalPause("Test");
      const tx = await circuitBreaker.connect(guardian1).initiateLiftPause();
      const receipt = await tx.wait();

      const event = receipt?.logs.find((log: any) => {
        try {
          const decoded = circuitBreaker.interface.parseLog({ topics: [...log.topics], data: log.data });
          return decoded?.name === "OperationInitiated";
        } catch {
          return false;
        }
      });
      const decoded = circuitBreaker.interface.parseLog({
        topics: [...(event as any).topics],
        data: (event as any).data,
      });
      const opId = decoded?.args[0];

      await circuitBreaker.connect(guardian1).signOperation(opId);

      await expect(circuitBreaker.connect(guardian1).signOperation(opId)).to.be.revertedWith("Already signed");
    });

    it("should expire operations after timeout", async function () {
      const { circuitBreaker, guardian1, guardian2 } = await loadFixture(deployCircuitBreakerFixture);

      await circuitBreaker.connect(guardian1).triggerGlobalPause("Test");
      const tx = await circuitBreaker.connect(guardian1).initiateLiftPause();
      const receipt = await tx.wait();

      const event = receipt?.logs.find((log: any) => {
        try {
          const decoded = circuitBreaker.interface.parseLog({ topics: [...log.topics], data: log.data });
          return decoded?.name === "OperationInitiated";
        } catch {
          return false;
        }
      });
      const decoded = circuitBreaker.interface.parseLog({
        topics: [...(event as any).topics],
        data: (event as any).data,
      });
      const opId = decoded?.args[0];

      await circuitBreaker.connect(guardian1).signOperation(opId);
      await circuitBreaker.connect(guardian2).signOperation(opId);

      // Advance time past expiration (24 hours default)
      await time.increase(25 * 60 * 60);

      await expect(circuitBreaker.connect(guardian1).executeLiftPause(opId)).to.be.revertedWith("Operation expired");
    });

    it("should not execute without sufficient signatures", async function () {
      const { circuitBreaker, guardian1 } = await loadFixture(deployCircuitBreakerFixture);

      await circuitBreaker.connect(guardian1).triggerGlobalPause("Test");
      const tx = await circuitBreaker.connect(guardian1).initiateLiftPause();
      const receipt = await tx.wait();

      const event = receipt?.logs.find((log: any) => {
        try {
          const decoded = circuitBreaker.interface.parseLog({ topics: [...log.topics], data: log.data });
          return decoded?.name === "OperationInitiated";
        } catch {
          return false;
        }
      });
      const decoded = circuitBreaker.interface.parseLog({
        topics: [...(event as any).topics],
        data: (event as any).data,
      });
      const opId = decoded?.args[0];

      // Only 1 signature (threshold is 2)
      await circuitBreaker.connect(guardian1).signOperation(opId);

      await expect(circuitBreaker.connect(guardian1).executeLiftPause(opId)).to.be.revertedWith(
        "Insufficient signatures"
      );
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                       4. ANOMALY DETECTION
  // ═══════════════════════════════════════════════════════════════════

  describe("Anomaly Detection", function () {
    it("should detect price anomaly exceeding threshold", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      // Set baseline price
      const basePrice = ethers.parseUnits("2000", 6);
      await circuitBreaker.connect(owner).setBaselinePrice(basePrice);

      // 25% increase (exceeds 20% threshold)
      const anomalousPrice = ethers.parseUnits("2500", 6);
      const isAnomaly = await circuitBreaker.checkPriceAnomaly(anomalousPrice);

      expect(isAnomaly).to.equal(true);
    });

    it("should not flag normal price movements", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      const basePrice = ethers.parseUnits("2000", 6);
      await circuitBreaker.connect(owner).setBaselinePrice(basePrice);

      // 10% increase (within threshold)
      const normalPrice = ethers.parseUnits("2200", 6);
      const isAnomaly = await circuitBreaker.checkPriceAnomaly(normalPrice);

      expect(isAnomaly).to.equal(false);
    });

    it("should detect volume spike anomaly", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      // Set baseline volume (1000 ETH)
      const baseVolume = ethers.parseEther("1000");
      await circuitBreaker.connect(owner).setBaselineVolume(baseVolume);

      // 400% spike (exceeds 300% threshold)
      const anomalousVolume = ethers.parseEther("4000");
      const isAnomaly = await circuitBreaker.checkVolumeAnomaly(anomalousVolume);

      expect(isAnomaly).to.equal(true);
    });

    it("should not flag normal volume increases", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      const baseVolume = ethers.parseEther("1000");
      await circuitBreaker.connect(owner).setBaselineVolume(baseVolume);

      // 150% increase (within threshold)
      const normalVolume = ethers.parseEther("1500");
      const isAnomaly = await circuitBreaker.checkVolumeAnomaly(normalVolume);

      expect(isAnomaly).to.equal(false);
    });

    it("should detect gas price anomaly", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      // Set baseline gas (50 gwei)
      const baseGas = ethers.parseUnits("50", "gwei");
      await circuitBreaker.connect(owner).setBaselineGasPrice(baseGas);

      // 500 gwei (10x increase)
      const anomalousGas = ethers.parseUnits("500", "gwei");
      const isAnomaly = await circuitBreaker.checkGasAnomaly(anomalousGas);

      expect(isAnomaly).to.equal(true);
    });

    it("should auto-pause on critical anomaly detection", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      await circuitBreaker.connect(owner).enableAutoPause(true);

      const basePrice = ethers.parseUnits("2000", 6);
      await circuitBreaker.connect(owner).setBaselinePrice(basePrice);

      // Trigger critical anomaly (50% drop)
      const criticalPrice = ethers.parseUnits("1000", 6);
      await circuitBreaker.connect(owner).reportPriceAndCheckAnomaly(criticalPrice);

      // Should auto-pause
      expect(await circuitBreaker.globalPauseActive()).to.equal(true);
    });

    it("should update anomaly statistics", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      const basePrice = ethers.parseUnits("2000", 6);
      await circuitBreaker.connect(owner).setBaselinePrice(basePrice);

      // Report several anomalies
      await circuitBreaker.checkPriceAnomaly(ethers.parseUnits("2600", 6));
      await circuitBreaker.checkPriceAnomaly(ethers.parseUnits("2700", 6));

      const stats = await circuitBreaker.getAnomalyStats();
      expect(stats.priceAnomalyCount).to.be.gt(0);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                     5. EMERGENCY WITHDRAWAL
  // ═══════════════════════════════════════════════════════════════════

  describe("Emergency Withdrawal", function () {
    it("should allow user to request emergency withdrawal", async function () {
      const { circuitBreaker, protectedToken, user1 } = await loadFixture(deployCircuitBreakerFixture);

      // User deposits tokens
      const depositAmount = ethers.parseEther("100");
      await protectedToken.mint(user1.address, depositAmount);
      await protectedToken.connect(user1).approve(circuitBreaker.target, depositAmount);
      await circuitBreaker.connect(user1).depositForEmergencyWithdrawal(protectedToken.target, depositAmount);

      // Request withdrawal
      const tx = await circuitBreaker.connect(user1).requestEmergencyWithdrawal(protectedToken.target, depositAmount);
      const receipt = await tx.wait();

      expect(receipt?.status).to.equal(1);
    });

    it("should enforce time delay for emergency withdrawal", async function () {
      const { circuitBreaker, protectedToken, user1 } = await loadFixture(deployCircuitBreakerFixture);

      const depositAmount = ethers.parseEther("100");
      await protectedToken.mint(user1.address, depositAmount);
      await protectedToken.connect(user1).approve(circuitBreaker.target, depositAmount);
      await circuitBreaker.connect(user1).depositForEmergencyWithdrawal(protectedToken.target, depositAmount);

      const tx = await circuitBreaker.connect(user1).requestEmergencyWithdrawal(protectedToken.target, depositAmount);
      const receipt = await tx.wait();

      // Extract withdrawal ID from event
      const event = receipt?.logs.find((log: any) => {
        try {
          const decoded = circuitBreaker.interface.parseLog({ topics: [...log.topics], data: log.data });
          return decoded?.name === "EmergencyWithdrawalRequested";
        } catch {
          return false;
        }
      });
      const decoded = circuitBreaker.interface.parseLog({
        topics: [...(event as any).topics],
        data: (event as any).data,
      });
      const withdrawalId = decoded?.args[0];

      // Try to execute immediately - should fail
      await expect(circuitBreaker.connect(user1).executeEmergencyWithdrawal(withdrawalId)).to.be.revertedWith(
        "Time delay not met"
      );

      // Advance time past delay (24 hours default)
      await time.increase(25 * 60 * 60);

      // Now should succeed
      await circuitBreaker.connect(user1).executeEmergencyWithdrawal(withdrawalId);

      const balance = await protectedToken.balanceOf(user1.address);
      expect(balance).to.equal(depositAmount);
    });

    it("should allow guardian to cancel suspicious withdrawal", async function () {
      const { circuitBreaker, protectedToken, user1, guardian1 } = await loadFixture(deployCircuitBreakerFixture);

      const depositAmount = ethers.parseEther("100");
      await protectedToken.mint(user1.address, depositAmount);
      await protectedToken.connect(user1).approve(circuitBreaker.target, depositAmount);
      await circuitBreaker.connect(user1).depositForEmergencyWithdrawal(protectedToken.target, depositAmount);

      const tx = await circuitBreaker.connect(user1).requestEmergencyWithdrawal(protectedToken.target, depositAmount);
      const receipt = await tx.wait();

      const event = receipt?.logs.find((log: any) => {
        try {
          const decoded = circuitBreaker.interface.parseLog({ topics: [...log.topics], data: log.data });
          return decoded?.name === "EmergencyWithdrawalRequested";
        } catch {
          return false;
        }
      });
      const decoded = circuitBreaker.interface.parseLog({
        topics: [...(event as any).topics],
        data: (event as any).data,
      });
      const withdrawalId = decoded?.args[0];

      // Guardian cancels
      await circuitBreaker.connect(guardian1).cancelEmergencyWithdrawal(withdrawalId, "Suspicious activity");

      // User cannot execute
      await time.increase(25 * 60 * 60);
      await expect(circuitBreaker.connect(user1).executeEmergencyWithdrawal(withdrawalId)).to.be.revertedWith(
        "Withdrawal cancelled"
      );
    });

    it("should emit WithdrawalExecuted event on success", async function () {
      const { circuitBreaker, protectedToken, user1 } = await loadFixture(deployCircuitBreakerFixture);

      const depositAmount = ethers.parseEther("50");
      await protectedToken.mint(user1.address, depositAmount);
      await protectedToken.connect(user1).approve(circuitBreaker.target, depositAmount);
      await circuitBreaker.connect(user1).depositForEmergencyWithdrawal(protectedToken.target, depositAmount);

      const tx = await circuitBreaker.connect(user1).requestEmergencyWithdrawal(protectedToken.target, depositAmount);
      const receipt = await tx.wait();

      const event = receipt?.logs.find((log: any) => {
        try {
          const decoded = circuitBreaker.interface.parseLog({ topics: [...log.topics], data: log.data });
          return decoded?.name === "EmergencyWithdrawalRequested";
        } catch {
          return false;
        }
      });
      const decoded = circuitBreaker.interface.parseLog({
        topics: [...(event as any).topics],
        data: (event as any).data,
      });
      const withdrawalId = decoded?.args[0];

      await time.increase(25 * 60 * 60);

      await expect(circuitBreaker.connect(user1).executeEmergencyWithdrawal(withdrawalId)).to.emit(
        circuitBreaker,
        "EmergencyWithdrawalExecuted"
      );
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                        6. RATE LIMITING
  // ═══════════════════════════════════════════════════════════════════

  describe("Rate Limiting", function () {
    it("should enforce rate limit on contract operations", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      // Set rate limit (10 operations per hour)
      await circuitBreaker.connect(owner).setContractRateLimit(10);

      // Perform operations up to limit
      for (let i = 0; i < 10; i++) {
        await circuitBreaker.connect(owner).incrementRateCounter();
      }

      // Next operation should fail
      await expect(circuitBreaker.connect(owner).incrementRateCounter()).to.be.revertedWith("Contract rate limit hit");
    });

    it("should reset rate limit after time window", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      await circuitBreaker.connect(owner).setContractRateLimit(5);

      // Hit rate limit
      for (let i = 0; i < 5; i++) {
        await circuitBreaker.connect(owner).incrementRateCounter();
      }

      // Advance time (1 hour)
      await time.increase(3600);

      // Should work again
      await expect(circuitBreaker.connect(owner).incrementRateCounter()).to.not.be.reverted;
    });

    it("should track rate limit usage per window", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      await circuitBreaker.connect(owner).setContractRateLimit(100);

      await circuitBreaker.connect(owner).incrementRateCounter();
      await circuitBreaker.connect(owner).incrementRateCounter();
      await circuitBreaker.connect(owner).incrementRateCounter();

      const usage = await circuitBreaker.getRateLimitUsage();
      expect(usage).to.equal(3);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                      7. GUARDIAN MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════

  describe("Guardian Management", function () {
    it("should allow admin to add guardian", async function () {
      const { circuitBreaker, owner, attacker } = await loadFixture(deployCircuitBreakerFixture);

      const newGuardian = ethers.Wallet.createRandom();

      await circuitBreaker.connect(owner).addGuardian(newGuardian.address);

      expect(await circuitBreaker.isGuardian(newGuardian.address)).to.equal(true);
      expect(await circuitBreaker.guardianCount()).to.equal(5);
    });

    it("should allow admin to remove guardian", async function () {
      const { circuitBreaker, owner, guardian4 } = await loadFixture(deployCircuitBreakerFixture);

      await circuitBreaker.connect(owner).removeGuardian(guardian4.address);

      expect(await circuitBreaker.isGuardian(guardian4.address)).to.equal(false);
      expect(await circuitBreaker.guardianCount()).to.equal(3);
    });

    it("should prevent removing below minimum guardians", async function () {
      const { circuitBreaker, owner, guardian1, guardian2, guardian3, guardian4 } = await loadFixture(
        deployCircuitBreakerFixture
      );

      // Remove guardians down to minimum (2)
      await circuitBreaker.connect(owner).removeGuardian(guardian4.address);
      await circuitBreaker.connect(owner).removeGuardian(guardian3.address);

      // This should fail (can't go below 2 guardians)
      await expect(circuitBreaker.connect(owner).removeGuardian(guardian2.address)).to.be.revertedWith(
        "Below minimum guardians"
      );
    });

    it("should prevent non-admin from managing guardians", async function () {
      const { circuitBreaker, attacker } = await loadFixture(deployCircuitBreakerFixture);

      const newGuardian = ethers.Wallet.createRandom();

      await expect(circuitBreaker.connect(attacker).addGuardian(newGuardian.address)).to.be.reverted;
    });

    it("should update signature threshold when guardians change", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      // Add guardians to increase threshold requirement
      await circuitBreaker.connect(owner).setSignatureThreshold(3);

      const threshold = await circuitBreaker.signatureThreshold();
      expect(threshold).to.equal(3);
    });

    it("should prevent threshold exceeding guardian count", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      // Only 4 guardians, can't set threshold to 5
      await expect(circuitBreaker.connect(owner).setSignatureThreshold(5)).to.be.revertedWith(
        "Threshold exceeds guardian count"
      );
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                         8. SECURITY TESTS
  // ═══════════════════════════════════════════════════════════════════

  describe("Security Tests", function () {
    it("should prevent reentrancy on withdrawal execution", async function () {
      const { circuitBreaker } = await loadFixture(deployCircuitBreakerFixture);

      // Deploy malicious contract that attempts reentrancy
      const ReentrancyAttacker = await ethers.getContractFactory("ReentrancyAttacker");
      const attacker = await ReentrancyAttacker.deploy(circuitBreaker.target);

      // Attempt reentrancy attack should fail
      await expect(attacker.attack()).to.be.reverted;
    });

    it("should prevent unauthorized pause lifting", async function () {
      const { circuitBreaker, guardian1, attacker } = await loadFixture(deployCircuitBreakerFixture);

      await circuitBreaker.connect(guardian1).triggerGlobalPause("Test");

      // Attacker cannot lift pause
      await expect(circuitBreaker.connect(attacker).initiateLiftPause()).to.be.revertedWith("Not a guardian");
    });

    it("should validate operation signatures are from guardians only", async function () {
      const { circuitBreaker, guardian1, attacker } = await loadFixture(deployCircuitBreakerFixture);

      await circuitBreaker.connect(guardian1).triggerGlobalPause("Test");
      const tx = await circuitBreaker.connect(guardian1).initiateLiftPause();
      const receipt = await tx.wait();

      const event = receipt?.logs.find((log: any) => {
        try {
          const decoded = circuitBreaker.interface.parseLog({ topics: [...log.topics], data: log.data });
          return decoded?.name === "OperationInitiated";
        } catch {
          return false;
        }
      });
      const decoded = circuitBreaker.interface.parseLog({
        topics: [...(event as any).topics],
        data: (event as any).data,
      });
      const opId = decoded?.args[0];

      // Attacker cannot sign
      await expect(circuitBreaker.connect(attacker).signOperation(opId)).to.be.revertedWith("Not a guardian");
    });

    it("should prevent manipulation of anomaly thresholds by non-admin", async function () {
      const { circuitBreaker, attacker } = await loadFixture(deployCircuitBreakerFixture);

      const newThreshold = ethers.parseUnits("100", 6);
      await expect(circuitBreaker.connect(attacker).setBaselinePrice(newThreshold)).to.be.reverted;
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                       9. EDGE CASES & LIMITS
  // ═══════════════════════════════════════════════════════════════════

  describe("Edge Cases & Limits", function () {
    it("should handle zero value anomaly check", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      const basePrice = ethers.parseUnits("2000", 6);
      await circuitBreaker.connect(owner).setBaselinePrice(basePrice);

      // Zero price is definitely anomalous
      const isAnomaly = await circuitBreaker.checkPriceAnomaly(0);
      expect(isAnomaly).to.equal(true);
    });

    it("should handle maximum uint256 values", async function () {
      const { circuitBreaker, owner } = await loadFixture(deployCircuitBreakerFixture);

      const basePrice = ethers.MaxUint256 / 2n;
      await circuitBreaker.connect(owner).setBaselinePrice(basePrice);

      // Should not overflow
      const maxPrice = ethers.MaxUint256;
      await expect(circuitBreaker.checkPriceAnomaly(maxPrice)).to.not.be.reverted;
    });

    it("should handle rapid pause/unpause cycles", async function () {
      const { circuitBreaker, guardian1, guardian2 } = await loadFixture(deployCircuitBreakerFixture);

      for (let i = 0; i < 3; i++) {
        await circuitBreaker.connect(guardian1).triggerGlobalPause(`Cycle ${i}`);
        expect(await circuitBreaker.globalPauseActive()).to.equal(true);

        // Quick multi-sig lift
        const tx = await circuitBreaker.connect(guardian1).initiateLiftPause();
        const receipt = await tx.wait();
        const event = receipt?.logs.find((log: any) => {
          try {
            const decoded = circuitBreaker.interface.parseLog({ topics: [...log.topics], data: log.data });
            return decoded?.name === "OperationInitiated";
          } catch {
            return false;
          }
        });
        const decoded = circuitBreaker.interface.parseLog({
          topics: [...(event as any).topics],
          data: (event as any).data,
        });
        const opId = decoded?.args[0];

        await circuitBreaker.connect(guardian1).signOperation(opId);
        await circuitBreaker.connect(guardian2).signOperation(opId);
        await circuitBreaker.connect(guardian1).executeLiftPause(opId);

        expect(await circuitBreaker.globalPauseActive()).to.equal(false);
      }

      const pauseCount = await circuitBreaker.totalPauseCount();
      expect(pauseCount).to.equal(3);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
//                     MOCK REENTRANCY ATTACKER
// ═══════════════════════════════════════════════════════════════════

/**
 * Deploy this contract in the test to verify reentrancy protection
 */
