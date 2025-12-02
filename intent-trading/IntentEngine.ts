import { EventEmitter } from 'events';
import * as crypto from 'crypto';

/**
 * INTENT-BASED TRADING ENGINE
 *
 * HYPOTHESIS: Intent-based execution where users specify outcomes rather than
 * exact paths will achieve 15% better execution through solver competition
 * while simplifying the user experience.
 *
 * SUCCESS METRICS:
 * - Price improvement >15% vs direct execution
 * - Intent fulfillment rate >98%
 * - Solver competition (>10 active solvers)
 * - Gas savings >30% through batching
 * - MEV protection via sealed auctions
 *
 * SECURITY CONSIDERATIONS:
 * - Solver reputation and bonding requirements
 * - Intent signature verification
 * - Slippage protection for users
 * - Fair solver selection to prevent collusion
 * - Timeout and expiration handling
 */

// Intent types
enum IntentType {
  SWAP = 'swap',
  LIMIT_ORDER = 'limit_order',
  TWA_ORDER = 'twa_order', // Time-weighted average
  RANGE_ORDER = 'range_order',
  CONDITIONAL = 'conditional',
  BATCH_SWAP = 'batch_swap'
}

// Intent status
enum IntentStatus {
  PENDING = 'pending',
  AUCTION = 'auction',
  EXECUTING = 'executing',
  FULFILLED = 'fulfilled',
  PARTIALLY_FILLED = 'partially_filled',
  EXPIRED = 'expired',
  CANCELLED = 'cancelled',
  FAILED = 'failed'
}

// Solver solution
interface SolverSolution {
  solverId: string;
  intentId: string;
  executionPath: ExecutionStep[];
  expectedOutput: bigint;
  guaranteedOutput: bigint; // After slippage
  gasEstimate: bigint;
  validUntil: Date;
  bondAmount: bigint;
  score: number;
  simulationResult?: SimulationResult;
}

// Execution step
interface ExecutionStep {
  protocol: string;
  action: string;
  tokenIn: string;
  tokenOut: string;
  amountIn: bigint;
  expectedAmountOut: bigint;
  poolAddress?: string;
  data: string;
}

// Simulation result
interface SimulationResult {
  success: boolean;
  finalOutput: bigint;
  actualGasUsed: bigint;
  priceImpact: number;
  revertReason?: string;
}

// User intent
interface UserIntent {
  id: string;
  creator: string;
  type: IntentType;
  inputToken: string;
  outputToken: string;
  inputAmount: bigint;
  minOutputAmount: bigint;
  maxSlippage: number; // basis points
  deadline: Date;
  conditions?: IntentCondition[];
  preferences?: ExecutionPreferences;
  signature: string;
  nonce: bigint;
  status: IntentStatus;
  createdAt: Date;
  fulfilledAt?: Date;
  winningSolution?: SolverSolution;
  actualOutput?: bigint;
}

// Intent conditions
interface IntentCondition {
  type: 'price_above' | 'price_below' | 'time_after' | 'oracle_trigger' | 'custom';
  parameter: string;
  value: string;
  satisfied: boolean;
}

// Execution preferences
interface ExecutionPreferences {
  preferredProtocols?: string[];
  excludedProtocols?: string[];
  maxGasPrice?: bigint;
  urgency: 'low' | 'medium' | 'high';
  allowPartialFill: boolean;
  privateExecution: boolean;
}

// Solver info
interface Solver {
  id: string;
  address: string;
  bondedAmount: bigint;
  reputation: number;
  successfulSolutions: number;
  failedSolutions: number;
  totalVolume: bigint;
  lastActive: Date;
  active: boolean;
  specializations: string[];
}

// Auction for intent fulfillment
interface IntentAuction {
  intentId: string;
  startTime: Date;
  endTime: Date;
  solutions: Map<string, SolverSolution>;
  winningSolverId?: string;
  status: 'open' | 'evaluating' | 'closed';
}

// Configuration
interface IntentEngineConfig {
  minSolverBond: bigint;
  auctionDuration: number; // ms
  maxSolutionsPerAuction: number;
  solutionValidityPeriod: number; // ms
  maxSlippageBasisPoints: number;
  minReputationScore: number;
  simulationGasLimit: bigint;
}

/**
 * Solver Manager - handles solver registration and reputation
 */
class SolverManager extends EventEmitter {
  private solvers: Map<string, Solver> = new Map();
  private minBond: bigint;
  private minReputation: number;

  constructor(minBond: bigint, minReputation: number) {
    super();
    this.minBond = minBond;
    this.minReputation = minReputation;
  }

  /**
   * Register a new solver
   */
  registerSolver(
    address: string,
    bondAmount: bigint,
    specializations: string[]
  ): Solver {
    if (bondAmount < this.minBond) {
      throw new Error(`Bond amount below minimum ${this.minBond}`);
    }

    const solver: Solver = {
      id: crypto.randomBytes(16).toString('hex'),
      address,
      bondedAmount: bondAmount,
      reputation: 100, // Start with neutral reputation
      successfulSolutions: 0,
      failedSolutions: 0,
      totalVolume: 0n,
      lastActive: new Date(),
      active: true,
      specializations
    };

    this.solvers.set(solver.id, solver);
    this.emit('solverRegistered', solver);

    return solver;
  }

  /**
   * Update solver reputation after fulfillment
   */
  updateReputation(solverId: string, success: boolean, volume: bigint): void {
    const solver = this.solvers.get(solverId);
    if (!solver) return;

    if (success) {
      solver.successfulSolutions++;
      // Reputation boost based on volume
      const volumeBoost = Number(volume / 1000000000000000000n); // per ETH
      solver.reputation = Math.min(200, solver.reputation + 1 + volumeBoost * 0.01);
    } else {
      solver.failedSolutions++;
      solver.reputation = Math.max(0, solver.reputation - 10);
    }

    solver.totalVolume += volume;
    solver.lastActive = new Date();

    // Deactivate if reputation too low
    if (solver.reputation < this.minReputation) {
      solver.active = false;
      this.emit('solverDeactivated', { solverId, reason: 'low_reputation' });
    }

    this.emit('reputationUpdated', { solverId, newReputation: solver.reputation });
  }

  /**
   * Slash solver bond for malicious behavior
   */
  slashBond(solverId: string, amount: bigint, reason: string): void {
    const solver = this.solvers.get(solverId);
    if (!solver) return;

    const slashAmount = amount < solver.bondedAmount ? amount : solver.bondedAmount;
    solver.bondedAmount -= slashAmount;
    solver.reputation = Math.max(0, solver.reputation - 25);

    if (solver.bondedAmount < this.minBond) {
      solver.active = false;
    }

    this.emit('bondSlashed', { solverId, amount: slashAmount, reason });
  }

  /**
   * Get active solvers
   */
  getActiveSolvers(): Solver[] {
    return Array.from(this.solvers.values()).filter(s => s.active);
  }

  /**
   * Get solver by ID
   */
  getSolver(solverId: string): Solver | undefined {
    return this.solvers.get(solverId);
  }

  /**
   * Get solver statistics
   */
  getStats(): {
    totalSolvers: number;
    activeSolvers: number;
    totalBonded: bigint;
    avgReputation: number;
  } {
    const solvers = Array.from(this.solvers.values());
    const active = solvers.filter(s => s.active);

    const totalBonded = solvers.reduce((sum, s) => sum + s.bondedAmount, 0n);
    const avgReputation = active.length > 0
      ? active.reduce((sum, s) => sum + s.reputation, 0) / active.length
      : 0;

    return {
      totalSolvers: solvers.length,
      activeSolvers: active.length,
      totalBonded,
      avgReputation
    };
  }
}

/**
 * Intent Auction Manager
 */
class AuctionManager extends EventEmitter {
  private auctions: Map<string, IntentAuction> = new Map();
  private auctionDuration: number;
  private maxSolutions: number;

  constructor(auctionDuration: number, maxSolutions: number) {
    super();
    this.auctionDuration = auctionDuration;
    this.maxSolutions = maxSolutions;
  }

  /**
   * Start auction for an intent
   */
  startAuction(intentId: string): IntentAuction {
    const auction: IntentAuction = {
      intentId,
      startTime: new Date(),
      endTime: new Date(Date.now() + this.auctionDuration),
      solutions: new Map(),
      status: 'open'
    };

    this.auctions.set(intentId, auction);
    this.emit('auctionStarted', { intentId, endTime: auction.endTime });

    // Schedule auction closure
    setTimeout(() => {
      this.closeAuction(intentId);
    }, this.auctionDuration);

    return auction;
  }

  /**
   * Submit solution to auction
   */
  submitSolution(solution: SolverSolution): boolean {
    const auction = this.auctions.get(solution.intentId);

    if (!auction) {
      throw new Error('Auction not found');
    }

    if (auction.status !== 'open') {
      throw new Error('Auction not open');
    }

    if (auction.solutions.size >= this.maxSolutions) {
      // Check if this solution is better than worst one
      const worst = this.findWorstSolution(auction);
      if (solution.score <= worst.score) {
        return false;
      }
      auction.solutions.delete(worst.solverId);
    }

    auction.solutions.set(solution.solverId, solution);
    this.emit('solutionSubmitted', { intentId: solution.intentId, solverId: solution.solverId });

    return true;
  }

  /**
   * Close auction and select winner
   */
  closeAuction(intentId: string): SolverSolution | null {
    const auction = this.auctions.get(intentId);
    if (!auction || auction.status !== 'open') return null;

    auction.status = 'evaluating';

    if (auction.solutions.size === 0) {
      auction.status = 'closed';
      this.emit('auctionClosed', { intentId, winner: null, reason: 'no_solutions' });
      return null;
    }

    // Select best solution
    const winner = this.selectWinner(auction);
    auction.winningSolverId = winner.solverId;
    auction.status = 'closed';

    this.emit('auctionClosed', { intentId, winner });

    return winner;
  }

  /**
   * Select winning solution based on multiple criteria
   */
  private selectWinner(auction: IntentAuction): SolverSolution {
    const solutions = Array.from(auction.solutions.values());

    // Score each solution
    const scoredSolutions = solutions.map(solution => {
      let score = 0;

      // 50% weight: guaranteed output (higher is better)
      const outputScore = Number(solution.guaranteedOutput) / 1e18 * 500;

      // 30% weight: gas efficiency (lower gas is better)
      const gasScore = (1 / Number(solution.gasEstimate / 1000000n)) * 300;

      // 20% weight: solution quality/complexity
      const qualityScore = solution.score * 2;

      score = outputScore + gasScore + qualityScore;

      return { solution, totalScore: score };
    });

    // Sort by score and return best
    scoredSolutions.sort((a, b) => b.totalScore - a.totalScore);
    return scoredSolutions[0].solution;
  }

  private findWorstSolution(auction: IntentAuction): SolverSolution {
    let worst: SolverSolution | null = null;
    let worstScore = Infinity;

    for (const solution of auction.solutions.values()) {
      if (solution.score < worstScore) {
        worstScore = solution.score;
        worst = solution;
      }
    }

    return worst!;
  }

  /**
   * Get auction status
   */
  getAuction(intentId: string): IntentAuction | undefined {
    return this.auctions.get(intentId);
  }
}

/**
 * Intent Validator
 */
class IntentValidator {
  private maxSlippage: number;

  constructor(maxSlippage: number) {
    this.maxSlippage = maxSlippage;
  }

  /**
   * Validate intent structure and parameters
   */
  validateIntent(intent: UserIntent): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check basic fields
    if (!intent.creator) errors.push('Missing creator');
    if (!intent.inputToken) errors.push('Missing input token');
    if (!intent.outputToken) errors.push('Missing output token');
    if (intent.inputAmount <= 0n) errors.push('Invalid input amount');
    if (intent.minOutputAmount <= 0n) errors.push('Invalid min output amount');

    // Check slippage
    if (intent.maxSlippage > this.maxSlippage) {
      errors.push(`Slippage ${intent.maxSlippage} exceeds maximum ${this.maxSlippage}`);
    }

    // Check deadline
    if (intent.deadline <= new Date()) {
      errors.push('Intent deadline has passed');
    }

    // Check signature (simplified)
    if (!intent.signature || intent.signature.length < 64) {
      errors.push('Invalid signature');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Verify intent signature
   */
  verifySignature(intent: UserIntent): boolean {
    // In production: verify EIP-712 signature
    const message = this.encodeIntent(intent);
    const hash = crypto.createHash('sha256').update(message).digest('hex');

    // Simplified verification (would use actual crypto in production)
    return intent.signature.length > 0 && hash.length > 0;
  }

  private encodeIntent(intent: UserIntent): string {
    return JSON.stringify({
      creator: intent.creator,
      type: intent.type,
      inputToken: intent.inputToken,
      outputToken: intent.outputToken,
      inputAmount: intent.inputAmount.toString(),
      minOutputAmount: intent.minOutputAmount.toString(),
      maxSlippage: intent.maxSlippage,
      deadline: intent.deadline.toISOString(),
      nonce: intent.nonce.toString()
    });
  }
}

/**
 * Solution Simulator
 */
class SolutionSimulator {
  private gasLimit: bigint;

  constructor(gasLimit: bigint) {
    this.gasLimit = gasLimit;
  }

  /**
   * Simulate solution execution
   */
  async simulate(
    intent: UserIntent,
    solution: SolverSolution
  ): Promise<SimulationResult> {
    // In production: use actual blockchain simulation (tenderly, local fork, etc.)

    try {
      // Simulate each step
      let currentAmount = intent.inputAmount;
      let totalGas = 0n;
      let totalPriceImpact = 0;

      for (const step of solution.executionPath) {
        // Simulate step
        const stepResult = await this.simulateStep(step, currentAmount);

        if (!stepResult.success) {
          return {
            success: false,
            finalOutput: 0n,
            actualGasUsed: totalGas,
            priceImpact: totalPriceImpact,
            revertReason: stepResult.reason
          };
        }

        currentAmount = stepResult.outputAmount;
        totalGas += stepResult.gasUsed;
        totalPriceImpact += stepResult.priceImpact;
      }

      // Verify output meets minimum
      const success = currentAmount >= intent.minOutputAmount;

      return {
        success,
        finalOutput: currentAmount,
        actualGasUsed: totalGas,
        priceImpact: totalPriceImpact,
        revertReason: success ? undefined : 'Output below minimum'
      };
    } catch (error) {
      return {
        success: false,
        finalOutput: 0n,
        actualGasUsed: 0n,
        priceImpact: 0,
        revertReason: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  private async simulateStep(
    step: ExecutionStep,
    inputAmount: bigint
  ): Promise<{
    success: boolean;
    outputAmount: bigint;
    gasUsed: bigint;
    priceImpact: number;
    reason?: string;
  }> {
    // Simplified simulation
    // In production: actual EVM simulation

    // Simulate slippage based on pool liquidity (mock)
    const slippage = Math.random() * 0.02; // 0-2%
    const outputAmount = step.expectedAmountOut * BigInt(Math.floor((1 - slippage) * 10000)) / 10000n;

    const gasUsed = 100000n; // Approximate gas per swap

    return {
      success: true,
      outputAmount,
      gasUsed,
      priceImpact: slippage * 100 // Convert to percentage
    };
  }
}

/**
 * Main Intent-Based Trading Engine
 */
export class IntentEngine extends EventEmitter {
  private config: IntentEngineConfig;
  private solverManager: SolverManager;
  private auctionManager: AuctionManager;
  private validator: IntentValidator;
  private simulator: SolutionSimulator;
  private intents: Map<string, UserIntent> = new Map();
  private intentHistory: UserIntent[] = [];

  constructor(config: IntentEngineConfig) {
    super();
    this.config = config;

    this.solverManager = new SolverManager(config.minSolverBond, config.minReputationScore);
    this.auctionManager = new AuctionManager(config.auctionDuration, config.maxSolutionsPerAuction);
    this.validator = new IntentValidator(config.maxSlippageBasisPoints);
    this.simulator = new SolutionSimulator(config.simulationGasLimit);

    // Wire up events
    this.setupEventHandlers();
  }

  /**
   * Submit a new intent
   */
  async submitIntent(intentData: Omit<UserIntent, 'id' | 'status' | 'createdAt'>): Promise<string> {
    // Create intent with ID
    const intent: UserIntent = {
      ...intentData,
      id: crypto.randomBytes(16).toString('hex'),
      status: IntentStatus.PENDING,
      createdAt: new Date()
    };

    // Validate intent
    const validation = this.validator.validateIntent(intent);
    if (!validation.valid) {
      throw new Error(`Invalid intent: ${validation.errors.join(', ')}`);
    }

    // Verify signature
    if (!this.validator.verifySignature(intent)) {
      throw new Error('Invalid signature');
    }

    // Check conditions if any
    if (intent.conditions && intent.conditions.length > 0) {
      const conditionsMet = await this.checkConditions(intent.conditions);
      if (!conditionsMet) {
        // Store for later evaluation
        this.intents.set(intent.id, intent);
        this.emit('intentQueued', intent);
        return intent.id;
      }
    }

    // Store intent
    this.intents.set(intent.id, intent);

    // Start auction immediately if no conditions
    await this.startIntentAuction(intent);

    this.emit('intentSubmitted', intent);
    return intent.id;
  }

  /**
   * Register a solver
   */
  registerSolver(address: string, bondAmount: bigint, specializations: string[]): Solver {
    return this.solverManager.registerSolver(address, bondAmount, specializations);
  }

  /**
   * Submit solver solution
   */
  async submitSolution(
    solverId: string,
    intentId: string,
    executionPath: ExecutionStep[],
    guaranteedOutput: bigint,
    gasEstimate: bigint
  ): Promise<boolean> {
    const intent = this.intents.get(intentId);
    if (!intent) {
      throw new Error('Intent not found');
    }

    const solver = this.solverManager.getSolver(solverId);
    if (!solver || !solver.active) {
      throw new Error('Invalid or inactive solver');
    }

    // Calculate expected output
    const expectedOutput = executionPath.reduce(
      (_, step) => step.expectedAmountOut,
      0n
    );

    // Validate solution meets minimum output
    if (guaranteedOutput < intent.minOutputAmount) {
      throw new Error('Solution does not meet minimum output');
    }

    // Calculate solution score
    const score = this.calculateSolutionScore(solver, guaranteedOutput, gasEstimate);

    const solution: SolverSolution = {
      solverId,
      intentId,
      executionPath,
      expectedOutput,
      guaranteedOutput,
      gasEstimate,
      validUntil: new Date(Date.now() + this.config.solutionValidityPeriod),
      bondAmount: solver.bondedAmount,
      score
    };

    // Simulate solution
    solution.simulationResult = await this.simulator.simulate(intent, solution);

    if (!solution.simulationResult.success) {
      this.emit('solutionRejected', {
        intentId,
        solverId,
        reason: solution.simulationResult.revertReason
      });
      return false;
    }

    // Submit to auction
    const accepted = this.auctionManager.submitSolution(solution);

    if (accepted) {
      this.emit('solutionAccepted', { intentId, solverId, score });
    }

    return accepted;
  }

  /**
   * Execute winning solution
   */
  async executeIntent(intentId: string): Promise<boolean> {
    const intent = this.intents.get(intentId);
    if (!intent) {
      throw new Error('Intent not found');
    }

    const auction = this.auctionManager.getAuction(intentId);
    if (!auction || auction.status !== 'closed' || !auction.winningSolverId) {
      throw new Error('No winning solution');
    }

    const winningSolution = auction.solutions.get(auction.winningSolverId);
    if (!winningSolution) {
      throw new Error('Winning solution not found');
    }

    intent.status = IntentStatus.EXECUTING;

    try {
      // In production: actually execute on-chain
      // Here we simulate execution

      const finalSimulation = await this.simulator.simulate(intent, winningSolution);

      if (!finalSimulation.success) {
        intent.status = IntentStatus.FAILED;
        this.solverManager.slashBond(
          winningSolution.solverId,
          winningSolution.bondAmount / 10n,
          'Execution failed'
        );
        this.emit('intentFailed', { intentId, reason: finalSimulation.revertReason });
        return false;
      }

      // Verify output meets guarantee
      if (finalSimulation.finalOutput < winningSolution.guaranteedOutput) {
        // Solver must compensate
        const shortfall = winningSolution.guaranteedOutput - finalSimulation.finalOutput;
        this.emit('solverCompensation', {
          intentId,
          solverId: winningSolution.solverId,
          shortfall
        });
      }

      intent.status = IntentStatus.FULFILLED;
      intent.fulfilledAt = new Date();
      intent.winningSolution = winningSolution;
      intent.actualOutput = finalSimulation.finalOutput;

      // Update solver reputation
      this.solverManager.updateReputation(
        winningSolution.solverId,
        true,
        intent.inputAmount
      );

      this.intentHistory.push(intent);
      this.intents.delete(intentId);

      this.emit('intentFulfilled', {
        intentId,
        solverId: winningSolution.solverId,
        actualOutput: finalSimulation.finalOutput
      });

      return true;
    } catch (error) {
      intent.status = IntentStatus.FAILED;
      this.emit('intentFailed', { intentId, error });
      return false;
    }
  }

  /**
   * Cancel an intent
   */
  cancelIntent(intentId: string, userAddress: string): boolean {
    const intent = this.intents.get(intentId);
    if (!intent) return false;

    if (intent.creator !== userAddress) {
      throw new Error('Not intent creator');
    }

    if (intent.status !== IntentStatus.PENDING && intent.status !== IntentStatus.AUCTION) {
      throw new Error('Cannot cancel intent in current status');
    }

    intent.status = IntentStatus.CANCELLED;
    this.intents.delete(intentId);

    this.emit('intentCancelled', { intentId });
    return true;
  }

  /**
   * Get intent statistics
   */
  getStatistics(): {
    totalIntents: number;
    pendingIntents: number;
    fulfilledIntents: number;
    avgPriceImprovement: number;
    solverStats: any;
  } {
    const pending = Array.from(this.intents.values()).filter(
      i => i.status === IntentStatus.PENDING || i.status === IntentStatus.AUCTION
    );

    const fulfilled = this.intentHistory.filter(i => i.status === IntentStatus.FULFILLED);

    // Calculate average price improvement
    let totalImprovement = 0;
    for (const intent of fulfilled) {
      if (intent.actualOutput && intent.minOutputAmount > 0n) {
        const improvement =
          Number((intent.actualOutput - intent.minOutputAmount) * 10000n / intent.minOutputAmount);
        totalImprovement += improvement;
      }
    }

    const avgImprovement = fulfilled.length > 0 ? totalImprovement / fulfilled.length : 0;

    return {
      totalIntents: this.intents.size + this.intentHistory.length,
      pendingIntents: pending.length,
      fulfilledIntents: fulfilled.length,
      avgPriceImprovement: avgImprovement / 100, // Convert to percentage
      solverStats: this.solverManager.getStats()
    };
  }

  /**
   * Get intent by ID
   */
  getIntent(intentId: string): UserIntent | undefined {
    return this.intents.get(intentId);
  }

  private async startIntentAuction(intent: UserIntent): Promise<void> {
    intent.status = IntentStatus.AUCTION;
    const auction = this.auctionManager.startAuction(intent.id);

    this.emit('auctionStarted', { intentId: intent.id, endTime: auction.endTime });
  }

  private async checkConditions(conditions: IntentCondition[]): Promise<boolean> {
    // In production: check actual on-chain conditions
    for (const condition of conditions) {
      // Simplified condition checking
      condition.satisfied = true; // Would actually evaluate
      if (!condition.satisfied) return false;
    }
    return true;
  }

  private calculateSolutionScore(
    solver: Solver,
    guaranteedOutput: bigint,
    gasEstimate: bigint
  ): number {
    // Score based on:
    // - Solver reputation (30%)
    // - Output amount (50%)
    // - Gas efficiency (20%)

    const reputationScore = solver.reputation / 200; // 0-1 scale
    const outputScore = Number(guaranteedOutput / 1000000000000000000n) / 1000; // Normalize
    const gasScore = 1 / (Number(gasEstimate / 100000n) + 1); // Lower is better

    return reputationScore * 30 + outputScore * 50 + gasScore * 20;
  }

  private setupEventHandlers(): void {
    this.auctionManager.on('auctionClosed', async ({ intentId, winner }) => {
      if (winner) {
        // Auto-execute winning solution
        await this.executeIntent(intentId);
      } else {
        const intent = this.intents.get(intentId);
        if (intent) {
          intent.status = IntentStatus.FAILED;
          this.emit('intentFailed', { intentId, reason: 'No valid solutions' });
        }
      }
    });

    this.solverManager.on('solverDeactivated', ({ solverId }) => {
      this.emit('solverDeactivated', solverId);
    });
  }
}

// Export types
export {
  IntentType,
  IntentStatus,
  UserIntent,
  SolverSolution,
  ExecutionStep,
  Solver,
  IntentCondition,
  ExecutionPreferences,
  SolverManager,
  AuctionManager
};

// Default configuration
export const defaultIntentEngineConfig: IntentEngineConfig = {
  minSolverBond: 100000000000000000000n, // 100 tokens
  auctionDuration: 30000, // 30 seconds
  maxSolutionsPerAuction: 10,
  solutionValidityPeriod: 60000, // 1 minute
  maxSlippageBasisPoints: 1000, // 10%
  minReputationScore: 50,
  simulationGasLimit: 3000000n
};
