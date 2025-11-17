import { EventEmitter } from 'events';
import * as crypto from 'crypto';

/**
 * GAS OPTIMIZATION ENGINE WITH EIP-1559 SUPPORT
 *
 * HYPOTHESIS: Machine learning-based gas price prediction combined with
 * transaction batching and nonce management will reduce gas costs by >30%
 * while maintaining >95% transaction success rate.
 *
 * SUCCESS METRICS:
 * - Gas cost reduction >30% vs naive estimation
 * - Transaction success rate >95%
 * - Price prediction accuracy within 10%
 * - Latency overhead <5ms
 * - Support for priority transactions with guaranteed inclusion
 *
 * SECURITY CONSIDERATIONS:
 * - Nonce management to prevent double-spend
 * - Transaction replay protection
 * - Mempool monitoring for front-running
 * - Safe cancellation and replacement strategies
 */

// EIP-1559 Fee Structure
interface EIP1559FeeEstimate {
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  baseFeePerGas: bigint;
  estimatedGasUsed: bigint;
  totalMaxCost: bigint;
  confidence: number; // 0-100
  strategy: FeeStrategy;
}

// Fee strategies
enum FeeStrategy {
  SLOW = 'slow',           // Next 10 blocks
  STANDARD = 'standard',   // Next 3 blocks
  FAST = 'fast',           // Next block
  INSTANT = 'instant',     // Current block (high priority)
  CUSTOM = 'custom'
}

// Transaction priority
enum TransactionPriority {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

// Block fee history
interface BlockFeeHistory {
  blockNumber: bigint;
  baseFeePerGas: bigint;
  gasUsed: bigint;
  gasLimit: bigint;
  timestamp: number;
  rewards: bigint[]; // Priority fees at different percentiles
}

// Transaction tracking
interface PendingTransaction {
  id: string;
  hash?: string;
  from: string;
  to: string;
  data: string;
  value: bigint;
  nonce: number;
  gasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  createdAt: Date;
  submittedAt?: Date;
  confirmedAt?: Date;
  status: TransactionStatus;
  retries: number;
  priority: TransactionPriority;
  deadline?: Date;
}

enum TransactionStatus {
  PENDING = 'pending',
  SUBMITTED = 'submitted',
  CONFIRMED = 'confirmed',
  FAILED = 'failed',
  REPLACED = 'replaced',
  CANCELLED = 'cancelled'
}

// Nonce tracker
interface NonceTracker {
  currentNonce: number;
  pendingNonces: Set<number>;
  confirmedNonces: Set<number>;
  lastUpdated: Date;
}

// Gas statistics
interface GasStatistics {
  averageBaseFee: bigint;
  medianBaseFee: bigint;
  volatility: number;
  trend: 'increasing' | 'decreasing' | 'stable';
  predictedNextBaseFee: bigint;
  networkCongestion: number; // 0-100
}

// Batch transaction
interface TransactionBatch {
  id: string;
  transactions: PendingTransaction[];
  totalGasLimit: bigint;
  maxFeePerGas: bigint;
  createdAt: Date;
  status: 'pending' | 'executed' | 'failed';
}

// Configuration
interface GasOptimizerConfig {
  maxHistoryBlocks: number;
  predictionHorizonBlocks: number;
  batchMaxSize: number;
  maxPendingTransactions: number;
  nonceGapTolerance: number;
  staleTransactionTimeout: number; // ms
  replacementBumpPercent: number; // Minimum fee bump for replacement
  minConfidence: number;
}

/**
 * Block fee analyzer for pattern detection
 */
class BlockFeeAnalyzer {
  private history: BlockFeeHistory[] = [];
  private maxBlocks: number;
  private emaShort: bigint = 0n;
  private emaLong: bigint = 0n;

  constructor(maxBlocks: number) {
    this.maxBlocks = maxBlocks;
  }

  /**
   * Add new block fee data
   */
  addBlockData(block: BlockFeeHistory): void {
    this.history.push(block);

    if (this.history.length > this.maxBlocks) {
      this.history.shift();
    }

    // Update EMAs
    this.updateEMAs(block.baseFeePerGas);
  }

  /**
   * Get gas statistics
   */
  getStatistics(): GasStatistics {
    if (this.history.length === 0) {
      return {
        averageBaseFee: 0n,
        medianBaseFee: 0n,
        volatility: 0,
        trend: 'stable',
        predictedNextBaseFee: 0n,
        networkCongestion: 0
      };
    }

    const baseFees = this.history.map(b => b.baseFeePerGas);

    // Calculate average
    const sum = baseFees.reduce((a, b) => a + b, 0n);
    const averageBaseFee = sum / BigInt(baseFees.length);

    // Calculate median
    const sorted = [...baseFees].sort((a, b) => Number(a - b));
    const medianBaseFee = sorted[Math.floor(sorted.length / 2)];

    // Calculate volatility (coefficient of variation)
    const variance = this.calculateVariance(baseFees, averageBaseFee);
    const volatility = Math.sqrt(Number(variance)) / Number(averageBaseFee) * 100;

    // Determine trend
    let trend: 'increasing' | 'decreasing' | 'stable' = 'stable';
    if (this.emaShort > this.emaLong * 105n / 100n) {
      trend = 'increasing';
    } else if (this.emaShort < this.emaLong * 95n / 100n) {
      trend = 'decreasing';
    }

    // Predict next base fee using EIP-1559 formula
    const lastBlock = this.history[this.history.length - 1];
    const predictedNextBaseFee = this.predictNextBaseFee(lastBlock);

    // Calculate network congestion
    const recentBlocks = this.history.slice(-10);
    const avgGasUsedRatio = recentBlocks.reduce((sum, b) => {
      return sum + Number(b.gasUsed * 100n / b.gasLimit);
    }, 0) / recentBlocks.length;
    const networkCongestion = Math.min(100, avgGasUsedRatio);

    return {
      averageBaseFee,
      medianBaseFee,
      volatility,
      trend,
      predictedNextBaseFee,
      networkCongestion
    };
  }

  /**
   * Predict base fee for future block
   */
  predictNextBaseFee(currentBlock: BlockFeeHistory): bigint {
    // EIP-1559 base fee adjustment formula
    const targetGasUsed = currentBlock.gasLimit / 2n;
    const gasUsedDelta = currentBlock.gasUsed - targetGasUsed;

    let baseFeeChange: bigint;
    if (gasUsedDelta > 0n) {
      // Block was more than 50% full, increase base fee
      baseFeeChange = currentBlock.baseFeePerGas * gasUsedDelta / targetGasUsed / 8n;
    } else {
      // Block was less than 50% full, decrease base fee
      baseFeeChange = currentBlock.baseFeePerGas * (-gasUsedDelta) / targetGasUsed / 8n;
      baseFeeChange = -baseFeeChange;
    }

    const nextBaseFee = currentBlock.baseFeePerGas + baseFeeChange;

    // Base fee cannot go below 0
    return nextBaseFee > 0n ? nextBaseFee : 0n;
  }

  /**
   * Get percentile priority fee from recent blocks
   */
  getPercentilePriorityFee(percentile: number): bigint {
    if (this.history.length === 0) return 0n;

    const allRewards: bigint[] = [];
    for (const block of this.history.slice(-20)) {
      allRewards.push(...block.rewards);
    }

    if (allRewards.length === 0) return 0n;

    const sorted = allRewards.sort((a, b) => Number(a - b));
    const index = Math.floor((percentile / 100) * sorted.length);
    return sorted[Math.min(index, sorted.length - 1)];
  }

  private updateEMAs(baseFee: bigint): void {
    // Short EMA (5 blocks)
    if (this.emaShort === 0n) {
      this.emaShort = baseFee;
    } else {
      const kShort = 2n * baseFee / 6n; // k = 2/(5+1)
      this.emaShort = kShort + this.emaShort * 4n / 6n;
    }

    // Long EMA (20 blocks)
    if (this.emaLong === 0n) {
      this.emaLong = baseFee;
    } else {
      const kLong = 2n * baseFee / 21n; // k = 2/(20+1)
      this.emaLong = kLong + this.emaLong * 19n / 21n;
    }
  }

  private calculateVariance(values: bigint[], mean: bigint): bigint {
    if (values.length === 0) return 0n;

    let sumSquaredDiff = 0n;
    for (const value of values) {
      const diff = value - mean;
      sumSquaredDiff += diff * diff;
    }

    return sumSquaredDiff / BigInt(values.length);
  }

  getHistory(): BlockFeeHistory[] {
    return this.history;
  }
}

/**
 * Transaction batcher for gas efficiency
 */
class TransactionBatcher {
  private pendingBatches: Map<string, TransactionBatch> = new Map();
  private maxBatchSize: number;

  constructor(maxBatchSize: number) {
    this.maxBatchSize = maxBatchSize;
  }

  /**
   * Create a new batch
   */
  createBatch(transactions: PendingTransaction[]): TransactionBatch {
    if (transactions.length > this.maxBatchSize) {
      throw new Error(`Batch size exceeds maximum of ${this.maxBatchSize}`);
    }

    const totalGasLimit = transactions.reduce((sum, tx) => sum + tx.gasLimit, 0n);
    const maxFeePerGas = transactions.reduce(
      (max, tx) => tx.maxFeePerGas > max ? tx.maxFeePerGas : max,
      0n
    );

    const batch: TransactionBatch = {
      id: crypto.randomBytes(16).toString('hex'),
      transactions,
      totalGasLimit,
      maxFeePerGas,
      createdAt: new Date(),
      status: 'pending'
    };

    this.pendingBatches.set(batch.id, batch);
    return batch;
  }

  /**
   * Optimize batch for gas savings
   */
  optimizeBatch(batch: TransactionBatch): TransactionBatch {
    // Sort transactions by gas efficiency (value/gas ratio)
    const sorted = batch.transactions.sort((a, b) => {
      const efficiencyA = Number(a.value / a.gasLimit);
      const efficiencyB = Number(b.value / b.gasLimit);
      return efficiencyB - efficiencyA;
    });

    // Recalculate totals
    batch.transactions = sorted;
    batch.totalGasLimit = sorted.reduce((sum, tx) => sum + tx.gasLimit, 0n);

    return batch;
  }

  /**
   * Get pending batches
   */
  getPendingBatches(): TransactionBatch[] {
    return Array.from(this.pendingBatches.values());
  }

  /**
   * Mark batch as executed
   */
  markBatchExecuted(batchId: string): void {
    const batch = this.pendingBatches.get(batchId);
    if (batch) {
      batch.status = 'executed';
      this.pendingBatches.delete(batchId);
    }
  }
}

/**
 * Nonce manager for transaction ordering
 */
class NonceManager {
  private trackers: Map<string, NonceTracker> = new Map();
  private gapTolerance: number;

  constructor(gapTolerance: number) {
    this.gapTolerance = gapTolerance;
  }

  /**
   * Get next nonce for address
   */
  getNextNonce(address: string, currentChainNonce: number): number {
    let tracker = this.trackers.get(address);

    if (!tracker) {
      tracker = {
        currentNonce: currentChainNonce,
        pendingNonces: new Set(),
        confirmedNonces: new Set(),
        lastUpdated: new Date()
      };
      this.trackers.set(address, tracker);
    }

    // Find next available nonce
    let nextNonce = Math.max(currentChainNonce, tracker.currentNonce);

    while (tracker.pendingNonces.has(nextNonce)) {
      nextNonce++;

      // Check for excessive gaps
      if (nextNonce - currentChainNonce > this.gapTolerance) {
        throw new Error(`Nonce gap too large for ${address}`);
      }
    }

    tracker.pendingNonces.add(nextNonce);
    tracker.currentNonce = nextNonce + 1;
    tracker.lastUpdated = new Date();

    return nextNonce;
  }

  /**
   * Mark nonce as confirmed
   */
  confirmNonce(address: string, nonce: number): void {
    const tracker = this.trackers.get(address);
    if (tracker) {
      tracker.pendingNonces.delete(nonce);
      tracker.confirmedNonces.add(nonce);
      tracker.lastUpdated = new Date();

      // Clean up old confirmed nonces
      if (tracker.confirmedNonces.size > 1000) {
        const sorted = Array.from(tracker.confirmedNonces).sort((a, b) => a - b);
        const toRemove = sorted.slice(0, 500);
        toRemove.forEach(n => tracker.confirmedNonces.delete(n));
      }
    }
  }

  /**
   * Release nonce (for failed/cancelled transactions)
   */
  releaseNonce(address: string, nonce: number): void {
    const tracker = this.trackers.get(address);
    if (tracker) {
      tracker.pendingNonces.delete(nonce);
      tracker.lastUpdated = new Date();
    }
  }

  /**
   * Get pending nonces for address
   */
  getPendingNonces(address: string): number[] {
    const tracker = this.trackers.get(address);
    return tracker ? Array.from(tracker.pendingNonces).sort((a, b) => a - b) : [];
  }

  /**
   * Check for nonce gaps
   */
  hasNonceGap(address: string, currentChainNonce: number): boolean {
    const tracker = this.trackers.get(address);
    if (!tracker) return false;

    const pendingList = Array.from(tracker.pendingNonces).sort((a, b) => a - b);
    if (pendingList.length === 0) return false;

    // Check if there's a gap between chain nonce and first pending
    if (pendingList[0] > currentChainNonce) {
      return true;
    }

    // Check for gaps in pending nonces
    for (let i = 1; i < pendingList.length; i++) {
      if (pendingList[i] - pendingList[i - 1] > 1) {
        return true;
      }
    }

    return false;
  }
}

/**
 * Main Gas Optimization Engine
 */
export class GasOptimizationEngine extends EventEmitter {
  private config: GasOptimizerConfig;
  private feeAnalyzer: BlockFeeAnalyzer;
  private batcher: TransactionBatcher;
  private nonceManager: NonceManager;
  private pendingTransactions: Map<string, PendingTransaction> = new Map();
  private transactionHistory: PendingTransaction[] = [];
  private lastBlockNumber: bigint = 0n;

  constructor(config: GasOptimizerConfig) {
    super();
    this.config = config;
    this.feeAnalyzer = new BlockFeeAnalyzer(config.maxHistoryBlocks);
    this.batcher = new TransactionBatcher(config.batchMaxSize);
    this.nonceManager = new NonceManager(config.nonceGapTolerance);

    // Start stale transaction checker
    this.startStaleTransactionChecker();
  }

  /**
   * Process new block data
   */
  processNewBlock(block: BlockFeeHistory): void {
    this.feeAnalyzer.addBlockData(block);
    this.lastBlockNumber = block.blockNumber;

    const stats = this.feeAnalyzer.getStatistics();
    this.emit('blockProcessed', { block, stats });

    // Check if any pending transactions need repricing
    this.checkTransactionRepricing(stats);
  }

  /**
   * Estimate gas fees for a transaction
   */
  estimateFees(
    gasLimit: bigint,
    strategy: FeeStrategy = FeeStrategy.STANDARD
  ): EIP1559FeeEstimate {
    const stats = this.feeAnalyzer.getStatistics();

    let maxPriorityFeePerGas: bigint;
    let confidence: number;

    switch (strategy) {
      case FeeStrategy.SLOW:
        maxPriorityFeePerGas = this.feeAnalyzer.getPercentilePriorityFee(10);
        confidence = 70;
        break;

      case FeeStrategy.STANDARD:
        maxPriorityFeePerGas = this.feeAnalyzer.getPercentilePriorityFee(50);
        confidence = 85;
        break;

      case FeeStrategy.FAST:
        maxPriorityFeePerGas = this.feeAnalyzer.getPercentilePriorityFee(75);
        confidence = 95;
        break;

      case FeeStrategy.INSTANT:
        maxPriorityFeePerGas = this.feeAnalyzer.getPercentilePriorityFee(95);
        confidence = 99;
        break;

      default:
        maxPriorityFeePerGas = this.feeAnalyzer.getPercentilePriorityFee(50);
        confidence = 85;
    }

    // Adjust based on network congestion
    const congestionMultiplier = 100 + Math.floor(stats.networkCongestion / 2);
    maxPriorityFeePerGas = maxPriorityFeePerGas * BigInt(congestionMultiplier) / 100n;

    // Calculate max fee (base fee + priority fee with buffer)
    const baseFeeBuffer = stats.trend === 'increasing' ? 125n : 110n; // 25% or 10% buffer
    const maxFeePerGas = stats.predictedNextBaseFee * baseFeeBuffer / 100n + maxPriorityFeePerGas;

    const totalMaxCost = maxFeePerGas * gasLimit;

    // Adjust confidence based on volatility
    if (stats.volatility > 50) {
      confidence = Math.max(50, confidence - 20);
    } else if (stats.volatility > 25) {
      confidence = Math.max(60, confidence - 10);
    }

    return {
      maxFeePerGas,
      maxPriorityFeePerGas,
      baseFeePerGas: stats.predictedNextBaseFee,
      estimatedGasUsed: gasLimit,
      totalMaxCost,
      confidence,
      strategy
    };
  }

  /**
   * Create and track a new transaction
   */
  createTransaction(
    from: string,
    to: string,
    data: string,
    value: bigint,
    gasLimit: bigint,
    priority: TransactionPriority = TransactionPriority.MEDIUM,
    deadline?: Date
  ): PendingTransaction {
    if (this.pendingTransactions.size >= this.config.maxPendingTransactions) {
      throw new Error('Maximum pending transactions reached');
    }

    // Determine fee strategy based on priority
    let strategy: FeeStrategy;
    switch (priority) {
      case TransactionPriority.LOW:
        strategy = FeeStrategy.SLOW;
        break;
      case TransactionPriority.MEDIUM:
        strategy = FeeStrategy.STANDARD;
        break;
      case TransactionPriority.HIGH:
        strategy = FeeStrategy.FAST;
        break;
      case TransactionPriority.CRITICAL:
        strategy = FeeStrategy.INSTANT;
        break;
    }

    const feeEstimate = this.estimateFees(gasLimit, strategy);

    // Get next nonce (would fetch current chain nonce in production)
    const currentChainNonce = this.getCurrentChainNonce(from);
    const nonce = this.nonceManager.getNextNonce(from, currentChainNonce);

    const transaction: PendingTransaction = {
      id: crypto.randomBytes(16).toString('hex'),
      from,
      to,
      data,
      value,
      nonce,
      gasLimit,
      maxFeePerGas: feeEstimate.maxFeePerGas,
      maxPriorityFeePerGas: feeEstimate.maxPriorityFeePerGas,
      createdAt: new Date(),
      status: TransactionStatus.PENDING,
      retries: 0,
      priority,
      deadline
    };

    this.pendingTransactions.set(transaction.id, transaction);
    this.emit('transactionCreated', transaction);

    return transaction;
  }

  /**
   * Submit transaction (simulate)
   */
  async submitTransaction(transactionId: string): Promise<string> {
    const tx = this.pendingTransactions.get(transactionId);
    if (!tx) {
      throw new Error('Transaction not found');
    }

    if (tx.status !== TransactionStatus.PENDING && tx.status !== TransactionStatus.FAILED) {
      throw new Error(`Cannot submit transaction in ${tx.status} status`);
    }

    // Check deadline
    if (tx.deadline && new Date() > tx.deadline) {
      tx.status = TransactionStatus.FAILED;
      this.nonceManager.releaseNonce(tx.from, tx.nonce);
      throw new Error('Transaction deadline expired');
    }

    // Simulate hash generation (would be real tx hash)
    tx.hash = '0x' + crypto.randomBytes(32).toString('hex');
    tx.submittedAt = new Date();
    tx.status = TransactionStatus.SUBMITTED;

    this.emit('transactionSubmitted', tx);

    return tx.hash;
  }

  /**
   * Replace transaction with higher fees
   */
  replaceTransaction(
    transactionId: string,
    newPriority?: TransactionPriority
  ): PendingTransaction {
    const originalTx = this.pendingTransactions.get(transactionId);
    if (!originalTx) {
      throw new Error('Transaction not found');
    }

    if (originalTx.status !== TransactionStatus.SUBMITTED) {
      throw new Error('Can only replace submitted transactions');
    }

    const priority = newPriority || originalTx.priority;
    let strategy: FeeStrategy;

    switch (priority) {
      case TransactionPriority.LOW:
        strategy = FeeStrategy.STANDARD; // Bump up
        break;
      case TransactionPriority.MEDIUM:
        strategy = FeeStrategy.FAST;
        break;
      case TransactionPriority.HIGH:
        strategy = FeeStrategy.INSTANT;
        break;
      default:
        strategy = FeeStrategy.INSTANT;
    }

    const newFeeEstimate = this.estimateFees(originalTx.gasLimit, strategy);

    // Ensure minimum bump (usually 10% for replacement)
    const minBumpFactor = BigInt(100 + this.config.replacementBumpPercent);
    const minMaxFee = originalTx.maxFeePerGas * minBumpFactor / 100n;
    const minPriorityFee = originalTx.maxPriorityFeePerGas * minBumpFactor / 100n;

    const newMaxFeePerGas = newFeeEstimate.maxFeePerGas > minMaxFee
      ? newFeeEstimate.maxFeePerGas
      : minMaxFee;

    const newPriorityFee = newFeeEstimate.maxPriorityFeePerGas > minPriorityFee
      ? newFeeEstimate.maxPriorityFeePerGas
      : minPriorityFee;

    // Create replacement transaction (same nonce)
    const replacementTx: PendingTransaction = {
      ...originalTx,
      id: crypto.randomBytes(16).toString('hex'),
      hash: undefined,
      maxFeePerGas: newMaxFeePerGas,
      maxPriorityFeePerGas: newPriorityFee,
      createdAt: new Date(),
      submittedAt: undefined,
      status: TransactionStatus.PENDING,
      retries: originalTx.retries + 1,
      priority
    };

    // Mark original as replaced
    originalTx.status = TransactionStatus.REPLACED;

    this.pendingTransactions.set(replacementTx.id, replacementTx);
    this.emit('transactionReplaced', { original: originalTx, replacement: replacementTx });

    return replacementTx;
  }

  /**
   * Cancel transaction (submit 0-value tx with same nonce)
   */
  cancelTransaction(transactionId: string): PendingTransaction {
    const originalTx = this.pendingTransactions.get(transactionId);
    if (!originalTx) {
      throw new Error('Transaction not found');
    }

    if (originalTx.status !== TransactionStatus.SUBMITTED) {
      throw new Error('Can only cancel submitted transactions');
    }

    // Create cancellation (self-send with 0 value, higher fees)
    const cancelFees = this.estimateFees(21000n, FeeStrategy.INSTANT);

    const minBumpFactor = BigInt(100 + this.config.replacementBumpPercent);
    const newMaxFee = originalTx.maxFeePerGas * minBumpFactor / 100n;
    const newPriorityFee = originalTx.maxPriorityFeePerGas * minBumpFactor / 100n;

    const cancellationTx: PendingTransaction = {
      id: crypto.randomBytes(16).toString('hex'),
      from: originalTx.from,
      to: originalTx.from, // Self-send
      data: '0x',
      value: 0n,
      nonce: originalTx.nonce, // Same nonce
      gasLimit: 21000n, // Basic transfer
      maxFeePerGas: newMaxFee > cancelFees.maxFeePerGas ? newMaxFee : cancelFees.maxFeePerGas,
      maxPriorityFeePerGas: newPriorityFee > cancelFees.maxPriorityFeePerGas
        ? newPriorityFee
        : cancelFees.maxPriorityFeePerGas,
      createdAt: new Date(),
      status: TransactionStatus.PENDING,
      retries: 0,
      priority: TransactionPriority.CRITICAL
    };

    originalTx.status = TransactionStatus.CANCELLED;
    this.pendingTransactions.set(cancellationTx.id, cancellationTx);

    this.emit('transactionCancelled', { original: originalTx, cancellation: cancellationTx });

    return cancellationTx;
  }

  /**
   * Confirm transaction
   */
  confirmTransaction(transactionId: string, blockNumber: bigint): void {
    const tx = this.pendingTransactions.get(transactionId);
    if (!tx) return;

    tx.status = TransactionStatus.CONFIRMED;
    tx.confirmedAt = new Date();

    this.nonceManager.confirmNonce(tx.from, tx.nonce);
    this.pendingTransactions.delete(transactionId);
    this.transactionHistory.push(tx);

    // Keep history manageable
    if (this.transactionHistory.length > 10000) {
      this.transactionHistory = this.transactionHistory.slice(-10000);
    }

    this.emit('transactionConfirmed', { transaction: tx, blockNumber });
  }

  /**
   * Get gas savings report
   */
  getGasSavingsReport(): {
    totalTransactions: number;
    totalGasSaved: bigint;
    averageSavingsPercent: number;
    totalCost: bigint;
    successRate: number;
  } {
    if (this.transactionHistory.length === 0) {
      return {
        totalTransactions: 0,
        totalGasSaved: 0n,
        averageSavingsPercent: 0,
        totalCost: 0n,
        successRate: 0
      };
    }

    const stats = this.feeAnalyzer.getStatistics();
    const confirmedTxs = this.transactionHistory.filter(
      tx => tx.status === TransactionStatus.CONFIRMED
    );

    let totalGasSaved = 0n;
    let totalCost = 0n;

    for (const tx of confirmedTxs) {
      // Calculate what naive estimation would have cost
      const naiveMaxFee = stats.averageBaseFee * 2n; // 2x average base fee
      const naiveCost = naiveMaxFee * tx.gasLimit;

      const actualCost = tx.maxFeePerGas * tx.gasLimit;
      const saved = naiveCost > actualCost ? naiveCost - actualCost : 0n;

      totalGasSaved += saved;
      totalCost += actualCost;
    }

    const averageSavingsPercent = totalCost > 0n
      ? Number((totalGasSaved * 10000n) / (totalCost + totalGasSaved)) / 100
      : 0;

    const successRate = confirmedTxs.length / this.transactionHistory.length * 100;

    return {
      totalTransactions: this.transactionHistory.length,
      totalGasSaved,
      averageSavingsPercent,
      totalCost,
      successRate
    };
  }

  /**
   * Get current gas statistics
   */
  getGasStatistics(): GasStatistics {
    return this.feeAnalyzer.getStatistics();
  }

  /**
   * Get pending transactions
   */
  getPendingTransactions(): PendingTransaction[] {
    return Array.from(this.pendingTransactions.values());
  }

  /**
   * Check for transactions that need repricing
   */
  private checkTransactionRepricing(stats: GasStatistics): void {
    for (const [id, tx] of this.pendingTransactions) {
      if (tx.status !== TransactionStatus.SUBMITTED) continue;

      // Check if transaction is underprice
      if (tx.maxFeePerGas < stats.predictedNextBaseFee) {
        this.emit('transactionUnderpriced', {
          transaction: tx,
          recommendedMaxFee: stats.predictedNextBaseFee * 120n / 100n
        });
      }

      // Check deadline
      if (tx.deadline && new Date() > tx.deadline) {
        this.emit('transactionDeadlineApproaching', tx);
      }
    }
  }

  /**
   * Start stale transaction checker
   */
  private startStaleTransactionChecker(): void {
    setInterval(() => {
      const now = Date.now();

      for (const [id, tx] of this.pendingTransactions) {
        if (tx.status === TransactionStatus.SUBMITTED && tx.submittedAt) {
          const age = now - tx.submittedAt.getTime();

          if (age > this.config.staleTransactionTimeout) {
            this.emit('transactionStale', tx);
          }
        }
      }
    }, 30000); // Check every 30 seconds
  }

  /**
   * Get current chain nonce (simulated)
   */
  private getCurrentChainNonce(address: string): number {
    // In production, would fetch from blockchain
    return 0;
  }
}

// Export components
export {
  FeeStrategy,
  TransactionPriority,
  TransactionStatus,
  EIP1559FeeEstimate,
  PendingTransaction,
  BlockFeeHistory,
  GasStatistics,
  BlockFeeAnalyzer,
  TransactionBatcher,
  NonceManager
};

// Default configuration
export const defaultGasOptimizerConfig: GasOptimizerConfig = {
  maxHistoryBlocks: 1000,
  predictionHorizonBlocks: 10,
  batchMaxSize: 100,
  maxPendingTransactions: 1000,
  nonceGapTolerance: 10,
  staleTransactionTimeout: 300000, // 5 minutes
  replacementBumpPercent: 10,
  minConfidence: 70
};
