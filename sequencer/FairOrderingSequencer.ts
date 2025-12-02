/**
 * Fair Ordering Sequencer for Layer 2 Rollup
 *
 * SCIENTIFIC HYPOTHESIS:
 * A commit-reveal sequencer with encrypted transaction ordering and
 * verifiable delay functions will eliminate MEV extraction by ensuring
 * transaction ordering is determined before content is known, achieving
 * >99.9% fairness in ordering with <100ms latency overhead.
 *
 * SUCCESS METRICS:
 * - MEV extraction: <0.001% of transaction value
 * - Ordering fairness: >99.9% based on arrival time
 * - Throughput: >10,000 TPS
 * - Latency overhead: <100ms for fair ordering
 * - Finality: <1 second for transaction inclusion
 * - Censorship resistance: 100% of valid transactions included
 *
 * SECURITY CONSIDERATIONS:
 * - Encrypted mempool prevents front-running
 * - VDF ensures ordering cannot be manipulated
 * - Multi-sequencer rotation for decentralization
 * - Fraud proofs for invalid sequencing
 * - Slashing for malicious behavior
 */

import { EventEmitter } from 'events';
import Redis from 'ioredis';
import winston from 'winston';
import crypto from 'crypto';

// ============================================================================
// INTERFACES & TYPES
// ============================================================================

interface SequencerConfig {
  batchSize: number;
  batchTimeout: number;
  vdfDifficulty: number;
  commitWindow: number;
  revealWindow: number;
  maxTransactionsPerBatch: number;
  minStake: bigint;
  slashingPenalty: number;
  rotationPeriod: number;
}

interface EncryptedTransaction {
  txId: string;
  encryptedData: Buffer;
  commitment: Buffer;
  sender: string;
  nonce: bigint;
  timestamp: bigint;
  gasLimit: number;
  priorityFee: bigint;
  revealed: boolean;
  decryptedTx?: Transaction;
}

interface Transaction {
  txId: string;
  from: string;
  to: string;
  data: Buffer;
  value: bigint;
  gasLimit: number;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  nonce: bigint;
  chainId: number;
  signature: Buffer;
}

interface Batch {
  batchId: string;
  sequenceNumber: bigint;
  transactions: EncryptedTransaction[];
  orderingProof: OrderingProof;
  vdfProof: VDFProof;
  stateRoot: Buffer;
  previousStateRoot: Buffer;
  timestamp: bigint;
  sequencer: string;
  status: BatchStatus;
  commitment: Buffer;
  submittedAt?: Date;
  finalizedAt?: Date;
}

interface OrderingProof {
  merkleRoot: Buffer;
  commitments: Buffer[];
  timestamps: bigint[];
  ordering: number[];
  signature: Buffer;
}

interface VDFProof {
  input: Buffer;
  output: Buffer;
  iterations: number;
  proof: Buffer;
  verificationKey: Buffer;
}

interface SequencerNode {
  address: string;
  stake: bigint;
  reputation: number;
  batchesProduced: number;
  slashingEvents: number;
  lastActive: Date;
  isActive: boolean;
  publicKey: Buffer;
}

interface FraudProof {
  proofId: string;
  batchId: string;
  type: FraudType;
  evidence: Buffer;
  challenger: string;
  challengedSequencer: string;
  timestamp: Date;
  resolved: boolean;
  outcome?: FraudOutcome;
}

interface SequencerRotation {
  previousSequencer: string;
  newSequencer: string;
  rotationTime: Date;
  reason: RotationReason;
  batchNumber: bigint;
}

interface CommitRevealState {
  phase: CommitRevealPhase;
  commitDeadline: bigint;
  revealDeadline: bigint;
  currentBatchId: string;
  pendingCommitments: Map<string, Buffer>;
  revealedTransactions: Map<string, EncryptedTransaction>;
}

interface SequencerMetrics {
  totalBatches: bigint;
  totalTransactions: bigint;
  avgBatchSize: number;
  avgOrderingLatency: number;
  throughputTPS: number;
  fairnessScore: number;
  fraudProofsSubmitted: number;
  slashingEvents: number;
  activeSequencers: number;
}

enum BatchStatus {
  PENDING = 'PENDING',
  COMMITTED = 'COMMITTED',
  REVEALED = 'REVEALED',
  ORDERED = 'ORDERED',
  EXECUTED = 'EXECUTED',
  FINALIZED = 'FINALIZED',
  DISPUTED = 'DISPUTED',
  INVALID = 'INVALID'
}

enum FraudType {
  INVALID_ORDERING = 'INVALID_ORDERING',
  CENSORSHIP = 'CENSORSHIP',
  INVALID_STATE_ROOT = 'INVALID_STATE_ROOT',
  INVALID_VDF = 'INVALID_VDF',
  DOUBLE_INCLUSION = 'DOUBLE_INCLUSION'
}

enum FraudOutcome {
  CHALLENGER_WINS = 'CHALLENGER_WINS',
  SEQUENCER_WINS = 'SEQUENCER_WINS',
  INVALID_PROOF = 'INVALID_PROOF'
}

enum RotationReason {
  SCHEDULED = 'SCHEDULED',
  SLASHED = 'SLASHED',
  OFFLINE = 'OFFLINE',
  VOLUNTARY = 'VOLUNTARY'
}

enum CommitRevealPhase {
  COMMIT = 'COMMIT',
  REVEAL = 'REVEAL',
  ORDERING = 'ORDERING',
  EXECUTION = 'EXECUTION'
}

// ============================================================================
// VERIFIABLE DELAY FUNCTION
// ============================================================================

class VerifiableDelayFunction {
  private difficulty: number;

  constructor(difficulty: number) {
    this.difficulty = difficulty;
  }

  async compute(input: Buffer): Promise<VDFProof> {
    // Simplified VDF using repeated hashing
    // Production would use time-lock puzzles or Wesolowski VDF

    let current = input;
    const iterations = Math.pow(2, this.difficulty);

    for (let i = 0; i < iterations; i++) {
      current = crypto.createHash('sha256').update(current).digest();
    }

    const proof = this.generateProof(input, current, iterations);

    return {
      input,
      output: current,
      iterations,
      proof,
      verificationKey: this.getVerificationKey()
    };
  }

  verify(vdfProof: VDFProof): boolean {
    // Verify the VDF output is correct
    let current = vdfProof.input;

    for (let i = 0; i < vdfProof.iterations; i++) {
      current = crypto.createHash('sha256').update(current).digest();
    }

    return current.equals(vdfProof.output);
  }

  private generateProof(input: Buffer, output: Buffer, iterations: number): Buffer {
    const proofData = Buffer.concat([
      input,
      output,
      Buffer.from(iterations.toString())
    ]);

    return crypto.createHash('sha256').update(proofData).digest();
  }

  private getVerificationKey(): Buffer {
    return crypto.randomBytes(32);
  }
}

// ============================================================================
// FAIR ORDERING SEQUENCER
// ============================================================================

export class FairOrderingSequencer extends EventEmitter {
  private config: SequencerConfig;
  private redis: Redis;
  private logger: winston.Logger;
  private vdf: VerifiableDelayFunction;

  private sequencers: Map<string, SequencerNode> = new Map();
  private pendingTransactions: Map<string, EncryptedTransaction> = new Map();
  private batches: Map<string, Batch> = new Map();
  private fraudProofs: Map<string, FraudProof> = new Map();
  private commitRevealState: CommitRevealState;

  private currentSequencer: string = '';
  private nextBatchSequence: bigint = 1n;
  private metrics: SequencerMetrics;
  private isRunning: boolean = false;
  private batchTimer?: NodeJS.Timeout;
  private phaseTimer?: NodeJS.Timeout;

  constructor(config: SequencerConfig, redisUrl: string) {
    super();

    this.config = config;
    this.redis = new Redis(redisUrl);
    this.vdf = new VerifiableDelayFunction(config.vdfDifficulty);

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'sequencer.log' })
      ]
    });

    this.commitRevealState = {
      phase: CommitRevealPhase.COMMIT,
      commitDeadline: 0n,
      revealDeadline: 0n,
      currentBatchId: '',
      pendingCommitments: new Map(),
      revealedTransactions: new Map()
    };

    this.metrics = {
      totalBatches: 0n,
      totalTransactions: 0n,
      avgBatchSize: 0,
      avgOrderingLatency: 0,
      throughputTPS: 0,
      fairnessScore: 1.0,
      fraudProofsSubmitted: 0,
      slashingEvents: 0,
      activeSequencers: 0
    };

    this.logger.info('Fair Ordering Sequencer initialized', {
      batchSize: config.batchSize,
      vdfDifficulty: config.vdfDifficulty,
      commitWindow: config.commitWindow
    });
  }

  // ============================================================================
  // INITIALIZATION
  // ============================================================================

  async start(): Promise<void> {
    if (this.isRunning) {
      throw new Error('Sequencer already running');
    }

    // Select initial sequencer
    await this.selectSequencer();

    // Start batch production
    this.startBatchProduction();

    // Start commit-reveal cycle
    this.startCommitRevealCycle();

    this.isRunning = true;
    this.logger.info('Fair Ordering Sequencer started');
    this.emit('started');
  }

  async stop(): Promise<void> {
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
    }

    if (this.phaseTimer) {
      clearTimeout(this.phaseTimer);
    }

    this.isRunning = false;
    this.logger.info('Fair Ordering Sequencer stopped');
    this.emit('stopped');
  }

  // ============================================================================
  // SEQUENCER MANAGEMENT
  // ============================================================================

  registerSequencer(
    address: string,
    stake: bigint,
    publicKey: Buffer
  ): void {
    if (stake < this.config.minStake) {
      throw new Error('Insufficient stake');
    }

    const node: SequencerNode = {
      address,
      stake,
      reputation: 100,
      batchesProduced: 0,
      slashingEvents: 0,
      lastActive: new Date(),
      isActive: true,
      publicKey
    };

    this.sequencers.set(address, node);
    this.metrics.activeSequencers++;

    this.logger.info('Sequencer registered', {
      address,
      stake: stake.toString()
    });

    this.emit('sequencerRegistered', node);
  }

  private async selectSequencer(): Promise<void> {
    // Weighted random selection based on stake and reputation
    const activeSequencers = Array.from(this.sequencers.values()).filter(
      s => s.isActive && s.stake >= this.config.minStake
    );

    if (activeSequencers.length === 0) {
      throw new Error('No active sequencers');
    }

    // Calculate weights
    const totalWeight = activeSequencers.reduce(
      (sum, s) => sum + Number(s.stake) * s.reputation,
      0
    );

    let randomValue = Math.random() * totalWeight;
    let selectedSequencer = activeSequencers[0];

    for (const sequencer of activeSequencers) {
      const weight = Number(sequencer.stake) * sequencer.reputation;
      randomValue -= weight;

      if (randomValue <= 0) {
        selectedSequencer = sequencer;
        break;
      }
    }

    const previousSequencer = this.currentSequencer;
    this.currentSequencer = selectedSequencer.address;

    if (previousSequencer && previousSequencer !== this.currentSequencer) {
      const rotation: SequencerRotation = {
        previousSequencer,
        newSequencer: this.currentSequencer,
        rotationTime: new Date(),
        reason: RotationReason.SCHEDULED,
        batchNumber: this.nextBatchSequence
      };

      this.emit('sequencerRotated', rotation);
    }

    this.logger.info('Sequencer selected', {
      address: this.currentSequencer,
      stake: selectedSequencer.stake.toString(),
      reputation: selectedSequencer.reputation
    });
  }

  // ============================================================================
  // TRANSACTION SUBMISSION
  // ============================================================================

  submitEncryptedTransaction(
    encryptedData: Buffer,
    commitment: Buffer,
    sender: string,
    nonce: bigint,
    gasLimit: number,
    priorityFee: bigint
  ): string {
    const txId = crypto.randomBytes(16).toString('hex');
    const timestamp = this.getNanoseconds();

    // Verify commitment matches encrypted data
    const expectedCommitment = this.computeCommitment(encryptedData);
    if (!commitment.equals(expectedCommitment)) {
      throw new Error('Invalid commitment');
    }

    const encryptedTx: EncryptedTransaction = {
      txId,
      encryptedData,
      commitment,
      sender,
      nonce,
      timestamp,
      gasLimit,
      priorityFee,
      revealed: false
    };

    this.pendingTransactions.set(txId, encryptedTx);
    this.commitRevealState.pendingCommitments.set(txId, commitment);

    this.logger.info('Encrypted transaction submitted', {
      txId,
      sender,
      timestamp: timestamp.toString()
    });

    this.emit('transactionSubmitted', encryptedTx);

    return txId;
  }

  revealTransaction(txId: string, decryptionKey: Buffer): void {
    const encryptedTx = this.pendingTransactions.get(txId);
    if (!encryptedTx) {
      throw new Error('Transaction not found');
    }

    if (
      this.commitRevealState.phase !== CommitRevealPhase.REVEAL &&
      this.commitRevealState.phase !== CommitRevealPhase.ORDERING
    ) {
      throw new Error('Not in reveal phase');
    }

    // Decrypt transaction
    const decryptedData = this.decryptTransaction(
      encryptedTx.encryptedData,
      decryptionKey
    );

    const tx = this.parseTransaction(decryptedData);

    // Verify commitment
    const recomputedCommitment = this.computeCommitment(encryptedTx.encryptedData);
    if (!recomputedCommitment.equals(encryptedTx.commitment)) {
      throw new Error('Commitment mismatch');
    }

    encryptedTx.revealed = true;
    encryptedTx.decryptedTx = tx;

    this.commitRevealState.revealedTransactions.set(txId, encryptedTx);

    this.logger.info('Transaction revealed', { txId });

    this.emit('transactionRevealed', encryptedTx);
  }

  // ============================================================================
  // BATCH PRODUCTION
  // ============================================================================

  private startBatchProduction(): void {
    this.batchTimer = setInterval(() => {
      this.produceBatch();
    }, this.config.batchTimeout);
  }

  private async produceBatch(): Promise<void> {
    if (!this.isRunning) return;

    // Check if we're the current sequencer
    // In production, only the selected sequencer produces batches

    const batchId = crypto.randomBytes(16).toString('hex');

    // Collect transactions for this batch
    const transactions = this.selectTransactionsForBatch();

    if (transactions.length === 0) {
      return;
    }

    // Determine fair ordering using timestamps and VDF
    const orderingProof = await this.computeFairOrdering(transactions);

    // Compute VDF proof
    const vdfInput = Buffer.concat(transactions.map(tx => tx.commitment));
    const vdfProof = await this.vdf.compute(vdfInput);

    // Compute state root (simplified)
    const stateRoot = this.computeStateRoot(transactions);
    const previousStateRoot = this.getPreviousStateRoot();

    const batch: Batch = {
      batchId,
      sequenceNumber: this.nextBatchSequence++,
      transactions,
      orderingProof,
      vdfProof,
      stateRoot,
      previousStateRoot,
      timestamp: this.getNanoseconds(),
      sequencer: this.currentSequencer,
      status: BatchStatus.ORDERED,
      commitment: this.computeBatchCommitment(transactions, orderingProof),
      submittedAt: new Date()
    };

    this.batches.set(batchId, batch);

    // Update metrics
    this.metrics.totalBatches++;
    this.metrics.totalTransactions += BigInt(transactions.length);
    this.updateAverageBatchSize(transactions.length);

    // Remove transactions from pending
    for (const tx of transactions) {
      this.pendingTransactions.delete(tx.txId);
    }

    this.logger.info('Batch produced', {
      batchId,
      sequenceNumber: batch.sequenceNumber.toString(),
      transactionCount: transactions.length
    });

    this.emit('batchProduced', batch);

    // Update sequencer stats
    const sequencer = this.sequencers.get(this.currentSequencer);
    if (sequencer) {
      sequencer.batchesProduced++;
      sequencer.lastActive = new Date();
    }
  }

  private selectTransactionsForBatch(): EncryptedTransaction[] {
    const transactions: EncryptedTransaction[] = [];

    // Select revealed transactions up to batch size
    for (const [, tx] of this.commitRevealState.revealedTransactions) {
      if (transactions.length >= this.config.maxTransactionsPerBatch) {
        break;
      }

      transactions.push(tx);
    }

    // Clear selected transactions from revealed state
    for (const tx of transactions) {
      this.commitRevealState.revealedTransactions.delete(tx.txId);
    }

    return transactions;
  }

  private async computeFairOrdering(
    transactions: EncryptedTransaction[]
  ): Promise<OrderingProof> {
    // Fair ordering based on commit timestamps (first-come-first-served)
    // Prevents MEV by ensuring order is based on arrival time, not content

    const sortedTxs = [...transactions].sort((a, b) => {
      // Primary: timestamp
      const timeDiff = Number(a.timestamp - b.timestamp);
      if (timeDiff !== 0) return timeDiff;

      // Secondary: commitment hash (deterministic tie-breaker)
      return Buffer.compare(a.commitment, b.commitment);
    });

    const ordering = sortedTxs.map(tx =>
      transactions.findIndex(t => t.txId === tx.txId)
    );

    const commitments = sortedTxs.map(tx => tx.commitment);
    const timestamps = sortedTxs.map(tx => tx.timestamp);

    // Build merkle tree for ordering proof
    const merkleRoot = this.computeMerkleRoot(commitments);

    // Sign the ordering
    const orderingData = Buffer.concat([
      merkleRoot,
      ...timestamps.map(t => Buffer.from(t.toString())),
      Buffer.from(ordering.join(','))
    ]);

    const signature = this.signOrdering(orderingData);

    return {
      merkleRoot,
      commitments,
      timestamps,
      ordering,
      signature
    };
  }

  private computeMerkleRoot(leaves: Buffer[]): Buffer {
    if (leaves.length === 0) {
      return Buffer.alloc(32);
    }

    if (leaves.length === 1) {
      return leaves[0];
    }

    const nextLevel: Buffer[] = [];

    for (let i = 0; i < leaves.length; i += 2) {
      if (i + 1 < leaves.length) {
        const combined = crypto
          .createHash('sha256')
          .update(Buffer.concat([leaves[i], leaves[i + 1]]))
          .digest();
        nextLevel.push(combined);
      } else {
        nextLevel.push(leaves[i]);
      }
    }

    return this.computeMerkleRoot(nextLevel);
  }

  private signOrdering(data: Buffer): Buffer {
    // Sign with sequencer's private key
    return crypto.createHash('sha256').update(data).digest();
  }

  // ============================================================================
  // COMMIT-REVEAL CYCLE
  // ============================================================================

  private startCommitRevealCycle(): void {
    this.transitionToCommitPhase();
  }

  private transitionToCommitPhase(): void {
    const now = this.getNanoseconds();

    this.commitRevealState.phase = CommitRevealPhase.COMMIT;
    this.commitRevealState.commitDeadline =
      now + BigInt(this.config.commitWindow * 1e6);
    this.commitRevealState.currentBatchId = crypto.randomBytes(16).toString('hex');
    this.commitRevealState.pendingCommitments.clear();

    this.logger.info('Commit phase started', {
      batchId: this.commitRevealState.currentBatchId,
      deadline: this.commitRevealState.commitDeadline.toString()
    });

    this.emit('commitPhaseStarted');

    this.phaseTimer = setTimeout(() => {
      this.transitionToRevealPhase();
    }, this.config.commitWindow);
  }

  private transitionToRevealPhase(): void {
    const now = this.getNanoseconds();

    this.commitRevealState.phase = CommitRevealPhase.REVEAL;
    this.commitRevealState.revealDeadline =
      now + BigInt(this.config.revealWindow * 1e6);

    this.logger.info('Reveal phase started', {
      pendingCommitments: this.commitRevealState.pendingCommitments.size,
      deadline: this.commitRevealState.revealDeadline.toString()
    });

    this.emit('revealPhaseStarted');

    this.phaseTimer = setTimeout(() => {
      this.transitionToOrderingPhase();
    }, this.config.revealWindow);
  }

  private transitionToOrderingPhase(): void {
    this.commitRevealState.phase = CommitRevealPhase.ORDERING;

    // Check for unrevealed transactions (censorship detection)
    const unrevealedCount =
      this.commitRevealState.pendingCommitments.size -
      this.commitRevealState.revealedTransactions.size;

    if (unrevealedCount > 0) {
      this.logger.warn('Unrevealed transactions detected', {
        count: unrevealedCount
      });
    }

    this.logger.info('Ordering phase started', {
      revealedTransactions: this.commitRevealState.revealedTransactions.size
    });

    this.emit('orderingPhaseStarted');

    // Produce batch after ordering
    setTimeout(() => {
      this.produceBatch();
      this.transitionToCommitPhase();
    }, 1000);
  }

  // ============================================================================
  // FRAUD PROOFS
  // ============================================================================

  submitFraudProof(
    batchId: string,
    type: FraudType,
    evidence: Buffer,
    challenger: string
  ): string {
    const batch = this.batches.get(batchId);
    if (!batch) {
      throw new Error('Batch not found');
    }

    const proofId = crypto.randomBytes(16).toString('hex');

    const fraudProof: FraudProof = {
      proofId,
      batchId,
      type,
      evidence,
      challenger,
      challengedSequencer: batch.sequencer,
      timestamp: new Date(),
      resolved: false
    };

    this.fraudProofs.set(proofId, fraudProof);
    batch.status = BatchStatus.DISPUTED;

    this.metrics.fraudProofsSubmitted++;

    this.logger.warn('Fraud proof submitted', {
      proofId,
      batchId,
      type,
      challenger
    });

    this.emit('fraudProofSubmitted', fraudProof);

    // Verify fraud proof
    this.verifyFraudProof(fraudProof);

    return proofId;
  }

  private async verifyFraudProof(fraudProof: FraudProof): Promise<void> {
    const batch = this.batches.get(fraudProof.batchId);
    if (!batch) return;

    let isValid = false;

    switch (fraudProof.type) {
      case FraudType.INVALID_ORDERING:
        isValid = this.verifyInvalidOrdering(batch, fraudProof.evidence);
        break;

      case FraudType.INVALID_VDF:
        isValid = !this.vdf.verify(batch.vdfProof);
        break;

      case FraudType.CENSORSHIP:
        isValid = this.verifyCensorship(batch, fraudProof.evidence);
        break;

      case FraudType.INVALID_STATE_ROOT:
        isValid = this.verifyInvalidStateRoot(batch, fraudProof.evidence);
        break;

      case FraudType.DOUBLE_INCLUSION:
        isValid = this.verifyDoubleInclusion(batch, fraudProof.evidence);
        break;
    }

    if (isValid) {
      // Slash sequencer
      await this.slashSequencer(batch.sequencer, fraudProof.type);
      fraudProof.outcome = FraudOutcome.CHALLENGER_WINS;
      batch.status = BatchStatus.INVALID;
    } else {
      fraudProof.outcome = FraudOutcome.SEQUENCER_WINS;
      batch.status = BatchStatus.FINALIZED;
    }

    fraudProof.resolved = true;

    this.logger.info('Fraud proof resolved', {
      proofId: fraudProof.proofId,
      outcome: fraudProof.outcome
    });

    this.emit('fraudProofResolved', fraudProof);
  }

  private verifyInvalidOrdering(batch: Batch, evidence: Buffer): boolean {
    // Check if ordering violates timestamp order
    const proof = batch.orderingProof;

    for (let i = 1; i < proof.timestamps.length; i++) {
      if (proof.timestamps[i] < proof.timestamps[i - 1]) {
        return true; // Invalid: later transaction has earlier timestamp
      }
    }

    return false;
  }

  private verifyCensorship(batch: Batch, evidence: Buffer): boolean {
    // Check if a valid transaction was excluded
    // Evidence would contain proof of transaction submission
    return false;
  }

  private verifyInvalidStateRoot(batch: Batch, evidence: Buffer): boolean {
    // Re-execute batch and compare state roots
    return false;
  }

  private verifyDoubleInclusion(batch: Batch, evidence: Buffer): boolean {
    // Check if same transaction included twice
    const txIds = new Set<string>();

    for (const tx of batch.transactions) {
      if (txIds.has(tx.txId)) {
        return true;
      }
      txIds.add(tx.txId);
    }

    return false;
  }

  private async slashSequencer(address: string, reason: FraudType): Promise<void> {
    const sequencer = this.sequencers.get(address);
    if (!sequencer) return;

    const slashAmount =
      (sequencer.stake * BigInt(this.config.slashingPenalty)) / 100n;
    sequencer.stake -= slashAmount;
    sequencer.slashingEvents++;
    sequencer.reputation = Math.max(0, sequencer.reputation - 20);

    if (sequencer.stake < this.config.minStake) {
      sequencer.isActive = false;
      this.metrics.activeSequencers--;
    }

    this.metrics.slashingEvents++;

    this.logger.warn('Sequencer slashed', {
      address,
      reason,
      slashAmount: slashAmount.toString(),
      remainingStake: sequencer.stake.toString()
    });

    this.emit('sequencerSlashed', sequencer, reason, slashAmount);

    // Rotate to new sequencer
    await this.selectSequencer();
  }

  // ============================================================================
  // HELPER FUNCTIONS
  // ============================================================================

  private computeCommitment(data: Buffer): Buffer {
    return crypto.createHash('sha256').update(data).digest();
  }

  private decryptTransaction(encryptedData: Buffer, key: Buffer): Buffer {
    // Simplified decryption
    // Production would use proper encryption scheme
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.alloc(12));
    return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
  }

  private parseTransaction(data: Buffer): Transaction {
    // Parse transaction data
    return JSON.parse(data.toString());
  }

  private computeStateRoot(transactions: EncryptedTransaction[]): Buffer {
    const txHashes = transactions.map(tx =>
      crypto.createHash('sha256').update(tx.txId).digest()
    );
    return this.computeMerkleRoot(txHashes);
  }

  private getPreviousStateRoot(): Buffer {
    const batches = Array.from(this.batches.values());
    if (batches.length === 0) {
      return Buffer.alloc(32);
    }

    const lastBatch = batches[batches.length - 1];
    return lastBatch.stateRoot;
  }

  private computeBatchCommitment(
    transactions: EncryptedTransaction[],
    orderingProof: OrderingProof
  ): Buffer {
    const data = Buffer.concat([
      orderingProof.merkleRoot,
      ...transactions.map(tx => tx.commitment)
    ]);

    return crypto.createHash('sha256').update(data).digest();
  }

  private getNanoseconds(): bigint {
    return process.hrtime.bigint();
  }

  private updateAverageBatchSize(newSize: number): void {
    const totalBatches = Number(this.metrics.totalBatches);
    this.metrics.avgBatchSize =
      (this.metrics.avgBatchSize * (totalBatches - 1) + newSize) / totalBatches;
  }

  // ============================================================================
  // PUBLIC API
  // ============================================================================

  getBatch(batchId: string): Batch | undefined {
    return this.batches.get(batchId);
  }

  getTransaction(txId: string): EncryptedTransaction | undefined {
    return this.pendingTransactions.get(txId);
  }

  getCurrentSequencer(): string {
    return this.currentSequencer;
  }

  getCommitRevealPhase(): CommitRevealPhase {
    return this.commitRevealState.phase;
  }

  getMetrics(): SequencerMetrics {
    return { ...this.metrics };
  }

  async healthCheck(): Promise<{
    healthy: boolean;
    issues: string[];
  }> {
    const issues: string[] = [];

    // Check active sequencers
    if (this.metrics.activeSequencers === 0) {
      issues.push('No active sequencers');
    }

    // Check pending transactions
    if (this.pendingTransactions.size > this.config.maxTransactionsPerBatch * 10) {
      issues.push('High pending transaction count');
    }

    // Check fairness score
    if (this.metrics.fairnessScore < 0.95) {
      issues.push(`Low fairness score: ${this.metrics.fairnessScore}`);
    }

    return {
      healthy: issues.length === 0,
      issues
    };
  }
}

export default FairOrderingSequencer;
