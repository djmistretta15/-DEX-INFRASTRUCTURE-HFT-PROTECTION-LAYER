import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import * as zlib from 'zlib';

/**
 * ORDER BOOK SNAPSHOT AND RECOVERY SYSTEM
 *
 * HYPOTHESIS: Incremental snapshots with write-ahead logging and point-in-time
 * recovery will ensure zero data loss with recovery time <30 seconds and
 * <100MB storage overhead per trading day.
 *
 * SUCCESS METRICS:
 * - Recovery time objective (RTO) <30 seconds
 * - Recovery point objective (RPO) <1 second
 * - Zero data loss during crashes
 * - Storage efficiency <100MB per day
 * - Snapshot creation overhead <1ms
 *
 * SECURITY CONSIDERATIONS:
 * - Cryptographic verification of snapshot integrity
 * - Tamper-evident write-ahead log
 * - Atomic snapshot operations
 * - Secure storage with encryption at rest
 * - Audit trail for all recovery operations
 */

// Snapshot types
enum SnapshotType {
  FULL = 'full',
  INCREMENTAL = 'incremental',
  DIFFERENTIAL = 'differential'
}

// Recovery mode
enum RecoveryMode {
  POINT_IN_TIME = 'point_in_time',
  LATEST = 'latest',
  SPECIFIC_SNAPSHOT = 'specific_snapshot'
}

// Order book entry
interface OrderBookEntry {
  orderId: string;
  userId: string;
  side: 'buy' | 'sell';
  price: bigint;
  quantity: bigint;
  remainingQuantity: bigint;
  timestamp: bigint;
  orderType: string;
  status: string;
}

// Price level
interface PriceLevel {
  price: bigint;
  totalQuantity: bigint;
  orderCount: number;
  orders: Map<string, OrderBookEntry>;
}

// Order book state
interface OrderBookState {
  symbol: string;
  bids: Map<bigint, PriceLevel>;
  asks: Map<bigint, PriceLevel>;
  lastTradePrice: bigint;
  lastTradeTime: bigint;
  volume24h: bigint;
  sequenceNumber: bigint;
}

// Snapshot metadata
interface SnapshotMetadata {
  id: string;
  type: SnapshotType;
  timestamp: Date;
  sequenceNumber: bigint;
  symbol: string;
  baseSnapshotId?: string; // For incremental/differential
  checksum: string;
  compressedSize: number;
  originalSize: number;
  entryCount: number;
}

// Write-ahead log entry
interface WALEntry {
  sequenceNumber: bigint;
  timestamp: bigint;
  operation: WALOperation;
  data: any;
  checksum: string;
}

enum WALOperation {
  ORDER_ADD = 'order_add',
  ORDER_CANCEL = 'order_cancel',
  ORDER_MODIFY = 'order_modify',
  ORDER_FILL = 'order_fill',
  TRADE = 'trade',
  PRICE_LEVEL_UPDATE = 'price_level_update'
}

// Recovery checkpoint
interface RecoveryCheckpoint {
  snapshotId: string;
  walSequenceStart: bigint;
  walSequenceEnd: bigint;
  timestamp: Date;
  verified: boolean;
}

// Configuration
interface RecoveryConfig {
  snapshotIntervalMs: number;
  fullSnapshotIntervalMs: number;
  maxIncrementalSnapshots: number;
  walBufferSize: number;
  compressionLevel: number;
  checksumAlgorithm: 'sha256' | 'sha512' | 'xxhash';
  encryptSnapshots: boolean;
  retentionDays: number;
}

/**
 * Write-Ahead Log for durability
 */
class WriteAheadLog extends EventEmitter {
  private entries: WALEntry[] = [];
  private currentSequence: bigint = 0n;
  private bufferSize: number;
  private flushedSequence: bigint = 0n;

  constructor(bufferSize: number) {
    super();
    this.bufferSize = bufferSize;
  }

  /**
   * Append entry to WAL
   */
  append(operation: WALOperation, data: any): bigint {
    const sequenceNumber = this.currentSequence++;

    const entry: WALEntry = {
      sequenceNumber,
      timestamp: this.getNanoseconds(),
      operation,
      data,
      checksum: this.computeChecksum(sequenceNumber, operation, data)
    };

    this.entries.push(entry);

    // Check if we need to flush
    if (this.entries.length >= this.bufferSize) {
      this.flush();
    }

    this.emit('entryAppended', entry);
    return sequenceNumber;
  }

  /**
   * Flush WAL to persistent storage
   */
  flush(): void {
    const toFlush = this.entries.filter(e => e.sequenceNumber > this.flushedSequence);

    if (toFlush.length === 0) return;

    // In production, would write to disk/network storage
    this.flushedSequence = toFlush[toFlush.length - 1].sequenceNumber;

    this.emit('flushed', {
      entriesCount: toFlush.length,
      lastSequence: this.flushedSequence
    });
  }

  /**
   * Get entries since sequence number
   */
  getEntriesSince(sequenceNumber: bigint): WALEntry[] {
    return this.entries.filter(e => e.sequenceNumber > sequenceNumber);
  }

  /**
   * Verify WAL integrity
   */
  verifyIntegrity(): { valid: boolean; brokenAt?: bigint } {
    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];

      // Verify checksum
      const expectedChecksum = this.computeChecksum(
        entry.sequenceNumber,
        entry.operation,
        entry.data
      );

      if (expectedChecksum !== entry.checksum) {
        return { valid: false, brokenAt: entry.sequenceNumber };
      }

      // Verify sequence continuity
      if (i > 0 && entry.sequenceNumber !== this.entries[i - 1].sequenceNumber + 1n) {
        return { valid: false, brokenAt: entry.sequenceNumber };
      }
    }

    return { valid: true };
  }

  /**
   * Truncate WAL up to sequence number (after snapshot)
   */
  truncate(upToSequence: bigint): void {
    this.entries = this.entries.filter(e => e.sequenceNumber > upToSequence);
    this.emit('truncated', { upToSequence });
  }

  /**
   * Get current sequence number
   */
  getCurrentSequence(): bigint {
    return this.currentSequence;
  }

  private computeChecksum(sequence: bigint, operation: WALOperation, data: any): string {
    const content = JSON.stringify({ sequence: sequence.toString(), operation, data });
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  private getNanoseconds(): bigint {
    const [seconds, nanoseconds] = process.hrtime();
    return BigInt(seconds) * 1000000000n + BigInt(nanoseconds);
  }
}

/**
 * Snapshot manager for order book state
 */
class SnapshotManager extends EventEmitter {
  private snapshots: Map<string, { metadata: SnapshotMetadata; data: Buffer }> = new Map();
  private config: RecoveryConfig;
  private encryptionKey?: Buffer;

  constructor(config: RecoveryConfig, encryptionKey?: Buffer) {
    super();
    this.config = config;
    this.encryptionKey = encryptionKey;
  }

  /**
   * Create full snapshot of order book
   */
  createFullSnapshot(state: OrderBookState): SnapshotMetadata {
    const serialized = this.serializeState(state);
    const compressed = this.compress(serialized);

    let finalData = compressed;
    if (this.config.encryptSnapshots && this.encryptionKey) {
      finalData = this.encrypt(compressed);
    }

    const checksum = this.computeChecksum(finalData);

    const metadata: SnapshotMetadata = {
      id: crypto.randomBytes(16).toString('hex'),
      type: SnapshotType.FULL,
      timestamp: new Date(),
      sequenceNumber: state.sequenceNumber,
      symbol: state.symbol,
      checksum,
      compressedSize: finalData.length,
      originalSize: serialized.length,
      entryCount: this.countEntries(state)
    };

    this.snapshots.set(metadata.id, { metadata, data: finalData });
    this.emit('snapshotCreated', metadata);

    return metadata;
  }

  /**
   * Create incremental snapshot (changes since last snapshot)
   */
  createIncrementalSnapshot(
    state: OrderBookState,
    baseSnapshotId: string,
    changes: WALEntry[]
  ): SnapshotMetadata {
    const changeData = {
      baseSnapshotId,
      changes: changes.map(e => ({
        ...e,
        sequenceNumber: e.sequenceNumber.toString(),
        timestamp: e.timestamp.toString()
      }))
    };

    const serialized = Buffer.from(JSON.stringify(changeData));
    const compressed = this.compress(serialized);

    let finalData = compressed;
    if (this.config.encryptSnapshots && this.encryptionKey) {
      finalData = this.encrypt(compressed);
    }

    const checksum = this.computeChecksum(finalData);

    const metadata: SnapshotMetadata = {
      id: crypto.randomBytes(16).toString('hex'),
      type: SnapshotType.INCREMENTAL,
      timestamp: new Date(),
      sequenceNumber: state.sequenceNumber,
      symbol: state.symbol,
      baseSnapshotId,
      checksum,
      compressedSize: finalData.length,
      originalSize: serialized.length,
      entryCount: changes.length
    };

    this.snapshots.set(metadata.id, { metadata, data: finalData });
    this.emit('snapshotCreated', metadata);

    return metadata;
  }

  /**
   * Restore state from snapshot
   */
  restoreFromSnapshot(snapshotId: string): OrderBookState | null {
    const snapshot = this.snapshots.get(snapshotId);
    if (!snapshot) return null;

    // Verify checksum
    const currentChecksum = this.computeChecksum(snapshot.data);
    if (currentChecksum !== snapshot.metadata.checksum) {
      this.emit('corruptSnapshot', { snapshotId, expected: snapshot.metadata.checksum, actual: currentChecksum });
      return null;
    }

    let data = snapshot.data;
    if (this.config.encryptSnapshots && this.encryptionKey) {
      data = this.decrypt(data);
    }

    const decompressed = this.decompress(data);

    if (snapshot.metadata.type === SnapshotType.FULL) {
      return this.deserializeState(decompressed);
    } else {
      // For incremental, need to apply to base snapshot
      const changeData = JSON.parse(decompressed.toString());
      const baseState = this.restoreFromSnapshot(changeData.baseSnapshotId);

      if (!baseState) return null;

      // Apply changes
      for (const change of changeData.changes) {
        this.applyChange(baseState, change);
      }

      return baseState;
    }
  }

  /**
   * Get snapshot metadata list
   */
  getSnapshots(): SnapshotMetadata[] {
    return Array.from(this.snapshots.values()).map(s => s.metadata);
  }

  /**
   * Delete old snapshots based on retention policy
   */
  cleanupOldSnapshots(): number {
    const cutoff = Date.now() - this.config.retentionDays * 24 * 60 * 60 * 1000;
    let deleted = 0;

    for (const [id, snapshot] of this.snapshots) {
      if (snapshot.metadata.timestamp.getTime() < cutoff) {
        this.snapshots.delete(id);
        deleted++;
      }
    }

    this.emit('cleanup', { deletedCount: deleted });
    return deleted;
  }

  /**
   * Verify snapshot integrity
   */
  verifySnapshot(snapshotId: string): boolean {
    const snapshot = this.snapshots.get(snapshotId);
    if (!snapshot) return false;

    const currentChecksum = this.computeChecksum(snapshot.data);
    return currentChecksum === snapshot.metadata.checksum;
  }

  private serializeState(state: OrderBookState): Buffer {
    const serializable = {
      symbol: state.symbol,
      bids: this.serializePriceLevels(state.bids),
      asks: this.serializePriceLevels(state.asks),
      lastTradePrice: state.lastTradePrice.toString(),
      lastTradeTime: state.lastTradeTime.toString(),
      volume24h: state.volume24h.toString(),
      sequenceNumber: state.sequenceNumber.toString()
    };

    return Buffer.from(JSON.stringify(serializable));
  }

  private deserializeState(data: Buffer): OrderBookState {
    const parsed = JSON.parse(data.toString());

    return {
      symbol: parsed.symbol,
      bids: this.deserializePriceLevels(parsed.bids),
      asks: this.deserializePriceLevels(parsed.asks),
      lastTradePrice: BigInt(parsed.lastTradePrice),
      lastTradeTime: BigInt(parsed.lastTradeTime),
      volume24h: BigInt(parsed.volume24h),
      sequenceNumber: BigInt(parsed.sequenceNumber)
    };
  }

  private serializePriceLevels(levels: Map<bigint, PriceLevel>): any[] {
    const result: any[] = [];

    for (const [price, level] of levels) {
      const orders: any[] = [];
      for (const [orderId, order] of level.orders) {
        orders.push({
          ...order,
          price: order.price.toString(),
          quantity: order.quantity.toString(),
          remainingQuantity: order.remainingQuantity.toString(),
          timestamp: order.timestamp.toString()
        });
      }

      result.push({
        price: price.toString(),
        totalQuantity: level.totalQuantity.toString(),
        orderCount: level.orderCount,
        orders
      });
    }

    return result;
  }

  private deserializePriceLevels(data: any[]): Map<bigint, PriceLevel> {
    const levels = new Map<bigint, PriceLevel>();

    for (const levelData of data) {
      const orders = new Map<string, OrderBookEntry>();

      for (const orderData of levelData.orders) {
        orders.set(orderData.orderId, {
          ...orderData,
          price: BigInt(orderData.price),
          quantity: BigInt(orderData.quantity),
          remainingQuantity: BigInt(orderData.remainingQuantity),
          timestamp: BigInt(orderData.timestamp)
        });
      }

      levels.set(BigInt(levelData.price), {
        price: BigInt(levelData.price),
        totalQuantity: BigInt(levelData.totalQuantity),
        orderCount: levelData.orderCount,
        orders
      });
    }

    return levels;
  }

  private applyChange(state: OrderBookState, change: any): void {
    const operation = change.operation as WALOperation;

    switch (operation) {
      case WALOperation.ORDER_ADD:
        this.applyOrderAdd(state, change.data);
        break;
      case WALOperation.ORDER_CANCEL:
        this.applyOrderCancel(state, change.data);
        break;
      case WALOperation.ORDER_FILL:
        this.applyOrderFill(state, change.data);
        break;
      case WALOperation.TRADE:
        this.applyTrade(state, change.data);
        break;
    }

    state.sequenceNumber = BigInt(change.sequenceNumber);
  }

  private applyOrderAdd(state: OrderBookState, data: any): void {
    const order: OrderBookEntry = {
      ...data,
      price: BigInt(data.price),
      quantity: BigInt(data.quantity),
      remainingQuantity: BigInt(data.remainingQuantity),
      timestamp: BigInt(data.timestamp)
    };

    const levels = order.side === 'buy' ? state.bids : state.asks;

    if (!levels.has(order.price)) {
      levels.set(order.price, {
        price: order.price,
        totalQuantity: 0n,
        orderCount: 0,
        orders: new Map()
      });
    }

    const level = levels.get(order.price)!;
    level.orders.set(order.orderId, order);
    level.totalQuantity += order.remainingQuantity;
    level.orderCount++;
  }

  private applyOrderCancel(state: OrderBookState, data: any): void {
    const { orderId, side, price } = data;
    const priceBI = BigInt(price);
    const levels = side === 'buy' ? state.bids : state.asks;

    const level = levels.get(priceBI);
    if (level && level.orders.has(orderId)) {
      const order = level.orders.get(orderId)!;
      level.totalQuantity -= order.remainingQuantity;
      level.orderCount--;
      level.orders.delete(orderId);

      if (level.orderCount === 0) {
        levels.delete(priceBI);
      }
    }
  }

  private applyOrderFill(state: OrderBookState, data: any): void {
    const { orderId, side, price, filledQuantity } = data;
    const priceBI = BigInt(price);
    const filledQty = BigInt(filledQuantity);
    const levels = side === 'buy' ? state.bids : state.asks;

    const level = levels.get(priceBI);
    if (level && level.orders.has(orderId)) {
      const order = level.orders.get(orderId)!;
      order.remainingQuantity -= filledQty;
      level.totalQuantity -= filledQty;

      if (order.remainingQuantity === 0n) {
        level.orders.delete(orderId);
        level.orderCount--;

        if (level.orderCount === 0) {
          levels.delete(priceBI);
        }
      }
    }
  }

  private applyTrade(state: OrderBookState, data: any): void {
    state.lastTradePrice = BigInt(data.price);
    state.lastTradeTime = BigInt(data.timestamp);
    state.volume24h += BigInt(data.quantity);
  }

  private countEntries(state: OrderBookState): number {
    let count = 0;
    for (const level of state.bids.values()) {
      count += level.orderCount;
    }
    for (const level of state.asks.values()) {
      count += level.orderCount;
    }
    return count;
  }

  private compress(data: Buffer): Buffer {
    return zlib.deflateSync(data, { level: this.config.compressionLevel });
  }

  private decompress(data: Buffer): Buffer {
    return zlib.inflateSync(data);
  }

  private encrypt(data: Buffer): Buffer {
    if (!this.encryptionKey) return data;

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encryptionKey, iv);

    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Prepend IV and auth tag
    return Buffer.concat([iv, authTag, encrypted]);
  }

  private decrypt(data: Buffer): Buffer {
    if (!this.encryptionKey) return data;

    const iv = data.subarray(0, 16);
    const authTag = data.subarray(16, 32);
    const encrypted = data.subarray(32);

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }

  private computeChecksum(data: Buffer): string {
    return crypto.createHash(this.config.checksumAlgorithm).update(data).digest('hex');
  }
}

/**
 * Main Recovery Manager
 */
export class OrderBookRecoverySystem extends EventEmitter {
  private config: RecoveryConfig;
  private wal: WriteAheadLog;
  private snapshotManager: SnapshotManager;
  private currentState: OrderBookState | null = null;
  private lastFullSnapshotId: string | null = null;
  private lastSnapshotTime: Date | null = null;
  private incrementalSinceLastFull: number = 0;
  private checkpoints: RecoveryCheckpoint[] = [];
  private snapshotTimer?: NodeJS.Timer;

  constructor(config: RecoveryConfig, encryptionKey?: Buffer) {
    super();
    this.config = config;
    this.wal = new WriteAheadLog(config.walBufferSize);
    this.snapshotManager = new SnapshotManager(config, encryptionKey);

    // Wire up events
    this.wal.on('entryAppended', entry => this.emit('walEntry', entry));
    this.snapshotManager.on('snapshotCreated', meta => this.emit('snapshotCreated', meta));
  }

  /**
   * Initialize with order book state
   */
  initialize(state: OrderBookState): void {
    this.currentState = state;

    // Create initial full snapshot
    const metadata = this.snapshotManager.createFullSnapshot(state);
    this.lastFullSnapshotId = metadata.id;
    this.lastSnapshotTime = new Date();

    this.createCheckpoint(metadata.id);

    // Start automatic snapshot timer
    this.startSnapshotTimer();

    this.emit('initialized', { state: state.symbol, snapshotId: metadata.id });
  }

  /**
   * Log an order book operation (call this for every change)
   */
  logOperation(operation: WALOperation, data: any): bigint {
    const sequence = this.wal.append(operation, data);

    // Apply to current state (if maintained)
    if (this.currentState) {
      this.snapshotManager['applyChange'](this.currentState, {
        sequenceNumber: sequence.toString(),
        operation,
        data
      });
    }

    return sequence;
  }

  /**
   * Create a snapshot (automatic based on config)
   */
  createSnapshot(): SnapshotMetadata | null {
    if (!this.currentState || !this.lastFullSnapshotId) return null;

    let metadata: SnapshotMetadata;

    // Decide snapshot type
    const shouldCreateFull =
      !this.lastSnapshotTime ||
      Date.now() - this.lastSnapshotTime.getTime() >= this.config.fullSnapshotIntervalMs ||
      this.incrementalSinceLastFull >= this.config.maxIncrementalSnapshots;

    if (shouldCreateFull) {
      metadata = this.snapshotManager.createFullSnapshot(this.currentState);
      this.lastFullSnapshotId = metadata.id;
      this.incrementalSinceLastFull = 0;

      // Truncate WAL up to snapshot sequence
      this.wal.truncate(metadata.sequenceNumber);
    } else {
      // Get changes since last snapshot
      const lastSnapshot = this.checkpoints[this.checkpoints.length - 1];
      const changes = this.wal.getEntriesSince(lastSnapshot.walSequenceEnd);

      metadata = this.snapshotManager.createIncrementalSnapshot(
        this.currentState,
        this.lastFullSnapshotId,
        changes
      );
      this.incrementalSinceLastFull++;
    }

    this.lastSnapshotTime = new Date();
    this.createCheckpoint(metadata.id);

    return metadata;
  }

  /**
   * Recover state to latest consistent point
   */
  recoverToLatest(): OrderBookState | null {
    const snapshots = this.snapshotManager.getSnapshots();
    if (snapshots.length === 0) return null;

    // Find latest full snapshot
    const fullSnapshots = snapshots.filter(s => s.type === SnapshotType.FULL);
    if (fullSnapshots.length === 0) return null;

    const latestFull = fullSnapshots.sort((a, b) =>
      b.timestamp.getTime() - a.timestamp.getTime()
    )[0];

    // Restore from full snapshot
    const state = this.snapshotManager.restoreFromSnapshot(latestFull.id);
    if (!state) return null;

    // Apply WAL entries after snapshot
    const walEntries = this.wal.getEntriesSince(latestFull.sequenceNumber);

    for (const entry of walEntries) {
      this.snapshotManager['applyChange'](state, entry);
    }

    this.currentState = state;
    this.emit('recovered', {
      snapshotId: latestFull.id,
      walEntriesApplied: walEntries.length,
      finalSequence: state.sequenceNumber
    });

    return state;
  }

  /**
   * Recover to specific point in time
   */
  recoverToPointInTime(timestamp: Date): OrderBookState | null {
    const snapshots = this.snapshotManager.getSnapshots();

    // Find snapshot just before the timestamp
    const candidateSnapshots = snapshots
      .filter(s => s.timestamp.getTime() <= timestamp.getTime())
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    if (candidateSnapshots.length === 0) return null;

    // Find nearest full snapshot
    let baseSnapshot = candidateSnapshots.find(s => s.type === SnapshotType.FULL);
    if (!baseSnapshot) return null;

    const state = this.snapshotManager.restoreFromSnapshot(baseSnapshot.id);
    if (!state) return null;

    // Apply WAL entries up to the timestamp
    const walEntries = this.wal.getEntriesSince(baseSnapshot.sequenceNumber);
    const targetNanos = BigInt(timestamp.getTime()) * 1000000n;

    for (const entry of walEntries) {
      if (entry.timestamp > targetNanos) break;
      this.snapshotManager['applyChange'](state, entry);
    }

    this.emit('recoveredToPointInTime', {
      targetTime: timestamp,
      snapshotId: baseSnapshot.id,
      finalSequence: state.sequenceNumber
    });

    return state;
  }

  /**
   * Recover to specific snapshot
   */
  recoverToSnapshot(snapshotId: string): OrderBookState | null {
    const state = this.snapshotManager.restoreFromSnapshot(snapshotId);

    if (state) {
      this.currentState = state;
      this.emit('recoveredToSnapshot', { snapshotId, sequence: state.sequenceNumber });
    }

    return state;
  }

  /**
   * Verify system integrity
   */
  verifyIntegrity(): {
    walValid: boolean;
    snapshotsValid: boolean;
    checkpointsValid: boolean;
    issues: string[];
  } {
    const issues: string[] = [];

    // Verify WAL
    const walCheck = this.wal.verifyIntegrity();
    if (!walCheck.valid) {
      issues.push(`WAL integrity broken at sequence ${walCheck.brokenAt}`);
    }

    // Verify snapshots
    let allSnapshotsValid = true;
    for (const snapshot of this.snapshotManager.getSnapshots()) {
      if (!this.snapshotManager.verifySnapshot(snapshot.id)) {
        issues.push(`Snapshot ${snapshot.id} is corrupted`);
        allSnapshotsValid = false;
      }
    }

    // Verify checkpoints
    let checkpointsValid = true;
    for (const checkpoint of this.checkpoints) {
      if (!this.snapshotManager.verifySnapshot(checkpoint.snapshotId)) {
        issues.push(`Checkpoint snapshot ${checkpoint.snapshotId} invalid`);
        checkpointsValid = false;
      }
    }

    return {
      walValid: walCheck.valid,
      snapshotsValid: allSnapshotsValid,
      checkpointsValid,
      issues
    };
  }

  /**
   * Get recovery statistics
   */
  getStatistics(): {
    totalSnapshots: number;
    fullSnapshots: number;
    incrementalSnapshots: number;
    walEntries: number;
    totalStorageSize: number;
    checkpoints: number;
    lastSnapshotAge: number;
  } {
    const snapshots = this.snapshotManager.getSnapshots();
    const fullSnapshots = snapshots.filter(s => s.type === SnapshotType.FULL).length;

    const totalStorageSize = snapshots.reduce((sum, s) => sum + s.compressedSize, 0);

    const lastSnapshotAge = this.lastSnapshotTime
      ? Date.now() - this.lastSnapshotTime.getTime()
      : -1;

    return {
      totalSnapshots: snapshots.length,
      fullSnapshots,
      incrementalSnapshots: snapshots.length - fullSnapshots,
      walEntries: Number(this.wal.getCurrentSequence()),
      totalStorageSize,
      checkpoints: this.checkpoints.length,
      lastSnapshotAge
    };
  }

  /**
   * Export recovery state for backup
   */
  exportState(): {
    snapshots: SnapshotMetadata[];
    checkpoints: RecoveryCheckpoint[];
    walSequence: string;
  } {
    return {
      snapshots: this.snapshotManager.getSnapshots(),
      checkpoints: this.checkpoints,
      walSequence: this.wal.getCurrentSequence().toString()
    };
  }

  /**
   * Stop automatic snapshots
   */
  stop(): void {
    if (this.snapshotTimer) {
      clearInterval(this.snapshotTimer);
      this.snapshotTimer = undefined;
    }

    // Final snapshot before stop
    this.createSnapshot();

    // Flush WAL
    this.wal.flush();

    this.emit('stopped');
  }

  private createCheckpoint(snapshotId: string): void {
    const checkpoint: RecoveryCheckpoint = {
      snapshotId,
      walSequenceStart: this.checkpoints.length > 0
        ? this.checkpoints[this.checkpoints.length - 1].walSequenceEnd
        : 0n,
      walSequenceEnd: this.wal.getCurrentSequence(),
      timestamp: new Date(),
      verified: true
    };

    this.checkpoints.push(checkpoint);
    this.emit('checkpointCreated', checkpoint);

    // Keep only recent checkpoints
    if (this.checkpoints.length > 100) {
      this.checkpoints = this.checkpoints.slice(-100);
    }
  }

  private startSnapshotTimer(): void {
    this.snapshotTimer = setInterval(() => {
      this.createSnapshot();
    }, this.config.snapshotIntervalMs);
  }
}

// Export components
export {
  SnapshotType,
  RecoveryMode,
  WALOperation,
  OrderBookState,
  SnapshotMetadata,
  RecoveryCheckpoint,
  WriteAheadLog,
  SnapshotManager
};

// Default configuration
export const defaultRecoveryConfig: RecoveryConfig = {
  snapshotIntervalMs: 60000, // 1 minute
  fullSnapshotIntervalMs: 3600000, // 1 hour
  maxIncrementalSnapshots: 60,
  walBufferSize: 10000,
  compressionLevel: 6,
  checksumAlgorithm: 'sha256',
  encryptSnapshots: true,
  retentionDays: 30
};
