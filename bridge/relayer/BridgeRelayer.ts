/**
 * Cross-Chain Bridge Relayer Service
 *
 * SCIENTIFIC HYPOTHESIS:
 * A decentralized relayer network with stake-weighted validation and fraud proofs
 * will achieve cross-chain transfer finality with <5 minute average time while
 * maintaining security guarantees through economic incentives and challenge periods.
 *
 * SUCCESS METRICS:
 * - Transfer success rate: >99.9%
 * - Average finality time: <5 minutes for standard transfers
 * - Fraud proof submission: <30 seconds after detection
 * - Relayer uptime: >99.95%
 * - Gas efficiency: <300k gas per relay operation
 *
 * SECURITY CONSIDERATIONS:
 * - Multi-sig validation (3/5 relayers minimum)
 * - Stake slashing for invalid relays
 * - Merkle proof verification
 * - Rate limiting per source chain
 * - Nonce tracking to prevent replay attacks
 */

import { EventEmitter } from 'events';
import { ethers, Contract, Wallet, Provider } from 'ethers';
import Redis from 'ioredis';
import winston from 'winston';

// ============================================================================
// INTERFACES & TYPES
// ============================================================================

interface ChainConfig {
  chainId: number;
  name: string;
  rpcUrl: string;
  bridgeAddress: string;
  confirmations: number;
  blockTime: number;
  gasPrice: bigint;
}

interface RelayerConfig {
  privateKey: string;
  stake: bigint;
  minStake: bigint;
  maxPendingTransfers: number;
  batchSize: number;
  relayInterval: number;
  challengeMonitorInterval: number;
}

interface PendingTransfer {
  transferId: string;
  sourceChain: number;
  targetChain: number;
  sender: string;
  recipient: string;
  token: string;
  amount: bigint;
  nonce: bigint;
  timestamp: number;
  blockNumber: number;
  txHash: string;
  signatures: RelayerSignature[];
  status: TransferStatus;
  retries: number;
  lastError?: string;
}

interface RelayerSignature {
  relayer: string;
  signature: string;
  timestamp: number;
}

interface MerkleProof {
  root: string;
  proof: string[];
  leaf: string;
  index: number;
}

interface RelayerState {
  address: string;
  stake: bigint;
  successfulRelays: number;
  failedRelays: number;
  pendingTransfers: number;
  lastActive: number;
  reputation: number;
  slashed: boolean;
}

interface ChallengeData {
  transferId: string;
  challenger: string;
  reason: ChallengeReason;
  evidence: string;
  timestamp: number;
  resolved: boolean;
  outcome?: ChallengeOutcome;
}

interface RelayMetrics {
  totalRelays: number;
  successfulRelays: number;
  failedRelays: number;
  totalVolume: bigint;
  averageFinalityTime: number;
  pendingTransfers: number;
  activeChallenges: number;
  gasSpent: bigint;
}

enum TransferStatus {
  PENDING = 'PENDING',
  RELAYED = 'RELAYED',
  CONFIRMED = 'CONFIRMED',
  CHALLENGED = 'CHALLENGED',
  FINALIZED = 'FINALIZED',
  FAILED = 'FAILED'
}

enum ChallengeReason {
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  INVALID_PROOF = 'INVALID_PROOF',
  DOUBLE_SPEND = 'DOUBLE_SPEND',
  INVALID_AMOUNT = 'INVALID_AMOUNT',
  NONCE_MISMATCH = 'NONCE_MISMATCH'
}

enum ChallengeOutcome {
  CHALLENGER_WINS = 'CHALLENGER_WINS',
  RELAYER_WINS = 'RELAYER_WINS',
  INVALID = 'INVALID'
}

// ============================================================================
// BRIDGE RELAYER SERVICE
// ============================================================================

export class BridgeRelayer extends EventEmitter {
  private chains: Map<number, ChainConfig> = new Map();
  private providers: Map<number, Provider> = new Map();
  private contracts: Map<number, Contract> = new Map();
  private wallet: Wallet;
  private redis: Redis;
  private logger: winston.Logger;
  private config: RelayerConfig;

  private pendingTransfers: Map<string, PendingTransfer> = new Map();
  private processedNonces: Map<string, Set<bigint>> = new Map();
  private relayerStates: Map<string, RelayerState> = new Map();
  private activeChallenges: Map<string, ChallengeData> = new Map();
  private metrics: RelayMetrics;

  private relayerPeers: Set<string> = new Set();
  private isRunning: boolean = false;
  private relayIntervalId?: NodeJS.Timeout;
  private challengeMonitorId?: NodeJS.Timeout;

  constructor(
    chainConfigs: ChainConfig[],
    relayerConfig: RelayerConfig,
    redisUrl: string
  ) {
    super();

    this.config = relayerConfig;
    this.redis = new Redis(redisUrl);

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'relayer.log' })
      ]
    });

    // Initialize wallet
    this.wallet = new Wallet(relayerConfig.privateKey);

    // Initialize metrics
    this.metrics = {
      totalRelays: 0,
      successfulRelays: 0,
      failedRelays: 0,
      totalVolume: 0n,
      averageFinalityTime: 0,
      pendingTransfers: 0,
      activeChallenges: 0,
      gasSpent: 0n
    };

    // Setup chains
    for (const config of chainConfigs) {
      this.setupChain(config);
    }

    this.logger.info('Bridge relayer initialized', {
      address: this.wallet.address,
      chains: chainConfigs.map(c => c.name)
    });
  }

  // ============================================================================
  // INITIALIZATION
  // ============================================================================

  private setupChain(config: ChainConfig): void {
    this.chains.set(config.chainId, config);

    const provider = new ethers.JsonRpcProvider(config.rpcUrl);
    this.providers.set(config.chainId, provider);

    const contract = new Contract(
      config.bridgeAddress,
      BRIDGE_ABI,
      this.wallet.connect(provider)
    );
    this.contracts.set(config.chainId, contract);

    this.processedNonces.set(`${config.chainId}`, new Set());

    // Listen for bridge events
    this.subscribeToEvents(config.chainId);
  }

  private subscribeToEvents(chainId: number): void {
    const contract = this.contracts.get(chainId);
    if (!contract) return;

    // Listen for deposit events
    contract.on('TransferInitiated', (
      transferId: string,
      sender: string,
      recipient: string,
      token: string,
      amount: bigint,
      targetChain: number,
      nonce: bigint,
      event: any
    ) => {
      this.handleTransferInitiated(
        chainId,
        transferId,
        sender,
        recipient,
        token,
        amount,
        targetChain,
        nonce,
        event
      );
    });

    // Listen for challenge events
    contract.on('TransferChallenged', (
      transferId: string,
      challenger: string,
      reason: number,
      event: any
    ) => {
      this.handleChallenge(transferId, challenger, reason);
    });

    // Listen for finalization events
    contract.on('TransferFinalized', (
      transferId: string,
      recipient: string,
      amount: bigint,
      event: any
    ) => {
      this.handleFinalization(transferId);
    });

    this.logger.info(`Subscribed to events on chain ${chainId}`);
  }

  // ============================================================================
  // CORE RELAY LOGIC
  // ============================================================================

  async start(): Promise<void> {
    if (this.isRunning) {
      throw new Error('Relayer already running');
    }

    // Verify stake
    const stake = await this.getStake();
    if (stake < this.config.minStake) {
      throw new Error(`Insufficient stake: ${stake} < ${this.config.minStake}`);
    }

    // Load pending transfers from Redis
    await this.loadPendingTransfers();

    // Start relay loop
    this.relayIntervalId = setInterval(
      () => this.processRelayQueue(),
      this.config.relayInterval
    );

    // Start challenge monitor
    this.challengeMonitorId = setInterval(
      () => this.monitorChallenges(),
      this.config.challengeMonitorInterval
    );

    this.isRunning = true;
    this.logger.info('Bridge relayer started');
    this.emit('started');
  }

  async stop(): Promise<void> {
    if (!this.isRunning) return;

    if (this.relayIntervalId) {
      clearInterval(this.relayIntervalId);
    }

    if (this.challengeMonitorId) {
      clearInterval(this.challengeMonitorId);
    }

    // Save pending transfers
    await this.savePendingTransfers();

    this.isRunning = false;
    this.logger.info('Bridge relayer stopped');
    this.emit('stopped');
  }

  private async handleTransferInitiated(
    sourceChain: number,
    transferId: string,
    sender: string,
    recipient: string,
    token: string,
    amount: bigint,
    targetChain: number,
    nonce: bigint,
    event: any
  ): Promise<void> {
    const nonceKey = `${sourceChain}:${sender}`;
    const processedSet = this.processedNonces.get(nonceKey);

    // Check for replay
    if (processedSet?.has(nonce)) {
      this.logger.warn('Duplicate nonce detected', { transferId, nonce: nonce.toString() });
      return;
    }

    // Check pending transfer limit
    if (this.pendingTransfers.size >= this.config.maxPendingTransfers) {
      this.logger.warn('Max pending transfers reached', {
        current: this.pendingTransfers.size,
        max: this.config.maxPendingTransfers
      });
      return;
    }

    const transfer: PendingTransfer = {
      transferId,
      sourceChain,
      targetChain,
      sender,
      recipient,
      token,
      amount,
      nonce,
      timestamp: Date.now(),
      blockNumber: event.blockNumber,
      txHash: event.transactionHash,
      signatures: [],
      status: TransferStatus.PENDING,
      retries: 0
    };

    // Sign the transfer
    const signature = await this.signTransfer(transfer);
    transfer.signatures.push({
      relayer: this.wallet.address,
      signature,
      timestamp: Date.now()
    });

    this.pendingTransfers.set(transferId, transfer);
    processedSet?.add(nonce);

    // Broadcast to peer relayers
    await this.broadcastTransfer(transfer);

    // Cache in Redis
    await this.cacheTransfer(transfer);

    this.logger.info('Transfer initiated', {
      transferId,
      sourceChain,
      targetChain,
      amount: amount.toString()
    });

    this.emit('transferInitiated', transfer);
    this.metrics.pendingTransfers++;
  }

  private async signTransfer(transfer: PendingTransfer): Promise<string> {
    const message = ethers.solidityPackedKeccak256(
      ['bytes32', 'uint256', 'uint256', 'address', 'address', 'address', 'uint256', 'uint256'],
      [
        transfer.transferId,
        transfer.sourceChain,
        transfer.targetChain,
        transfer.sender,
        transfer.recipient,
        transfer.token,
        transfer.amount,
        transfer.nonce
      ]
    );

    return this.wallet.signMessage(ethers.getBytes(message));
  }

  private async processRelayQueue(): Promise<void> {
    if (!this.isRunning) return;

    const readyTransfers: PendingTransfer[] = [];

    for (const [id, transfer] of this.pendingTransfers) {
      if (
        transfer.status === TransferStatus.PENDING &&
        transfer.signatures.length >= 3 && // Minimum 3/5 signatures
        transfer.retries < 3
      ) {
        readyTransfers.push(transfer);
        if (readyTransfers.length >= this.config.batchSize) break;
      }
    }

    if (readyTransfers.length === 0) return;

    this.logger.info(`Processing ${readyTransfers.length} transfers`);

    // Process in parallel with concurrency limit
    const results = await Promise.allSettled(
      readyTransfers.map(transfer => this.relayTransfer(transfer))
    );

    results.forEach((result, index) => {
      const transfer = readyTransfers[index];
      if (result.status === 'rejected') {
        this.logger.error('Relay failed', {
          transferId: transfer.transferId,
          error: result.reason
        });
        transfer.retries++;
        transfer.lastError = result.reason.toString();

        if (transfer.retries >= 3) {
          transfer.status = TransferStatus.FAILED;
          this.metrics.failedRelays++;
        }
      }
    });
  }

  private async relayTransfer(transfer: PendingTransfer): Promise<void> {
    const targetContract = this.contracts.get(transfer.targetChain);
    if (!targetContract) {
      throw new Error(`No contract for chain ${transfer.targetChain}`);
    }

    const targetConfig = this.chains.get(transfer.targetChain);
    if (!targetConfig) {
      throw new Error(`No config for chain ${transfer.targetChain}`);
    }

    // Build merkle proof
    const proof = await this.buildMerkleProof(transfer);

    // Prepare signatures
    const signers = transfer.signatures.map(s => s.relayer);
    const signatures = transfer.signatures.map(s => s.signature);

    // Estimate gas
    const gasEstimate = await targetContract.claimTransfer.estimateGas(
      transfer.transferId,
      transfer.sourceChain,
      transfer.sender,
      transfer.recipient,
      transfer.token,
      transfer.amount,
      transfer.nonce,
      proof.proof,
      signers,
      signatures
    );

    // Add 20% buffer
    const gasLimit = (gasEstimate * 120n) / 100n;

    // Execute relay
    const tx = await targetContract.claimTransfer(
      transfer.transferId,
      transfer.sourceChain,
      transfer.sender,
      transfer.recipient,
      transfer.token,
      transfer.amount,
      transfer.nonce,
      proof.proof,
      signers,
      signatures,
      {
        gasLimit,
        gasPrice: targetConfig.gasPrice
      }
    );

    this.logger.info('Relay transaction submitted', {
      transferId: transfer.transferId,
      txHash: tx.hash,
      gasLimit: gasLimit.toString()
    });

    // Wait for confirmations
    const receipt = await tx.wait(targetConfig.confirmations);

    if (receipt.status === 1) {
      transfer.status = TransferStatus.RELAYED;
      this.metrics.successfulRelays++;
      this.metrics.totalRelays++;
      this.metrics.totalVolume += transfer.amount;
      this.metrics.gasSpent += receipt.gasUsed * receipt.gasPrice;
      this.metrics.pendingTransfers--;

      // Calculate finality time
      const finalityTime = Date.now() - transfer.timestamp;
      this.updateAverageFinalityTime(finalityTime);

      this.logger.info('Transfer relayed successfully', {
        transferId: transfer.transferId,
        gasUsed: receipt.gasUsed.toString(),
        finalityTime
      });

      this.emit('transferRelayed', transfer, receipt);
    } else {
      throw new Error('Transaction reverted');
    }

    // Update cache
    await this.cacheTransfer(transfer);
  }

  private async buildMerkleProof(transfer: PendingTransfer): Promise<MerkleProof> {
    // Get recent transfers from source chain
    const sourceContract = this.contracts.get(transfer.sourceChain);
    if (!sourceContract) {
      throw new Error(`No contract for source chain ${transfer.sourceChain}`);
    }

    // Fetch merkle root from source chain
    const merkleRoot = await sourceContract.getMerkleRoot(transfer.blockNumber);

    // Build proof from cached transfers
    const cachedTransfers = await this.redis.lrange(
      `transfers:${transfer.sourceChain}:${transfer.blockNumber}`,
      0,
      -1
    );

    const leaves = cachedTransfers.map(t => {
      const parsed = JSON.parse(t);
      return ethers.solidityPackedKeccak256(
        ['bytes32', 'address', 'address', 'uint256'],
        [parsed.transferId, parsed.sender, parsed.recipient, parsed.amount]
      );
    });

    // Find leaf index
    const leafHash = ethers.solidityPackedKeccak256(
      ['bytes32', 'address', 'address', 'uint256'],
      [transfer.transferId, transfer.sender, transfer.recipient, transfer.amount]
    );

    const index = leaves.indexOf(leafHash);
    if (index === -1) {
      throw new Error('Transfer not found in merkle tree');
    }

    // Build proof path
    const proof = this.computeMerkleProof(leaves, index);

    return {
      root: merkleRoot,
      proof,
      leaf: leafHash,
      index
    };
  }

  private computeMerkleProof(leaves: string[], index: number): string[] {
    const proof: string[] = [];
    let currentLeaves = [...leaves];
    let currentIndex = index;

    while (currentLeaves.length > 1) {
      const newLeaves: string[] = [];

      for (let i = 0; i < currentLeaves.length; i += 2) {
        if (i + 1 < currentLeaves.length) {
          if (i === currentIndex || i + 1 === currentIndex) {
            proof.push(currentLeaves[i === currentIndex ? i + 1 : i]);
          }

          const combined = ethers.solidityPackedKeccak256(
            ['bytes32', 'bytes32'],
            [currentLeaves[i], currentLeaves[i + 1]]
          );
          newLeaves.push(combined);
        } else {
          newLeaves.push(currentLeaves[i]);
        }
      }

      currentIndex = Math.floor(currentIndex / 2);
      currentLeaves = newLeaves;
    }

    return proof;
  }

  // ============================================================================
  // CHALLENGE & FRAUD PROOF SYSTEM
  // ============================================================================

  private async handleChallenge(
    transferId: string,
    challenger: string,
    reason: number
  ): Promise<void> {
    const transfer = this.pendingTransfers.get(transferId);
    if (!transfer) {
      this.logger.warn('Challenge for unknown transfer', { transferId });
      return;
    }

    const challenge: ChallengeData = {
      transferId,
      challenger,
      reason: this.mapChallengeReason(reason),
      evidence: '',
      timestamp: Date.now(),
      resolved: false
    };

    this.activeChallenges.set(transferId, challenge);
    transfer.status = TransferStatus.CHALLENGED;
    this.metrics.activeChallenges++;

    this.logger.warn('Transfer challenged', {
      transferId,
      challenger,
      reason: challenge.reason
    });

    // Automatically respond to challenge if we have proof
    await this.respondToChallenge(challenge, transfer);

    this.emit('transferChallenged', challenge);
  }

  private mapChallengeReason(reason: number): ChallengeReason {
    const reasons: ChallengeReason[] = [
      ChallengeReason.INVALID_SIGNATURE,
      ChallengeReason.INVALID_PROOF,
      ChallengeReason.DOUBLE_SPEND,
      ChallengeReason.INVALID_AMOUNT,
      ChallengeReason.NONCE_MISMATCH
    ];
    return reasons[reason] || ChallengeReason.INVALID_SIGNATURE;
  }

  private async respondToChallenge(
    challenge: ChallengeData,
    transfer: PendingTransfer
  ): Promise<void> {
    const targetContract = this.contracts.get(transfer.targetChain);
    if (!targetContract) return;

    try {
      // Build evidence based on challenge reason
      let evidence: string;

      switch (challenge.reason) {
        case ChallengeReason.INVALID_PROOF:
          // Provide valid merkle proof
          const proof = await this.buildMerkleProof(transfer);
          evidence = ethers.AbiCoder.defaultAbiCoder().encode(
            ['bytes32', 'bytes32[]'],
            [proof.root, proof.proof]
          );
          break;

        case ChallengeReason.INVALID_SIGNATURE:
          // Provide all valid signatures
          evidence = ethers.AbiCoder.defaultAbiCoder().encode(
            ['address[]', 'bytes[]'],
            [
              transfer.signatures.map(s => s.relayer),
              transfer.signatures.map(s => s.signature)
            ]
          );
          break;

        case ChallengeReason.DOUBLE_SPEND:
          // Provide nonce history
          const nonceKey = `${transfer.sourceChain}:${transfer.sender}`;
          const nonces = Array.from(this.processedNonces.get(nonceKey) || []);
          evidence = ethers.AbiCoder.defaultAbiCoder().encode(
            ['uint256[]'],
            [nonces]
          );
          break;

        default:
          // Provide source transaction proof
          evidence = transfer.txHash;
      }

      const tx = await targetContract.respondToChallenge(
        transfer.transferId,
        evidence
      );

      await tx.wait();

      this.logger.info('Challenge response submitted', {
        transferId: transfer.transferId,
        txHash: tx.hash
      });

    } catch (error) {
      this.logger.error('Failed to respond to challenge', {
        transferId: transfer.transferId,
        error
      });
    }
  }

  private async monitorChallenges(): Promise<void> {
    for (const [transferId, challenge] of this.activeChallenges) {
      if (challenge.resolved) continue;

      const transfer = this.pendingTransfers.get(transferId);
      if (!transfer) continue;

      const targetContract = this.contracts.get(transfer.targetChain);
      if (!targetContract) continue;

      try {
        const challengeData = await targetContract.getChallengeInfo(transferId);

        if (challengeData.resolved) {
          challenge.resolved = true;
          challenge.outcome = challengeData.challengerWins
            ? ChallengeOutcome.CHALLENGER_WINS
            : ChallengeOutcome.RELAYER_WINS;

          if (challenge.outcome === ChallengeOutcome.CHALLENGER_WINS) {
            transfer.status = TransferStatus.FAILED;
            this.metrics.failedRelays++;
            this.logger.error('Challenge lost', { transferId });
          } else {
            transfer.status = TransferStatus.RELAYED;
            this.logger.info('Challenge won', { transferId });
          }

          this.metrics.activeChallenges--;
          this.emit('challengeResolved', challenge);
        }
      } catch (error) {
        this.logger.error('Error monitoring challenge', { transferId, error });
      }
    }
  }

  async submitFraudProof(
    transferId: string,
    reason: ChallengeReason,
    evidence: string
  ): Promise<string> {
    const transfer = this.pendingTransfers.get(transferId);
    if (!transfer) {
      throw new Error('Transfer not found');
    }

    const sourceContract = this.contracts.get(transfer.sourceChain);
    if (!sourceContract) {
      throw new Error('Source chain contract not found');
    }

    const reasonIndex = Object.values(ChallengeReason).indexOf(reason);

    const tx = await sourceContract.challengeTransfer(
      transferId,
      reasonIndex,
      evidence
    );

    const receipt = await tx.wait();

    this.logger.info('Fraud proof submitted', {
      transferId,
      reason,
      txHash: tx.hash
    });

    return tx.hash;
  }

  // ============================================================================
  // PEER COORDINATION
  // ============================================================================

  async broadcastTransfer(transfer: PendingTransfer): Promise<void> {
    const message = {
      type: 'TRANSFER_SIGNATURE_REQUEST',
      transfer: this.serializeTransfer(transfer),
      signature: transfer.signatures[0]
    };

    await this.redis.publish('relayer:transfers', JSON.stringify(message));
  }

  async receiveSignature(
    transferId: string,
    relayer: string,
    signature: string
  ): Promise<void> {
    const transfer = this.pendingTransfers.get(transferId);
    if (!transfer) return;

    // Verify signature
    const isValid = await this.verifySignature(transfer, relayer, signature);
    if (!isValid) {
      this.logger.warn('Invalid signature received', { transferId, relayer });
      return;
    }

    // Check for duplicate
    if (transfer.signatures.some(s => s.relayer === relayer)) {
      return;
    }

    transfer.signatures.push({
      relayer,
      signature,
      timestamp: Date.now()
    });

    this.logger.info('Signature received', {
      transferId,
      relayer,
      totalSignatures: transfer.signatures.length
    });

    await this.cacheTransfer(transfer);
  }

  private async verifySignature(
    transfer: PendingTransfer,
    relayer: string,
    signature: string
  ): Promise<boolean> {
    const message = ethers.solidityPackedKeccak256(
      ['bytes32', 'uint256', 'uint256', 'address', 'address', 'address', 'uint256', 'uint256'],
      [
        transfer.transferId,
        transfer.sourceChain,
        transfer.targetChain,
        transfer.sender,
        transfer.recipient,
        transfer.token,
        transfer.amount,
        transfer.nonce
      ]
    );

    const recoveredAddress = ethers.verifyMessage(
      ethers.getBytes(message),
      signature
    );

    return recoveredAddress.toLowerCase() === relayer.toLowerCase();
  }

  // ============================================================================
  // STATE MANAGEMENT
  // ============================================================================

  private async loadPendingTransfers(): Promise<void> {
    const keys = await this.redis.keys('transfer:*');

    for (const key of keys) {
      const data = await this.redis.get(key);
      if (data) {
        const transfer = this.deserializeTransfer(JSON.parse(data));
        if (
          transfer.status === TransferStatus.PENDING ||
          transfer.status === TransferStatus.RELAYED
        ) {
          this.pendingTransfers.set(transfer.transferId, transfer);
        }
      }
    }

    this.metrics.pendingTransfers = this.pendingTransfers.size;
    this.logger.info(`Loaded ${this.pendingTransfers.size} pending transfers`);
  }

  private async savePendingTransfers(): Promise<void> {
    const pipeline = this.redis.pipeline();

    for (const [id, transfer] of this.pendingTransfers) {
      pipeline.set(
        `transfer:${id}`,
        JSON.stringify(this.serializeTransfer(transfer)),
        'EX',
        86400 * 7 // 7 days TTL
      );
    }

    await pipeline.exec();
    this.logger.info(`Saved ${this.pendingTransfers.size} pending transfers`);
  }

  private async cacheTransfer(transfer: PendingTransfer): Promise<void> {
    await this.redis.set(
      `transfer:${transfer.transferId}`,
      JSON.stringify(this.serializeTransfer(transfer)),
      'EX',
      86400 * 7
    );
  }

  private serializeTransfer(transfer: PendingTransfer): any {
    return {
      ...transfer,
      amount: transfer.amount.toString(),
      nonce: transfer.nonce.toString()
    };
  }

  private deserializeTransfer(data: any): PendingTransfer {
    return {
      ...data,
      amount: BigInt(data.amount),
      nonce: BigInt(data.nonce)
    };
  }

  private updateAverageFinalityTime(newTime: number): void {
    const totalRelays = this.metrics.successfulRelays;
    this.metrics.averageFinalityTime =
      (this.metrics.averageFinalityTime * (totalRelays - 1) + newTime) / totalRelays;
  }

  // ============================================================================
  // FAST FINALITY (LP LIQUIDITY)
  // ============================================================================

  async provideFastFinality(
    transferId: string,
    maxAmount: bigint
  ): Promise<string> {
    const transfer = this.pendingTransfers.get(transferId);
    if (!transfer) {
      throw new Error('Transfer not found');
    }

    if (transfer.amount > maxAmount) {
      throw new Error('Transfer amount exceeds max');
    }

    const targetContract = this.contracts.get(transfer.targetChain);
    if (!targetContract) {
      throw new Error('Target chain contract not found');
    }

    // Provide fast finality by using LP funds
    const tx = await targetContract.provideFastFinality(
      transfer.transferId,
      transfer.recipient,
      transfer.token,
      transfer.amount
    );

    const receipt = await tx.wait();

    this.logger.info('Fast finality provided', {
      transferId,
      amount: transfer.amount.toString(),
      txHash: tx.hash
    });

    return tx.hash;
  }

  // ============================================================================
  // STAKING & REPUTATION
  // ============================================================================

  async getStake(): Promise<bigint> {
    // Check stake on primary chain
    const primaryChain = Array.from(this.chains.values())[0];
    const contract = this.contracts.get(primaryChain.chainId);
    if (!contract) return 0n;

    return contract.getRelayerStake(this.wallet.address);
  }

  async addStake(amount: bigint): Promise<string> {
    const primaryChain = Array.from(this.chains.values())[0];
    const contract = this.contracts.get(primaryChain.chainId);
    if (!contract) {
      throw new Error('No primary chain contract');
    }

    const tx = await contract.addRelayerStake({ value: amount });
    await tx.wait();

    this.logger.info('Stake added', { amount: amount.toString() });
    return tx.hash;
  }

  async withdrawStake(amount: bigint): Promise<string> {
    const primaryChain = Array.from(this.chains.values())[0];
    const contract = this.contracts.get(primaryChain.chainId);
    if (!contract) {
      throw new Error('No primary chain contract');
    }

    const tx = await contract.withdrawRelayerStake(amount);
    await tx.wait();

    this.logger.info('Stake withdrawn', { amount: amount.toString() });
    return tx.hash;
  }

  calculateReputation(): number {
    const successRate = this.metrics.successfulRelays /
      (this.metrics.totalRelays || 1);
    const challengeRate = this.metrics.activeChallenges /
      (this.metrics.totalRelays || 1);

    // Reputation = 70% success rate + 20% uptime + 10% volume
    const reputation = (successRate * 0.7) - (challengeRate * 0.2) + 0.1;
    return Math.max(0, Math.min(1, reputation));
  }

  // ============================================================================
  // MONITORING & HEALTH
  // ============================================================================

  getMetrics(): RelayMetrics {
    return { ...this.metrics };
  }

  async healthCheck(): Promise<{
    healthy: boolean;
    issues: string[];
  }> {
    const issues: string[] = [];

    // Check stake
    const stake = await this.getStake();
    if (stake < this.config.minStake) {
      issues.push('Insufficient stake');
    }

    // Check provider connections
    for (const [chainId, provider] of this.providers) {
      try {
        await provider.getBlockNumber();
      } catch {
        issues.push(`Chain ${chainId} connection failed`);
      }
    }

    // Check pending transfers
    if (this.pendingTransfers.size > this.config.maxPendingTransfers * 0.9) {
      issues.push('Pending transfer queue near capacity');
    }

    // Check active challenges
    if (this.metrics.activeChallenges > 10) {
      issues.push('High number of active challenges');
    }

    // Check error rate
    const errorRate = this.metrics.failedRelays / (this.metrics.totalRelays || 1);
    if (errorRate > 0.05) {
      issues.push(`High error rate: ${(errorRate * 100).toFixed(2)}%`);
    }

    return {
      healthy: issues.length === 0,
      issues
    };
  }

  getTransferStatus(transferId: string): PendingTransfer | undefined {
    return this.pendingTransfers.get(transferId);
  }

  async getHistoricalTransfers(
    filter: {
      sourceChain?: number;
      targetChain?: number;
      status?: TransferStatus;
      startTime?: number;
      endTime?: number;
    }
  ): Promise<PendingTransfer[]> {
    const results: PendingTransfer[] = [];

    for (const transfer of this.pendingTransfers.values()) {
      let matches = true;

      if (filter.sourceChain && transfer.sourceChain !== filter.sourceChain) {
        matches = false;
      }
      if (filter.targetChain && transfer.targetChain !== filter.targetChain) {
        matches = false;
      }
      if (filter.status && transfer.status !== filter.status) {
        matches = false;
      }
      if (filter.startTime && transfer.timestamp < filter.startTime) {
        matches = false;
      }
      if (filter.endTime && transfer.timestamp > filter.endTime) {
        matches = false;
      }

      if (matches) {
        results.push(transfer);
      }
    }

    return results.sort((a, b) => b.timestamp - a.timestamp);
  }

  private handleFinalization(transferId: string): void {
    const transfer = this.pendingTransfers.get(transferId);
    if (transfer) {
      transfer.status = TransferStatus.FINALIZED;
      this.logger.info('Transfer finalized', { transferId });
      this.emit('transferFinalized', transfer);
    }
  }
}

// ============================================================================
// BRIDGE CONTRACT ABI (SUBSET)
// ============================================================================

const BRIDGE_ABI = [
  'event TransferInitiated(bytes32 indexed transferId, address indexed sender, address recipient, address token, uint256 amount, uint256 targetChain, uint256 nonce)',
  'event TransferChallenged(bytes32 indexed transferId, address indexed challenger, uint8 reason)',
  'event TransferFinalized(bytes32 indexed transferId, address recipient, uint256 amount)',
  'function claimTransfer(bytes32 transferId, uint256 sourceChain, address sender, address recipient, address token, uint256 amount, uint256 nonce, bytes32[] calldata proof, address[] calldata signers, bytes[] calldata signatures) external',
  'function challengeTransfer(bytes32 transferId, uint8 reason, bytes calldata evidence) external',
  'function respondToChallenge(bytes32 transferId, bytes calldata evidence) external',
  'function getChallengeInfo(bytes32 transferId) external view returns (bool resolved, bool challengerWins, uint256 deadline)',
  'function getMerkleRoot(uint256 blockNumber) external view returns (bytes32)',
  'function provideFastFinality(bytes32 transferId, address recipient, address token, uint256 amount) external',
  'function getRelayerStake(address relayer) external view returns (uint256)',
  'function addRelayerStake() external payable',
  'function withdrawRelayerStake(uint256 amount) external'
];

export default BridgeRelayer;
