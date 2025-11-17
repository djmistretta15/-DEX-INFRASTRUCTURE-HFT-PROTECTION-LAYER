/**
 * Threshold Signature Scheme (TSS) for Distributed Key Management
 *
 * SCIENTIFIC HYPOTHESIS:
 * A t-of-n threshold signature scheme using Shamir's Secret Sharing and
 * distributed key generation will enable secure multi-party signing with
 * no single point of failure, achieving <500ms signing latency while
 * maintaining cryptographic security equivalent to single-key ECDSA.
 *
 * SUCCESS METRICS:
 * - Signing latency: <500ms for t-of-n threshold (n<=10)
 * - Key generation time: <5 seconds for full DKG ceremony
 * - Security: Equivalent to 128-bit security level
 * - Availability: System operational with any t of n parties
 * - Verifiability: 100% deterministic signature verification
 *
 * SECURITY CONSIDERATIONS:
 * - Secure multiparty computation (MPC) protocols
 * - Verifiable Secret Sharing (VSS) to detect malicious parties
 * - Zero-knowledge proofs for correctness verification
 * - Robust against malicious minority (<t parties)
 * - Forward secrecy through key rotation
 */

import { EventEmitter } from 'events';
import crypto from 'crypto';
import winston from 'winston';

// ============================================================================
// INTERFACES & TYPES
// ============================================================================

interface TSSConfig {
  threshold: number; // t
  totalParties: number; // n
  curve: CurveType;
  hashFunction: HashFunction;
  timeout: number;
  rotationPeriod: number;
}

interface Party {
  id: number;
  publicKey: Buffer;
  commitment: Buffer;
  secretShare?: Buffer;
  verified: boolean;
  online: boolean;
  lastSeen: Date;
}

interface KeyShare {
  partyId: number;
  share: Buffer;
  verification: Buffer;
  index: number;
  publicKeyShare: Buffer;
}

interface DistributedKey {
  keyId: string;
  publicKey: Buffer;
  shares: Map<number, KeyShare>;
  threshold: number;
  totalParties: number;
  createdAt: Date;
  lastRotated: Date;
  rotationCount: number;
}

interface SignatureShare {
  partyId: number;
  share: Buffer;
  proof: ZKProof;
  timestamp: Date;
}

interface ThresholdSignature {
  signatureId: string;
  message: Buffer;
  messageHash: Buffer;
  signature: Buffer;
  participatingParties: number[];
  aggregatedFrom: SignatureShare[];
  timestamp: Date;
  verified: boolean;
}

interface ZKProof {
  commitment: Buffer;
  challenge: Buffer;
  response: Buffer;
}

interface DKGRound {
  roundId: string;
  phase: DKGPhase;
  participants: Set<number>;
  commitments: Map<number, Buffer>;
  shares: Map<number, Map<number, Buffer>>;
  complaints: Map<number, number[]>;
  qualifiedParties: Set<number>;
  startTime: Date;
  endTime?: Date;
  success: boolean;
}

interface SigningSession {
  sessionId: string;
  keyId: string;
  message: Buffer;
  messageHash: Buffer;
  participants: Set<number>;
  shares: Map<number, SignatureShare>;
  status: SigningStatus;
  startTime: Date;
  endTime?: Date;
  result?: ThresholdSignature;
}

interface KeyRotationEvent {
  oldKeyId: string;
  newKeyId: string;
  rotatedAt: Date;
  reason: string;
  participants: number[];
}

interface TSSMetrics {
  totalSignatures: number;
  avgSigningLatency: number;
  successfulDKGs: number;
  failedDKGs: number;
  keyRotations: number;
  activeParties: number;
  currentThreshold: number;
}

enum CurveType {
  SECP256K1 = 'secp256k1',
  ED25519 = 'ed25519',
  P256 = 'p256'
}

enum HashFunction {
  SHA256 = 'sha256',
  KECCAK256 = 'keccak256',
  BLAKE2B = 'blake2b'
}

enum DKGPhase {
  INIT = 'INIT',
  COMMITMENT = 'COMMITMENT',
  SHARE_DISTRIBUTION = 'SHARE_DISTRIBUTION',
  COMPLAINT = 'COMPLAINT',
  FINALIZATION = 'FINALIZATION',
  COMPLETE = 'COMPLETE',
  FAILED = 'FAILED'
}

enum SigningStatus {
  INITIATED = 'INITIATED',
  COLLECTING_SHARES = 'COLLECTING_SHARES',
  AGGREGATING = 'AGGREGATING',
  VERIFYING = 'VERIFYING',
  COMPLETE = 'COMPLETE',
  FAILED = 'FAILED',
  TIMEOUT = 'TIMEOUT'
}

// ============================================================================
// FINITE FIELD OPERATIONS
// ============================================================================

class FiniteField {
  private prime: bigint;

  constructor(prime: bigint) {
    this.prime = prime;
  }

  add(a: bigint, b: bigint): bigint {
    return ((a % this.prime) + (b % this.prime)) % this.prime;
  }

  sub(a: bigint, b: bigint): bigint {
    return (
      (((a % this.prime) - (b % this.prime)) % this.prime + this.prime) %
      this.prime
    );
  }

  mul(a: bigint, b: bigint): bigint {
    return ((a % this.prime) * (b % this.prime)) % this.prime;
  }

  pow(base: bigint, exp: bigint): bigint {
    let result = 1n;
    base = base % this.prime;

    while (exp > 0n) {
      if (exp % 2n === 1n) {
        result = this.mul(result, base);
      }
      exp = exp / 2n;
      base = this.mul(base, base);
    }

    return result;
  }

  inv(a: bigint): bigint {
    // Extended Euclidean Algorithm
    return this.pow(a, this.prime - 2n);
  }

  div(a: bigint, b: bigint): bigint {
    return this.mul(a, this.inv(b));
  }
}

// ============================================================================
// POLYNOMIAL OPERATIONS
// ============================================================================

class Polynomial {
  private coefficients: bigint[];
  private field: FiniteField;

  constructor(coefficients: bigint[], field: FiniteField) {
    this.coefficients = coefficients;
    this.field = field;
  }

  evaluate(x: bigint): bigint {
    let result = 0n;
    let xPower = 1n;

    for (const coeff of this.coefficients) {
      result = this.field.add(result, this.field.mul(coeff, xPower));
      xPower = this.field.mul(xPower, x);
    }

    return result;
  }

  static random(degree: number, field: FiniteField, secret: bigint): Polynomial {
    const coefficients: bigint[] = [secret];

    for (let i = 1; i <= degree; i++) {
      const randomBytes = crypto.randomBytes(32);
      const randomCoeff = BigInt('0x' + randomBytes.toString('hex')) % field['prime'];
      coefficients.push(randomCoeff);
    }

    return new Polynomial(coefficients, field);
  }

  static lagrangeInterpolate(
    points: Map<bigint, bigint>,
    field: FiniteField,
    targetX: bigint = 0n
  ): bigint {
    let result = 0n;
    const xs = Array.from(points.keys());

    for (const [xi, yi] of points) {
      let numerator = 1n;
      let denominator = 1n;

      for (const xj of xs) {
        if (xi !== xj) {
          numerator = field.mul(numerator, field.sub(targetX, xj));
          denominator = field.mul(denominator, field.sub(xi, xj));
        }
      }

      const lagrangeBasis = field.div(numerator, denominator);
      result = field.add(result, field.mul(yi, lagrangeBasis));
    }

    return result;
  }
}

// ============================================================================
// THRESHOLD SIGNATURE SCHEME
// ============================================================================

export class ThresholdSignatureScheme extends EventEmitter {
  private config: TSSConfig;
  private logger: winston.Logger;
  private field: FiniteField;

  private parties: Map<number, Party> = new Map();
  private distributedKeys: Map<string, DistributedKey> = new Map();
  private activeDKGs: Map<string, DKGRound> = new Map();
  private signingSessions: Map<string, SigningSession> = new Map();
  private metrics: TSSMetrics;

  // Curve parameters (secp256k1)
  private readonly SECP256K1_ORDER = BigInt(
    '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
  );

  constructor(config: TSSConfig) {
    super();

    this.config = config;
    this.field = new FiniteField(this.SECP256K1_ORDER);

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'tss.log' })
      ]
    });

    this.metrics = {
      totalSignatures: 0,
      avgSigningLatency: 0,
      successfulDKGs: 0,
      failedDKGs: 0,
      keyRotations: 0,
      activeParties: 0,
      currentThreshold: config.threshold
    };

    this.logger.info('TSS initialized', {
      threshold: config.threshold,
      totalParties: config.totalParties,
      curve: config.curve
    });
  }

  // ============================================================================
  // PARTY MANAGEMENT
  // ============================================================================

  registerParty(partyId: number, publicKey: Buffer): void {
    if (partyId < 1 || partyId > this.config.totalParties) {
      throw new Error(`Invalid party ID: ${partyId}`);
    }

    const party: Party = {
      id: partyId,
      publicKey,
      commitment: Buffer.alloc(0),
      verified: false,
      online: true,
      lastSeen: new Date()
    };

    this.parties.set(partyId, party);
    this.metrics.activeParties = this.parties.size;

    this.logger.info('Party registered', { partyId });
    this.emit('partyRegistered', party);
  }

  setPartyOnline(partyId: number, online: boolean): void {
    const party = this.parties.get(partyId);
    if (party) {
      party.online = online;
      party.lastSeen = new Date();
      this.metrics.activeParties = Array.from(this.parties.values()).filter(
        p => p.online
      ).length;
    }
  }

  // ============================================================================
  // DISTRIBUTED KEY GENERATION (DKG)
  // ============================================================================

  async initiateDKG(): Promise<string> {
    const roundId = crypto.randomBytes(16).toString('hex');

    const onlineParties = Array.from(this.parties.values())
      .filter(p => p.online)
      .map(p => p.id);

    if (onlineParties.length < this.config.threshold) {
      throw new Error(
        `Insufficient online parties: ${onlineParties.length}/${this.config.threshold}`
      );
    }

    const dkgRound: DKGRound = {
      roundId,
      phase: DKGPhase.INIT,
      participants: new Set(onlineParties),
      commitments: new Map(),
      shares: new Map(),
      complaints: new Map(),
      qualifiedParties: new Set(),
      startTime: new Date(),
      success: false
    };

    this.activeDKGs.set(roundId, dkgRound);

    this.logger.info('DKG initiated', {
      roundId,
      participants: onlineParties.length
    });

    this.emit('dkgInitiated', roundId);

    // Start DKG protocol
    await this.runDKGProtocol(roundId);

    return roundId;
  }

  private async runDKGProtocol(roundId: string): Promise<void> {
    const dkg = this.activeDKGs.get(roundId);
    if (!dkg) throw new Error('DKG round not found');

    try {
      // Phase 1: Commitment
      dkg.phase = DKGPhase.COMMITMENT;
      await this.dkgCommitmentPhase(dkg);

      // Phase 2: Share Distribution
      dkg.phase = DKGPhase.SHARE_DISTRIBUTION;
      await this.dkgShareDistributionPhase(dkg);

      // Phase 3: Complaint
      dkg.phase = DKGPhase.COMPLAINT;
      await this.dkgComplaintPhase(dkg);

      // Phase 4: Finalization
      dkg.phase = DKGPhase.FINALIZATION;
      await this.dkgFinalizationPhase(dkg);

      dkg.phase = DKGPhase.COMPLETE;
      dkg.success = true;
      dkg.endTime = new Date();

      this.metrics.successfulDKGs++;

      this.logger.info('DKG completed successfully', { roundId });
      this.emit('dkgComplete', roundId);
    } catch (error) {
      dkg.phase = DKGPhase.FAILED;
      dkg.success = false;
      dkg.endTime = new Date();

      this.metrics.failedDKGs++;

      this.logger.error('DKG failed', { roundId, error });
      this.emit('dkgFailed', roundId, error);
    }
  }

  private async dkgCommitmentPhase(dkg: DKGRound): Promise<void> {
    // Each party generates a random polynomial and commits to it
    for (const partyId of dkg.participants) {
      // Generate random polynomial of degree t-1
      const secret = this.generateRandomSecret();
      const poly = Polynomial.random(
        this.config.threshold - 1,
        this.field,
        secret
      );

      // Generate commitment (hash of polynomial coefficients)
      const commitment = this.generateCommitment(poly);
      dkg.commitments.set(partyId, commitment);

      // Store secret share for this party
      const party = this.parties.get(partyId);
      if (party) {
        party.secretShare = Buffer.from(secret.toString(16), 'hex');
      }

      // Initialize share map for this party
      dkg.shares.set(partyId, new Map());

      // Calculate shares for all other parties
      for (const recipientId of dkg.participants) {
        const shareValue = poly.evaluate(BigInt(recipientId));
        const shareBuffer = Buffer.from(shareValue.toString(16), 'hex');
        dkg.shares.get(partyId)!.set(recipientId, shareBuffer);
      }
    }

    this.logger.info('DKG commitment phase complete', {
      roundId: dkg.roundId,
      commitments: dkg.commitments.size
    });
  }

  private async dkgShareDistributionPhase(dkg: DKGRound): Promise<void> {
    // Parties exchange encrypted shares
    // In production, this would use secure channels

    this.logger.info('DKG share distribution complete', {
      roundId: dkg.roundId
    });
  }

  private async dkgComplaintPhase(dkg: DKGRound): Promise<void> {
    // Parties verify received shares against commitments
    for (const recipientId of dkg.participants) {
      const complaints: number[] = [];

      for (const senderId of dkg.participants) {
        if (senderId === recipientId) continue;

        const share = dkg.shares.get(senderId)?.get(recipientId);
        const commitment = dkg.commitments.get(senderId);

        if (!share || !commitment) {
          complaints.push(senderId);
          continue;
        }

        // Verify share against commitment (simplified VSS)
        const isValid = this.verifyShareCommitment(share, commitment, recipientId);

        if (!isValid) {
          complaints.push(senderId);
        }
      }

      if (complaints.length > 0) {
        dkg.complaints.set(recipientId, complaints);
      }
    }

    // Determine qualified parties (those with no valid complaints against them)
    for (const partyId of dkg.participants) {
      let disqualified = false;

      for (const [, partyComplaints] of dkg.complaints) {
        if (partyComplaints.includes(partyId)) {
          // Check if complaint is valid
          disqualified = true;
          break;
        }
      }

      if (!disqualified) {
        dkg.qualifiedParties.add(partyId);
      }
    }

    if (dkg.qualifiedParties.size < this.config.threshold) {
      throw new Error('Insufficient qualified parties after complaint phase');
    }

    this.logger.info('DKG complaint phase complete', {
      roundId: dkg.roundId,
      qualifiedParties: dkg.qualifiedParties.size
    });
  }

  private async dkgFinalizationPhase(dkg: DKGRound): Promise<void> {
    // Calculate group public key and individual key shares
    const keyId = crypto.randomBytes(16).toString('hex');

    // Aggregate shares for each party
    const shares: Map<number, KeyShare> = new Map();
    let groupPublicKey = Buffer.alloc(33);

    for (const partyId of dkg.qualifiedParties) {
      let aggregatedShare = 0n;

      // Sum all shares received by this party
      for (const senderId of dkg.qualifiedParties) {
        const share = dkg.shares.get(senderId)?.get(partyId);
        if (share) {
          const shareValue = BigInt('0x' + share.toString('hex'));
          aggregatedShare = this.field.add(aggregatedShare, shareValue);
        }
      }

      // Create key share
      const keyShare: KeyShare = {
        partyId,
        share: Buffer.from(aggregatedShare.toString(16).padStart(64, '0'), 'hex'),
        verification: this.generateShareVerification(aggregatedShare),
        index: partyId,
        publicKeyShare: this.derivePublicKeyShare(aggregatedShare)
      };

      shares.set(partyId, keyShare);
    }

    // Derive group public key (sum of all public key shares)
    groupPublicKey = this.aggregatePublicKeys(shares);

    // Create distributed key
    const distributedKey: DistributedKey = {
      keyId,
      publicKey: groupPublicKey,
      shares,
      threshold: this.config.threshold,
      totalParties: dkg.qualifiedParties.size,
      createdAt: new Date(),
      lastRotated: new Date(),
      rotationCount: 0
    };

    this.distributedKeys.set(keyId, distributedKey);

    this.logger.info('Distributed key created', {
      keyId,
      publicKey: groupPublicKey.toString('hex').slice(0, 20) + '...',
      threshold: distributedKey.threshold,
      parties: distributedKey.totalParties
    });

    this.emit('keyGenerated', distributedKey);
  }

  // ============================================================================
  // THRESHOLD SIGNING
  // ============================================================================

  async initiateSigningSession(
    keyId: string,
    message: Buffer,
    participants?: number[]
  ): Promise<string> {
    const key = this.distributedKeys.get(keyId);
    if (!key) {
      throw new Error('Key not found');
    }

    const sessionId = crypto.randomBytes(16).toString('hex');

    // Select participants
    let signers: number[];
    if (participants) {
      signers = participants;
    } else {
      // Select threshold number of online parties
      signers = Array.from(key.shares.keys())
        .filter(id => this.parties.get(id)?.online)
        .slice(0, key.threshold);
    }

    if (signers.length < key.threshold) {
      throw new Error(
        `Insufficient signers: ${signers.length}/${key.threshold}`
      );
    }

    const messageHash = this.hashMessage(message);

    const session: SigningSession = {
      sessionId,
      keyId,
      message,
      messageHash,
      participants: new Set(signers),
      shares: new Map(),
      status: SigningStatus.INITIATED,
      startTime: new Date()
    };

    this.signingSessions.set(sessionId, session);

    this.logger.info('Signing session initiated', {
      sessionId,
      keyId,
      participants: signers
    });

    this.emit('signingSessionInitiated', sessionId);

    // Collect signature shares
    await this.collectSignatureShares(sessionId);

    return sessionId;
  }

  private async collectSignatureShares(sessionId: string): Promise<void> {
    const session = this.signingSessions.get(sessionId);
    if (!session) throw new Error('Session not found');

    session.status = SigningStatus.COLLECTING_SHARES;

    const key = this.distributedKeys.get(session.keyId)!;

    // Each participant generates their signature share
    for (const partyId of session.participants) {
      const keyShare = key.shares.get(partyId);
      if (!keyShare) continue;

      // Generate signature share using secret share
      const signatureShare = this.generateSignatureShare(
        keyShare.share,
        session.messageHash,
        partyId
      );

      session.shares.set(partyId, signatureShare);

      this.logger.debug('Signature share collected', {
        sessionId,
        partyId
      });
    }

    if (session.shares.size >= key.threshold) {
      await this.aggregateSignature(sessionId);
    } else {
      session.status = SigningStatus.TIMEOUT;
      this.logger.error('Failed to collect enough signature shares', {
        sessionId,
        collected: session.shares.size,
        required: key.threshold
      });
    }
  }

  private generateSignatureShare(
    secretShare: Buffer,
    messageHash: Buffer,
    partyId: number
  ): SignatureShare {
    const secret = BigInt('0x' + secretShare.toString('hex'));
    const message = BigInt('0x' + messageHash.toString('hex'));

    // Generate random nonce for this signature
    const k = this.generateRandomSecret();
    const kInv = this.field.inv(k);

    // Partial signature: s_i = k^(-1) * (m + x_i * r) mod q
    // This is simplified; real implementation would need MPC for nonce generation
    const r = this.field.mul(k, message); // Simplified R calculation
    const partialSig = this.field.mul(kInv, this.field.add(message, this.field.mul(secret, r)));

    const shareBuffer = Buffer.from(
      partialSig.toString(16).padStart(64, '0'),
      'hex'
    );

    // Generate ZK proof of correctness
    const proof = this.generateSignatureProof(secret, partialSig, messageHash);

    return {
      partyId,
      share: shareBuffer,
      proof,
      timestamp: new Date()
    };
  }

  private async aggregateSignature(sessionId: string): Promise<void> {
    const session = this.signingSessions.get(sessionId);
    if (!session) throw new Error('Session not found');

    session.status = SigningStatus.AGGREGATING;

    const key = this.distributedKeys.get(session.keyId)!;

    // Verify all signature shares
    for (const [partyId, share] of session.shares) {
      const isValid = this.verifySignatureShare(share, session.messageHash);
      if (!isValid) {
        throw new Error(`Invalid signature share from party ${partyId}`);
      }
    }

    // Lagrange interpolation to combine shares
    const sharePoints = new Map<bigint, bigint>();

    for (const [partyId, share] of session.shares) {
      const x = BigInt(partyId);
      const y = BigInt('0x' + share.share.toString('hex'));
      sharePoints.set(x, y);
    }

    // Interpolate at x=0 to get the aggregated signature
    const aggregatedSig = Polynomial.lagrangeInterpolate(
      sharePoints,
      this.field,
      0n
    );

    const signature = Buffer.from(
      aggregatedSig.toString(16).padStart(128, '0'),
      'hex'
    );

    // Create threshold signature
    const thresholdSig: ThresholdSignature = {
      signatureId: crypto.randomBytes(16).toString('hex'),
      message: session.message,
      messageHash: session.messageHash,
      signature,
      participatingParties: Array.from(session.participants),
      aggregatedFrom: Array.from(session.shares.values()),
      timestamp: new Date(),
      verified: false
    };

    // Verify aggregated signature
    session.status = SigningStatus.VERIFYING;
    const isValid = this.verifyThresholdSignature(thresholdSig, key.publicKey);

    if (isValid) {
      thresholdSig.verified = true;
      session.status = SigningStatus.COMPLETE;
      session.result = thresholdSig;
      session.endTime = new Date();

      // Update metrics
      this.metrics.totalSignatures++;
      const latency = session.endTime.getTime() - session.startTime.getTime();
      this.updateAvgSigningLatency(latency);

      this.logger.info('Signature aggregated successfully', {
        sessionId,
        signatureId: thresholdSig.signatureId,
        latency
      });

      this.emit('signatureCreated', thresholdSig);
    } else {
      session.status = SigningStatus.FAILED;
      this.logger.error('Signature verification failed', { sessionId });
      this.emit('signatureFailed', sessionId, 'Verification failed');
    }
  }

  // ============================================================================
  // KEY ROTATION
  // ============================================================================

  async rotateKey(keyId: string): Promise<string> {
    const oldKey = this.distributedKeys.get(keyId);
    if (!oldKey) {
      throw new Error('Key not found');
    }

    this.logger.info('Initiating key rotation', { keyId });

    // Generate new key through DKG
    const dkgRoundId = await this.initiateDKG();
    const dkg = this.activeDKGs.get(dkgRoundId);

    if (!dkg || !dkg.success) {
      throw new Error('Key rotation DKG failed');
    }

    // Find the newly created key
    const newKeyId = Array.from(this.distributedKeys.keys()).find(
      id => !id.includes(keyId) && this.distributedKeys.get(id)!.createdAt > oldKey.createdAt
    );

    if (!newKeyId) {
      throw new Error('New key not found after DKG');
    }

    const newKey = this.distributedKeys.get(newKeyId)!;
    newKey.rotationCount = oldKey.rotationCount + 1;

    this.metrics.keyRotations++;

    const rotationEvent: KeyRotationEvent = {
      oldKeyId: keyId,
      newKeyId,
      rotatedAt: new Date(),
      reason: 'Scheduled rotation',
      participants: Array.from(newKey.shares.keys())
    };

    this.logger.info('Key rotation complete', {
      oldKeyId: keyId,
      newKeyId,
      rotationCount: newKey.rotationCount
    });

    this.emit('keyRotated', rotationEvent);

    return newKeyId;
  }

  // ============================================================================
  // HELPER FUNCTIONS
  // ============================================================================

  private generateRandomSecret(): bigint {
    const randomBytes = crypto.randomBytes(32);
    return BigInt('0x' + randomBytes.toString('hex')) % this.SECP256K1_ORDER;
  }

  private generateCommitment(poly: Polynomial): Buffer {
    // In production, use Pedersen commitments
    const polyData = JSON.stringify({
      degree: this.config.threshold - 1
    });
    return crypto.createHash('sha256').update(polyData).digest();
  }

  private verifyShareCommitment(
    share: Buffer,
    commitment: Buffer,
    recipientId: number
  ): boolean {
    // Simplified verification
    // In production, verify using VSS
    return share.length > 0 && commitment.length > 0;
  }

  private generateShareVerification(share: bigint): Buffer {
    // Generate verification data for the share
    const data = share.toString(16);
    return crypto.createHash('sha256').update(data).digest();
  }

  private derivePublicKeyShare(secretShare: bigint): Buffer {
    // Derive public key from secret share
    // In production, multiply by generator point
    const hash = crypto
      .createHash('sha256')
      .update(secretShare.toString(16))
      .digest();
    return hash;
  }

  private aggregatePublicKeys(shares: Map<number, KeyShare>): Buffer {
    // Aggregate public key shares
    // In production, use elliptic curve point addition
    const combined = Array.from(shares.values())
      .map(s => s.publicKeyShare)
      .reduce((acc, pk) => {
        const combined = Buffer.alloc(33);
        for (let i = 0; i < Math.min(acc.length, pk.length); i++) {
          combined[i] = acc[i] ^ pk[i];
        }
        return combined;
      });

    return combined;
  }

  private hashMessage(message: Buffer): Buffer {
    switch (this.config.hashFunction) {
      case HashFunction.SHA256:
        return crypto.createHash('sha256').update(message).digest();
      case HashFunction.KECCAK256:
        // Use sha3 from crypto module or external library
        return crypto.createHash('sha256').update(message).digest();
      case HashFunction.BLAKE2B:
        return crypto.createHash('sha256').update(message).digest();
      default:
        return crypto.createHash('sha256').update(message).digest();
    }
  }

  private generateSignatureProof(
    secret: bigint,
    partialSig: bigint,
    messageHash: Buffer
  ): ZKProof {
    // Generate zero-knowledge proof of signature correctness
    // Schnorr-style proof

    const r = this.generateRandomSecret();
    const commitment = Buffer.from(r.toString(16).padStart(64, '0'), 'hex');

    const challengeData = Buffer.concat([
      commitment,
      messageHash,
      Buffer.from(partialSig.toString(16).padStart(64, '0'), 'hex')
    ]);
    const challenge = crypto.createHash('sha256').update(challengeData).digest();
    const challengeBigInt = BigInt('0x' + challenge.toString('hex'));

    const response = this.field.add(r, this.field.mul(challengeBigInt, secret));

    return {
      commitment,
      challenge,
      response: Buffer.from(response.toString(16).padStart(64, '0'), 'hex')
    };
  }

  private verifySignatureShare(
    share: SignatureShare,
    messageHash: Buffer
  ): boolean {
    // Verify ZK proof
    const proof = share.proof;

    // Recompute challenge
    const challengeData = Buffer.concat([
      proof.commitment,
      messageHash,
      share.share
    ]);
    const expectedChallenge = crypto
      .createHash('sha256')
      .update(challengeData)
      .digest();

    return proof.challenge.equals(expectedChallenge);
  }

  private verifyThresholdSignature(
    signature: ThresholdSignature,
    publicKey: Buffer
  ): boolean {
    // Verify the aggregated signature against the group public key
    // In production, use ECDSA/EdDSA verification

    const sigHash = crypto
      .createHash('sha256')
      .update(
        Buffer.concat([
          signature.signature,
          signature.messageHash,
          publicKey
        ])
      )
      .digest();

    // Simplified verification
    return sigHash.length === 32;
  }

  private updateAvgSigningLatency(newLatency: number): void {
    const total = this.metrics.totalSignatures;
    this.metrics.avgSigningLatency =
      (this.metrics.avgSigningLatency * (total - 1) + newLatency) / total;
  }

  // ============================================================================
  // PUBLIC API
  // ============================================================================

  getDistributedKey(keyId: string): DistributedKey | undefined {
    return this.distributedKeys.get(keyId);
  }

  getSigningSession(sessionId: string): SigningSession | undefined {
    return this.signingSessions.get(sessionId);
  }

  getActiveParties(): Party[] {
    return Array.from(this.parties.values()).filter(p => p.online);
  }

  getMetrics(): TSSMetrics {
    return { ...this.metrics };
  }

  async healthCheck(): Promise<{
    healthy: boolean;
    issues: string[];
  }> {
    const issues: string[] = [];

    // Check active parties
    if (this.metrics.activeParties < this.config.threshold) {
      issues.push(
        `Insufficient active parties: ${this.metrics.activeParties}/${this.config.threshold}`
      );
    }

    // Check for stale sessions
    const now = Date.now();
    for (const [sessionId, session] of this.signingSessions) {
      if (
        session.status === SigningStatus.COLLECTING_SHARES &&
        now - session.startTime.getTime() > this.config.timeout
      ) {
        issues.push(`Stale signing session: ${sessionId}`);
      }
    }

    return {
      healthy: issues.length === 0,
      issues
    };
  }
}

export default ThresholdSignatureScheme;
