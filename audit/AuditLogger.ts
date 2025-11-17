import { EventEmitter } from 'events';
import * as crypto from 'crypto';

/**
 * IMMUTABLE AUDIT LOGGING SYSTEM
 *
 * HYPOTHESIS: Cryptographically secured, tamper-evident audit logs with
 * blockchain anchoring will satisfy regulatory requirements and enable
 * forensic analysis with zero data integrity concerns.
 *
 * SUCCESS METRICS:
 * - 100% log completeness (no missing events)
 * - Zero successful tamper attempts
 * - <10ms logging overhead
 * - Regulatory compliance (SOX, MiFID II, GDPR)
 * - Full reconstruction capability
 *
 * SECURITY CONSIDERATIONS:
 * - Merkle tree for tamper detection
 * - Hash chaining for sequential integrity
 * - Digital signatures for non-repudiation
 * - Encrypted storage for sensitive data
 * - Segregation of duties compliance
 */

// Audit Event Categories
enum AuditCategory {
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  DATA_ACCESS = 'data_access',
  DATA_MODIFICATION = 'data_modification',
  TRANSACTION = 'transaction',
  CONFIGURATION = 'configuration',
  SECURITY_EVENT = 'security_event',
  SYSTEM_EVENT = 'system_event',
  COMPLIANCE_EVENT = 'compliance_event',
  ADMIN_ACTION = 'admin_action'
}

// Audit Severity Levels
enum AuditSeverity {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical',
  ALERT = 'alert'
}

// Compliance Frameworks
enum ComplianceFramework {
  SOX = 'SOX',
  MIFID_II = 'MiFID_II',
  GDPR = 'GDPR',
  PCI_DSS = 'PCI_DSS',
  CCPA = 'CCPA',
  HIPAA = 'HIPAA'
}

// Interfaces
interface AuditEntry {
  id: string;
  timestamp: bigint;
  category: AuditCategory;
  severity: AuditSeverity;
  actor: AuditActor;
  action: string;
  resource: AuditResource;
  outcome: AuditOutcome;
  details: Map<string, any>;
  context: AuditContext;
  hash: string;
  previousHash: string;
  signature?: string;
}

interface AuditActor {
  id: string;
  type: 'user' | 'service' | 'system' | 'external';
  name: string;
  ipAddress?: string;
  userAgent?: string;
  sessionId?: string;
  roles?: string[];
}

interface AuditResource {
  id: string;
  type: string;
  name: string;
  path?: string;
  sensitivity: 'public' | 'internal' | 'confidential' | 'restricted';
}

interface AuditOutcome {
  success: boolean;
  resultCode?: string;
  errorMessage?: string;
  affectedRecords?: number;
}

interface AuditContext {
  correlationId: string;
  requestId?: string;
  traceId?: string;
  environment: string;
  service: string;
  version: string;
  region?: string;
  compliance?: ComplianceFramework[];
}

interface MerkleNode {
  hash: string;
  left?: MerkleNode;
  right?: MerkleNode;
  data?: string;
}

interface AuditQueryFilter {
  startTime?: bigint;
  endTime?: bigint;
  category?: AuditCategory;
  severity?: AuditSeverity;
  actorId?: string;
  resourceId?: string;
  action?: string;
  success?: boolean;
  compliance?: ComplianceFramework;
}

interface AuditStatistics {
  totalEntries: number;
  entriesByCategory: Map<AuditCategory, number>;
  entriesBySeverity: Map<AuditSeverity, number>;
  successRate: number;
  uniqueActors: number;
  uniqueResources: number;
  timeRange: { start: bigint; end: bigint };
}

interface RetentionPolicy {
  category: AuditCategory;
  retentionDays: number;
  archiveAfterDays: number;
  complianceFrameworks: ComplianceFramework[];
}

interface BlockchainAnchor {
  merkleRoot: string;
  blockNumber: number;
  transactionHash: string;
  timestamp: Date;
  entriesCount: number;
}

/**
 * Cryptographic hash chain for audit integrity
 */
class HashChain {
  private lastHash: string;

  constructor(genesisHash: string = '0'.repeat(64)) {
    this.lastHash = genesisHash;
  }

  /**
   * Add entry to chain and return hash
   */
  addEntry(data: string): { hash: string; previousHash: string } {
    const previousHash = this.lastHash;
    const combinedData = previousHash + data;
    const hash = this.computeHash(combinedData);
    this.lastHash = hash;

    return { hash, previousHash };
  }

  /**
   * Verify chain integrity
   */
  verifyChain(entries: Array<{ hash: string; previousHash: string; data: string }>): {
    valid: boolean;
    brokenAt?: number;
  } {
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      // Verify hash calculation
      const expectedHash = this.computeHash(entry.previousHash + entry.data);
      if (expectedHash !== entry.hash) {
        return { valid: false, brokenAt: i };
      }

      // Verify chain linkage
      if (i > 0) {
        const previousEntry = entries[i - 1];
        if (entry.previousHash !== previousEntry.hash) {
          return { valid: false, brokenAt: i };
        }
      }
    }

    return { valid: true };
  }

  private computeHash(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  getLastHash(): string {
    return this.lastHash;
  }
}

/**
 * Merkle Tree for batch verification
 */
class MerkleTree {
  private root?: MerkleNode;
  private leaves: string[] = [];

  /**
   * Build tree from audit entry hashes
   */
  buildTree(hashes: string[]): string {
    if (hashes.length === 0) {
      throw new Error('Cannot build tree with no leaves');
    }

    this.leaves = hashes;
    const nodes = hashes.map(hash => ({ hash, data: hash } as MerkleNode));
    this.root = this.buildLevel(nodes);

    return this.root.hash;
  }

  /**
   * Generate proof for a specific leaf
   */
  generateProof(leafIndex: number): string[] {
    if (!this.root || leafIndex >= this.leaves.length) {
      throw new Error('Invalid leaf index or tree not built');
    }

    const proof: string[] = [];
    let index = leafIndex;
    let levelSize = this.leaves.length;
    let levelHashes = this.leaves;

    while (levelSize > 1) {
      // Get sibling
      const isRight = index % 2 === 1;
      const siblingIndex = isRight ? index - 1 : index + 1;

      if (siblingIndex < levelSize) {
        proof.push((isRight ? 'L:' : 'R:') + levelHashes[siblingIndex]);
      }

      // Move to next level
      const nextLevel: string[] = [];
      for (let i = 0; i < levelSize; i += 2) {
        if (i + 1 < levelSize) {
          nextLevel.push(this.hashPair(levelHashes[i], levelHashes[i + 1]));
        } else {
          nextLevel.push(levelHashes[i]);
        }
      }

      index = Math.floor(index / 2);
      levelHashes = nextLevel;
      levelSize = nextLevel.length;
    }

    return proof;
  }

  /**
   * Verify a proof
   */
  verifyProof(leafHash: string, proof: string[], rootHash: string): boolean {
    let currentHash = leafHash;

    for (const proofElement of proof) {
      const [position, hash] = [proofElement.substring(0, 2), proofElement.substring(2)];

      if (position === 'L:') {
        currentHash = this.hashPair(hash, currentHash);
      } else {
        currentHash = this.hashPair(currentHash, hash);
      }
    }

    return currentHash === rootHash;
  }

  private buildLevel(nodes: MerkleNode[]): MerkleNode {
    if (nodes.length === 1) {
      return nodes[0];
    }

    const parentLevel: MerkleNode[] = [];

    for (let i = 0; i < nodes.length; i += 2) {
      if (i + 1 < nodes.length) {
        const left = nodes[i];
        const right = nodes[i + 1];
        const parentHash = this.hashPair(left.hash, right.hash);
        parentLevel.push({
          hash: parentHash,
          left,
          right
        });
      } else {
        // Odd node, promote to next level
        parentLevel.push(nodes[i]);
      }
    }

    return this.buildLevel(parentLevel);
  }

  private hashPair(left: string, right: string): string {
    return crypto.createHash('sha256').update(left + right).digest('hex');
  }

  getRoot(): string | undefined {
    return this.root?.hash;
  }
}

/**
 * Digital signature manager for non-repudiation
 */
class SignatureManager {
  private privateKey: crypto.KeyObject;
  private publicKey: crypto.KeyObject;

  constructor() {
    // Generate key pair (in production, would use HSM or secure key storage)
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Sign audit entry
   */
  sign(data: string): string {
    const signature = crypto.sign(null, Buffer.from(data), this.privateKey);
    return signature.toString('base64');
  }

  /**
   * Verify signature
   */
  verify(data: string, signature: string): boolean {
    try {
      return crypto.verify(
        null,
        Buffer.from(data),
        this.publicKey,
        Buffer.from(signature, 'base64')
      );
    } catch {
      return false;
    }
  }

  /**
   * Export public key for verification
   */
  exportPublicKey(): string {
    return this.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  }
}

/**
 * Main Audit Logger
 */
export class AuditLogger extends EventEmitter {
  private entries: AuditEntry[] = [];
  private hashChain: HashChain;
  private merkleTree: MerkleTree;
  private signatureManager: SignatureManager;
  private retentionPolicies: RetentionPolicy[] = [];
  private blockchainAnchors: BlockchainAnchor[] = [];
  private piiPatterns: RegExp[];
  private environment: string;
  private service: string;
  private version: string;

  constructor(
    environment: string,
    service: string,
    version: string,
    piiPatterns: RegExp[]
  ) {
    super();
    this.environment = environment;
    this.service = service;
    this.version = version;
    this.piiPatterns = piiPatterns;
    this.hashChain = new HashChain();
    this.merkleTree = new MerkleTree();
    this.signatureManager = new SignatureManager();
    this.initializeRetentionPolicies();
  }

  /**
   * Log an audit event
   */
  async logEvent(
    category: AuditCategory,
    severity: AuditSeverity,
    actor: AuditActor,
    action: string,
    resource: AuditResource,
    outcome: AuditOutcome,
    details: Map<string, any> = new Map(),
    compliance?: ComplianceFramework[]
  ): Promise<string> {
    const timestamp = this.getNanoseconds();
    const correlationId = crypto.randomBytes(16).toString('hex');

    // Sanitize PII from details
    const sanitizedDetails = this.sanitizeDetails(details);

    // Create context
    const context: AuditContext = {
      correlationId,
      environment: this.environment,
      service: this.service,
      version: this.version,
      compliance
    };

    // Generate entry ID
    const id = `audit_${timestamp}_${crypto.randomBytes(4).toString('hex')}`;

    // Prepare entry data for hashing (without hash fields)
    const entryData = {
      id,
      timestamp: timestamp.toString(),
      category,
      severity,
      actor,
      action,
      resource,
      outcome,
      details: Object.fromEntries(sanitizedDetails),
      context
    };

    const dataString = JSON.stringify(entryData);

    // Add to hash chain
    const { hash, previousHash } = this.hashChain.addEntry(dataString);

    // Sign the entry
    const signature = this.signatureManager.sign(hash);

    // Create complete entry
    const entry: AuditEntry = {
      id,
      timestamp,
      category,
      severity,
      actor,
      action,
      resource,
      outcome,
      details: sanitizedDetails,
      context,
      hash,
      previousHash,
      signature
    };

    this.entries.push(entry);

    // Emit event for real-time monitoring
    this.emit('auditEvent', entry);

    // Check if we need to create blockchain anchor
    if (this.entries.length % 1000 === 0) {
      await this.createBlockchainAnchor();
    }

    // Check for critical events
    if (severity === AuditSeverity.CRITICAL || severity === AuditSeverity.ALERT) {
      this.emit('criticalAuditEvent', entry);
    }

    // Check for security events
    if (category === AuditCategory.SECURITY_EVENT && !outcome.success) {
      this.emit('securityIncident', entry);
    }

    return id;
  }

  /**
   * Query audit logs
   */
  queryLogs(filter: AuditQueryFilter, limit: number = 100): AuditEntry[] {
    let results = this.entries;

    if (filter.startTime) {
      results = results.filter(e => e.timestamp >= filter.startTime!);
    }

    if (filter.endTime) {
      results = results.filter(e => e.timestamp <= filter.endTime!);
    }

    if (filter.category) {
      results = results.filter(e => e.category === filter.category);
    }

    if (filter.severity) {
      results = results.filter(e => e.severity === filter.severity);
    }

    if (filter.actorId) {
      results = results.filter(e => e.actor.id === filter.actorId);
    }

    if (filter.resourceId) {
      results = results.filter(e => e.resource.id === filter.resourceId);
    }

    if (filter.action) {
      results = results.filter(e => e.action.includes(filter.action));
    }

    if (filter.success !== undefined) {
      results = results.filter(e => e.outcome.success === filter.success);
    }

    if (filter.compliance) {
      results = results.filter(e =>
        e.context.compliance?.includes(filter.compliance!)
      );
    }

    return results.slice(-limit);
  }

  /**
   * Verify audit log integrity
   */
  verifyIntegrity(): {
    valid: boolean;
    totalEntries: number;
    invalidEntries: string[];
    signatureFailures: string[];
    chainBreaks: number[];
  } {
    const invalidEntries: string[] = [];
    const signatureFailures: string[] = [];
    const chainBreaks: number[] = [];

    // Verify each entry
    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];

      // Verify signature
      if (entry.signature) {
        const isValid = this.signatureManager.verify(entry.hash, entry.signature);
        if (!isValid) {
          signatureFailures.push(entry.id);
        }
      }

      // Verify hash chain
      if (i > 0) {
        const previousEntry = this.entries[i - 1];
        if (entry.previousHash !== previousEntry.hash) {
          chainBreaks.push(i);
        }
      }

      // Verify entry hash
      const entryData = {
        id: entry.id,
        timestamp: entry.timestamp.toString(),
        category: entry.category,
        severity: entry.severity,
        actor: entry.actor,
        action: entry.action,
        resource: entry.resource,
        outcome: entry.outcome,
        details: Object.fromEntries(entry.details),
        context: entry.context
      };

      const expectedHash = this.computeHash(entry.previousHash + JSON.stringify(entryData));
      if (expectedHash !== entry.hash) {
        invalidEntries.push(entry.id);
      }
    }

    const valid = invalidEntries.length === 0 &&
                  signatureFailures.length === 0 &&
                  chainBreaks.length === 0;

    return {
      valid,
      totalEntries: this.entries.length,
      invalidEntries,
      signatureFailures,
      chainBreaks
    };
  }

  /**
   * Generate compliance report
   */
  generateComplianceReport(
    framework: ComplianceFramework,
    startTime: bigint,
    endTime: bigint
  ): {
    framework: ComplianceFramework;
    period: { start: Date; end: Date };
    totalEvents: number;
    eventsByCategory: Map<AuditCategory, number>;
    securityIncidents: AuditEntry[];
    failedAuthentications: number;
    unauthorizedAccess: number;
    dataModifications: number;
    adminActions: AuditEntry[];
    integrityVerification: boolean;
  } {
    const relevantEntries = this.entries.filter(
      e => e.timestamp >= startTime &&
           e.timestamp <= endTime &&
           e.context.compliance?.includes(framework)
    );

    const eventsByCategory = new Map<AuditCategory, number>();
    for (const entry of relevantEntries) {
      const count = eventsByCategory.get(entry.category) || 0;
      eventsByCategory.set(entry.category, count + 1);
    }

    const securityIncidents = relevantEntries.filter(
      e => e.category === AuditCategory.SECURITY_EVENT && !e.outcome.success
    );

    const failedAuths = relevantEntries.filter(
      e => e.category === AuditCategory.AUTHENTICATION && !e.outcome.success
    ).length;

    const unauthorizedAccess = relevantEntries.filter(
      e => e.category === AuditCategory.AUTHORIZATION && !e.outcome.success
    ).length;

    const dataModifications = relevantEntries.filter(
      e => e.category === AuditCategory.DATA_MODIFICATION
    ).length;

    const adminActions = relevantEntries.filter(
      e => e.category === AuditCategory.ADMIN_ACTION
    );

    const integrity = this.verifyIntegrity();

    return {
      framework,
      period: {
        start: new Date(Number(startTime / 1000000n)),
        end: new Date(Number(endTime / 1000000n))
      },
      totalEvents: relevantEntries.length,
      eventsByCategory,
      securityIncidents,
      failedAuthentications: failedAuths,
      unauthorizedAccess,
      dataModifications,
      adminActions,
      integrityVerification: integrity.valid
    };
  }

  /**
   * Get audit statistics
   */
  getStatistics(): AuditStatistics {
    const entriesByCategory = new Map<AuditCategory, number>();
    const entriesBySeverity = new Map<AuditSeverity, number>();
    const actors = new Set<string>();
    const resources = new Set<string>();
    let successCount = 0;

    for (const entry of this.entries) {
      // By category
      const catCount = entriesByCategory.get(entry.category) || 0;
      entriesByCategory.set(entry.category, catCount + 1);

      // By severity
      const sevCount = entriesBySeverity.get(entry.severity) || 0;
      entriesBySeverity.set(entry.severity, sevCount + 1);

      // Actors
      actors.add(entry.actor.id);

      // Resources
      resources.add(entry.resource.id);

      // Success rate
      if (entry.outcome.success) {
        successCount++;
      }
    }

    const timeRange = {
      start: this.entries.length > 0 ? this.entries[0].timestamp : 0n,
      end: this.entries.length > 0 ? this.entries[this.entries.length - 1].timestamp : 0n
    };

    return {
      totalEntries: this.entries.length,
      entriesByCategory,
      entriesBySeverity,
      successRate: this.entries.length > 0 ? successCount / this.entries.length : 0,
      uniqueActors: actors.size,
      uniqueResources: resources.size,
      timeRange
    };
  }

  /**
   * Export audit logs
   */
  exportLogs(format: 'json' | 'csv' | 'syslog'): string {
    switch (format) {
      case 'json':
        return this.exportJSON();
      case 'csv':
        return this.exportCSV();
      case 'syslog':
        return this.exportSyslog();
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  /**
   * Create blockchain anchor for batch of entries
   */
  private async createBlockchainAnchor(): Promise<void> {
    const hashes = this.entries.slice(-1000).map(e => e.hash);
    const merkleRoot = this.merkleTree.buildTree(hashes);

    // In production, would actually submit to blockchain
    const anchor: BlockchainAnchor = {
      merkleRoot,
      blockNumber: Date.now(), // Simulated
      transactionHash: crypto.randomBytes(32).toString('hex'),
      timestamp: new Date(),
      entriesCount: 1000
    };

    this.blockchainAnchors.push(anchor);
    this.emit('blockchainAnchor', anchor);
  }

  /**
   * Verify entry against blockchain anchor
   */
  verifyAgainstAnchor(
    entryId: string,
    anchorIndex: number
  ): { verified: boolean; proof?: string[] } {
    const anchor = this.blockchainAnchors[anchorIndex];
    if (!anchor) {
      return { verified: false };
    }

    // Find entry and its position in the anchored batch
    const startIndex = anchorIndex * 1000;
    const endIndex = startIndex + 1000;
    const batch = this.entries.slice(startIndex, endIndex);

    const entryIndex = batch.findIndex(e => e.id === entryId);
    if (entryIndex === -1) {
      return { verified: false };
    }

    // Rebuild merkle tree for batch
    const hashes = batch.map(e => e.hash);
    this.merkleTree.buildTree(hashes);

    // Generate and verify proof
    const proof = this.merkleTree.generateProof(entryIndex);
    const verified = this.merkleTree.verifyProof(
      batch[entryIndex].hash,
      proof,
      anchor.merkleRoot
    );

    return { verified, proof };
  }

  private initializeRetentionPolicies(): void {
    // Default retention policies based on compliance requirements
    this.retentionPolicies = [
      {
        category: AuditCategory.TRANSACTION,
        retentionDays: 2555, // 7 years for SOX
        archiveAfterDays: 365,
        complianceFrameworks: [ComplianceFramework.SOX, ComplianceFramework.MIFID_II]
      },
      {
        category: AuditCategory.AUTHENTICATION,
        retentionDays: 365,
        archiveAfterDays: 90,
        complianceFrameworks: [ComplianceFramework.PCI_DSS]
      },
      {
        category: AuditCategory.DATA_ACCESS,
        retentionDays: 1825, // 5 years
        archiveAfterDays: 180,
        complianceFrameworks: [ComplianceFramework.GDPR]
      },
      {
        category: AuditCategory.SECURITY_EVENT,
        retentionDays: 3650, // 10 years
        archiveAfterDays: 365,
        complianceFrameworks: [ComplianceFramework.SOX, ComplianceFramework.PCI_DSS]
      }
    ];
  }

  private sanitizeDetails(details: Map<string, any>): Map<string, any> {
    const sanitized = new Map<string, any>();

    for (const [key, value] of details) {
      if (typeof value === 'string') {
        let sanitizedValue = value;
        for (const pattern of this.piiPatterns) {
          sanitizedValue = sanitizedValue.replace(pattern, '[REDACTED]');
        }
        sanitized.set(key, sanitizedValue);
      } else {
        sanitized.set(key, value);
      }
    }

    return sanitized;
  }

  private computeHash(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  private getNanoseconds(): bigint {
    const [seconds, nanoseconds] = process.hrtime();
    return BigInt(seconds) * 1000000000n + BigInt(nanoseconds);
  }

  private exportJSON(): string {
    return JSON.stringify(
      this.entries.map(entry => ({
        ...entry,
        timestamp: entry.timestamp.toString(),
        details: Object.fromEntries(entry.details)
      })),
      null,
      2
    );
  }

  private exportCSV(): string {
    const headers = [
      'id', 'timestamp', 'category', 'severity', 'actor_id', 'actor_type',
      'action', 'resource_id', 'resource_type', 'success', 'hash'
    ];

    const rows = this.entries.map(entry => [
      entry.id,
      entry.timestamp.toString(),
      entry.category,
      entry.severity,
      entry.actor.id,
      entry.actor.type,
      entry.action,
      entry.resource.id,
      entry.resource.type,
      entry.outcome.success,
      entry.hash
    ]);

    return [headers.join(','), ...rows.map(row => row.join(','))].join('\n');
  }

  private exportSyslog(): string {
    return this.entries.map(entry => {
      const priority = this.getSyslogPriority(entry.severity);
      const timestamp = new Date(Number(entry.timestamp / 1000000n)).toISOString();
      const message = `${entry.action} by ${entry.actor.id} on ${entry.resource.id}`;

      return `<${priority}>1 ${timestamp} ${this.service} ${entry.category} - - ${message}`;
    }).join('\n');
  }

  private getSyslogPriority(severity: AuditSeverity): number {
    // Syslog priority = facility * 8 + severity
    // Using local0 facility (16)
    const facilityCode = 16 * 8;

    switch (severity) {
      case AuditSeverity.ALERT:
        return facilityCode + 1;
      case AuditSeverity.CRITICAL:
        return facilityCode + 2;
      case AuditSeverity.ERROR:
        return facilityCode + 3;
      case AuditSeverity.WARNING:
        return facilityCode + 4;
      case AuditSeverity.INFO:
        return facilityCode + 6;
      default:
        return facilityCode + 7;
    }
  }
}

// Export types and enums
export {
  AuditCategory,
  AuditSeverity,
  ComplianceFramework,
  AuditEntry,
  AuditActor,
  AuditResource,
  AuditOutcome,
  AuditContext,
  AuditQueryFilter,
  AuditStatistics,
  HashChain,
  MerkleTree,
  SignatureManager
};
