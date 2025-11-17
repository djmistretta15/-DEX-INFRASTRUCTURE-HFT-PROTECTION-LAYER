import { EventEmitter } from 'events';
import * as crypto from 'crypto';

/**
 * KYC/AML COMPLIANCE ENGINE
 *
 * HYPOTHESIS: An automated compliance engine with real-time transaction
 * monitoring and risk scoring will achieve >99% regulatory compliance
 * while processing >10,000 transactions per second.
 *
 * SUCCESS METRICS:
 * - Compliance rate: >99.9%
 * - False positive rate: <1%
 * - Transaction processing: >10,000 TPS
 * - Risk detection latency: <100ms
 * - Regulatory report generation: <1 hour
 *
 * SECURITY CONSIDERATIONS:
 * - PII encryption at rest and in transit
 * - Data retention policies
 * - Access control and audit logging
 * - GDPR/CCPA compliance
 * - Sanctions list integration
 * - Travel rule compliance
 */

// KYC verification levels
enum KYCLevel {
  NONE = 'none',
  BASIC = 'basic',
  STANDARD = 'standard',
  ENHANCED = 'enhanced',
  INSTITUTIONAL = 'institutional'
}

// Risk levels
enum RiskLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
  PROHIBITED = 'prohibited'
}

// Verification status
enum VerificationStatus {
  PENDING = 'pending',
  IN_PROGRESS = 'in_progress',
  APPROVED = 'approved',
  REJECTED = 'rejected',
  EXPIRED = 'expired',
  SUSPENDED = 'suspended'
}

// Alert type
enum AlertType {
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  HIGH_VOLUME = 'high_volume',
  STRUCTURING = 'structuring',
  SANCTIONS_MATCH = 'sanctions_match',
  PEP_MATCH = 'pep_match',
  ADVERSE_MEDIA = 'adverse_media',
  UNUSUAL_PATTERN = 'unusual_pattern',
  VELOCITY_BREACH = 'velocity_breach',
  GEOGRAPHIC_RISK = 'geographic_risk'
}

// User identity
interface UserIdentity {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  dateOfBirth: Date;
  nationality: string;
  countryOfResidence: string;
  address: {
    street: string;
    city: string;
    state: string;
    postalCode: string;
    country: string;
  };
  phoneNumber: string;
  taxId?: string;
  idDocuments: IDDocument[];
  kycLevel: KYCLevel;
  status: VerificationStatus;
  riskScore: number;
  riskLevel: RiskLevel;
  verifiedAt?: Date;
  expiresAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

// ID document
interface IDDocument {
  type: 'passport' | 'drivers_license' | 'national_id' | 'proof_of_address';
  number: string;
  issuingCountry: string;
  expiryDate: Date;
  documentHash: string;
  verified: boolean;
  verifiedAt?: Date;
}

// Transaction for monitoring
interface MonitoredTransaction {
  id: string;
  userId: string;
  type: 'deposit' | 'withdrawal' | 'trade' | 'transfer';
  amount: bigint;
  currency: string;
  sourceAddress?: string;
  destinationAddress?: string;
  timestamp: Date;
  riskScore: number;
  flags: string[];
  reviewed: boolean;
}

// Compliance alert
interface ComplianceAlert {
  id: string;
  userId: string;
  transactionId?: string;
  type: AlertType;
  severity: RiskLevel;
  description: string;
  evidence: any;
  status: 'open' | 'investigating' | 'resolved' | 'reported';
  assignedTo?: string;
  createdAt: Date;
  resolvedAt?: Date;
}

// Sanctions entry
interface SanctionsEntry {
  name: string;
  aliases: string[];
  dateOfBirth?: string;
  nationality?: string;
  source: string;
  listType: string;
  addedAt: Date;
}

// Transaction limits
interface TransactionLimits {
  daily: bigint;
  weekly: bigint;
  monthly: bigint;
  perTransaction: bigint;
}

// Risk factor
interface RiskFactor {
  factor: string;
  weight: number;
  score: number;
  details: string;
}

// Compliance report
interface ComplianceReport {
  id: string;
  type: 'SAR' | 'STR' | 'CTR' | 'monthly' | 'annual';
  period: { start: Date; end: Date };
  generatedAt: Date;
  data: {
    totalTransactions: number;
    totalVolume: bigint;
    alertsGenerated: number;
    alertsResolved: number;
    riskBreakdown: Map<RiskLevel, number>;
    geographicDistribution: Map<string, number>;
    kycStatistics: Map<KYCLevel, number>;
  };
  submittedTo?: string;
  submittedAt?: Date;
}

// Main KYC/AML engine
export class KYCAMLEngine extends EventEmitter {
  private users: Map<string, UserIdentity> = new Map();
  private transactions: Map<string, MonitoredTransaction> = new Map();
  private alerts: Map<string, ComplianceAlert> = new Map();
  private sanctionsList: SanctionsEntry[] = [];
  private pepList: Set<string> = new Set();
  private highRiskCountries: Set<string> = new Set();
  private reports: Map<string, ComplianceReport> = new Map();

  // Transaction limits by KYC level
  private limitsByLevel: Map<KYCLevel, TransactionLimits> = new Map();

  // Configuration
  private encryptionKey: Buffer;
  private retentionPeriodDays: number = 2555; // 7 years
  private maxRiskScore: number = 100;

  constructor() {
    super();
    this.encryptionKey = crypto.randomBytes(32);
    this.initializeLimits();
    this.initializeHighRiskCountries();
    this.startMonitoring();
  }

  private initializeLimits(): void {
    this.limitsByLevel.set(KYCLevel.NONE, {
      daily: 0n,
      weekly: 0n,
      monthly: 0n,
      perTransaction: 0n
    });

    this.limitsByLevel.set(KYCLevel.BASIC, {
      daily: 1000n * 10n ** 18n, // $1,000
      weekly: 5000n * 10n ** 18n,
      monthly: 10000n * 10n ** 18n,
      perTransaction: 500n * 10n ** 18n
    });

    this.limitsByLevel.set(KYCLevel.STANDARD, {
      daily: 10000n * 10n ** 18n,
      weekly: 50000n * 10n ** 18n,
      monthly: 100000n * 10n ** 18n,
      perTransaction: 10000n * 10n ** 18n
    });

    this.limitsByLevel.set(KYCLevel.ENHANCED, {
      daily: 100000n * 10n ** 18n,
      weekly: 500000n * 10n ** 18n,
      monthly: 1000000n * 10n ** 18n,
      perTransaction: 100000n * 10n ** 18n
    });

    this.limitsByLevel.set(KYCLevel.INSTITUTIONAL, {
      daily: 10000000n * 10n ** 18n,
      weekly: 50000000n * 10n ** 18n,
      monthly: 100000000n * 10n ** 18n,
      perTransaction: 10000000n * 10n ** 18n
    });
  }

  private initializeHighRiskCountries(): void {
    // FATF high-risk jurisdictions (simplified)
    this.highRiskCountries.add('KP'); // North Korea
    this.highRiskCountries.add('IR'); // Iran
    this.highRiskCountries.add('MM'); // Myanmar
  }

  /**
   * Register new user for KYC
   */
  registerUser(userData: Omit<UserIdentity, 'id' | 'kycLevel' | 'status' | 'riskScore' | 'riskLevel' | 'createdAt' | 'updatedAt'>): UserIdentity {
    const id = crypto.randomBytes(16).toString('hex');

    // Encrypt PII
    const encryptedData = this.encryptPII(userData);

    const user: UserIdentity = {
      id,
      ...encryptedData,
      kycLevel: KYCLevel.NONE,
      status: VerificationStatus.PENDING,
      riskScore: 0,
      riskLevel: RiskLevel.LOW,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    this.users.set(id, user);
    this.emit('userRegistered', { userId: id });

    return user;
  }

  /**
   * Submit KYC documents
   */
  submitDocuments(userId: string, documents: IDDocument[]): boolean {
    const user = this.users.get(userId);
    if (!user) return false;

    user.idDocuments = documents;
    user.status = VerificationStatus.IN_PROGRESS;
    user.updatedAt = new Date();

    this.emit('documentsSubmitted', { userId, documentCount: documents.length });

    // Trigger verification
    this.verifyUser(userId);

    return true;
  }

  /**
   * Verify user KYC
   */
  async verifyUser(userId: string): Promise<void> {
    const user = this.users.get(userId);
    if (!user) return;

    // Screen against sanctions
    const sanctionsMatch = this.screenSanctions(user);
    if (sanctionsMatch) {
      user.status = VerificationStatus.REJECTED;
      user.riskLevel = RiskLevel.PROHIBITED;
      this.createAlert(userId, undefined, AlertType.SANCTIONS_MATCH, RiskLevel.CRITICAL, 'Sanctions list match detected', sanctionsMatch);
      return;
    }

    // Screen against PEP list
    const pepMatch = this.screenPEP(user);
    if (pepMatch) {
      this.createAlert(userId, undefined, AlertType.PEP_MATCH, RiskLevel.HIGH, 'Politically Exposed Person match', { name: user.firstName + ' ' + user.lastName });
    }

    // Calculate risk score
    const riskFactors = this.calculateRiskFactors(user);
    user.riskScore = riskFactors.reduce((sum, f) => sum + f.score * f.weight, 0);
    user.riskLevel = this.determineRiskLevel(user.riskScore);

    // Verify documents (simplified)
    const allDocsVerified = user.idDocuments.every(doc => {
      // In production, integrate with document verification API
      return doc.expiryDate > new Date();
    });

    if (allDocsVerified) {
      // Determine KYC level based on documents and risk
      user.kycLevel = this.determineKYCLevel(user);
      user.status = VerificationStatus.APPROVED;
      user.verifiedAt = new Date();
      user.expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year

      for (const doc of user.idDocuments) {
        doc.verified = true;
        doc.verifiedAt = new Date();
      }
    } else {
      user.status = VerificationStatus.REJECTED;
    }

    user.updatedAt = new Date();
    this.emit('userVerified', { userId, status: user.status, kycLevel: user.kycLevel });
  }

  /**
   * Monitor transaction
   */
  monitorTransaction(
    userId: string,
    type: 'deposit' | 'withdrawal' | 'trade' | 'transfer',
    amount: bigint,
    currency: string,
    sourceAddress?: string,
    destinationAddress?: string
  ): MonitoredTransaction | null {
    const user = this.users.get(userId);
    if (!user) return null;

    // Check if user is approved
    if (user.status !== VerificationStatus.APPROVED) {
      this.emit('transactionBlocked', { userId, reason: 'User not verified' });
      return null;
    }

    // Check transaction limits
    const limits = this.limitsByLevel.get(user.kycLevel);
    if (!limits) return null;

    if (amount > limits.perTransaction) {
      this.emit('transactionBlocked', { userId, reason: 'Exceeds per-transaction limit' });
      return null;
    }

    // Check daily/weekly/monthly limits
    const volumeCheck = this.checkVolumeLimit(userId, amount, limits);
    if (!volumeCheck.allowed) {
      this.emit('transactionBlocked', { userId, reason: volumeCheck.reason });
      return null;
    }

    const txId = crypto.randomBytes(16).toString('hex');
    const tx: MonitoredTransaction = {
      id: txId,
      userId,
      type,
      amount,
      currency,
      sourceAddress,
      destinationAddress,
      timestamp: new Date(),
      riskScore: 0,
      flags: [],
      reviewed: false
    };

    // Calculate transaction risk
    tx.riskScore = this.calculateTransactionRisk(tx, user);
    tx.flags = this.detectRedFlags(tx, user);

    this.transactions.set(txId, tx);

    // Generate alerts if needed
    if (tx.riskScore > 70) {
      this.createAlert(
        userId,
        txId,
        AlertType.SUSPICIOUS_ACTIVITY,
        this.determineRiskLevel(tx.riskScore),
        `High risk transaction detected: score ${tx.riskScore}`,
        { flags: tx.flags }
      );
    }

    // Check for structuring
    if (this.detectStructuring(userId)) {
      this.createAlert(
        userId,
        txId,
        AlertType.STRUCTURING,
        RiskLevel.HIGH,
        'Potential structuring behavior detected',
        { recentTransactions: this.getRecentTransactions(userId, 24) }
      );
    }

    this.emit('transactionMonitored', tx);
    return tx;
  }

  /**
   * Screen against sanctions list
   */
  screenSanctions(user: UserIdentity): SanctionsEntry | null {
    const fullName = `${user.firstName} ${user.lastName}`.toLowerCase();

    for (const entry of this.sanctionsList) {
      const entryName = entry.name.toLowerCase();

      // Exact match
      if (entryName === fullName) {
        return entry;
      }

      // Fuzzy match (simplified)
      if (this.calculateSimilarity(entryName, fullName) > 0.85) {
        return entry;
      }

      // Check aliases
      for (const alias of entry.aliases) {
        if (alias.toLowerCase() === fullName || this.calculateSimilarity(alias.toLowerCase(), fullName) > 0.85) {
          return entry;
        }
      }
    }

    return null;
  }

  /**
   * Screen against PEP list
   */
  screenPEP(user: UserIdentity): boolean {
    const fullName = `${user.firstName} ${user.lastName}`.toLowerCase();
    return this.pepList.has(fullName);
  }

  /**
   * Create compliance alert
   */
  createAlert(
    userId: string,
    transactionId: string | undefined,
    type: AlertType,
    severity: RiskLevel,
    description: string,
    evidence: any
  ): ComplianceAlert {
    const alert: ComplianceAlert = {
      id: crypto.randomBytes(16).toString('hex'),
      userId,
      transactionId,
      type,
      severity,
      description,
      evidence,
      status: 'open',
      createdAt: new Date()
    };

    this.alerts.set(alert.id, alert);
    this.emit('alertCreated', alert);

    // Auto-escalate critical alerts
    if (severity === RiskLevel.CRITICAL) {
      this.emit('criticalAlert', alert);
    }

    return alert;
  }

  /**
   * Resolve alert
   */
  resolveAlert(alertId: string, resolution: string, assignee: string): void {
    const alert = this.alerts.get(alertId);
    if (!alert) return;

    alert.status = 'resolved';
    alert.resolvedAt = new Date();
    alert.assignedTo = assignee;

    this.emit('alertResolved', { alertId, resolution });
  }

  /**
   * Generate compliance report
   */
  generateReport(
    type: 'SAR' | 'STR' | 'CTR' | 'monthly' | 'annual',
    startDate: Date,
    endDate: Date
  ): ComplianceReport {
    const txs = Array.from(this.transactions.values()).filter(
      tx => tx.timestamp >= startDate && tx.timestamp <= endDate
    );

    const userAlerts = Array.from(this.alerts.values()).filter(
      alert => alert.createdAt >= startDate && alert.createdAt <= endDate
    );

    const riskBreakdown = new Map<RiskLevel, number>();
    const geographicDistribution = new Map<string, number>();
    const kycStatistics = new Map<KYCLevel, number>();

    // Calculate risk breakdown
    for (const tx of txs) {
      const level = this.determineRiskLevel(tx.riskScore);
      riskBreakdown.set(level, (riskBreakdown.get(level) || 0) + 1);

      const user = this.users.get(tx.userId);
      if (user) {
        const country = user.countryOfResidence;
        geographicDistribution.set(country, (geographicDistribution.get(country) || 0) + 1);
      }
    }

    // Calculate KYC statistics
    for (const user of this.users.values()) {
      kycStatistics.set(user.kycLevel, (kycStatistics.get(user.kycLevel) || 0) + 1);
    }

    const report: ComplianceReport = {
      id: crypto.randomBytes(16).toString('hex'),
      type,
      period: { start: startDate, end: endDate },
      generatedAt: new Date(),
      data: {
        totalTransactions: txs.length,
        totalVolume: txs.reduce((sum, tx) => sum + tx.amount, 0n),
        alertsGenerated: userAlerts.length,
        alertsResolved: userAlerts.filter(a => a.status === 'resolved').length,
        riskBreakdown,
        geographicDistribution,
        kycStatistics
      }
    };

    this.reports.set(report.id, report);
    this.emit('reportGenerated', report);

    return report;
  }

  /**
   * Travel rule compliance (FATF Recommendation 16)
   */
  prepareTravelRuleData(
    transactionId: string
  ): { originator: any; beneficiary: any } | null {
    const tx = this.transactions.get(transactionId);
    if (!tx) return null;

    const user = this.users.get(tx.userId);
    if (!user) return null;

    // Travel rule requires originator and beneficiary info for transfers > $1000
    if (tx.amount < 1000n * 10n ** 18n) {
      return null;
    }

    return {
      originator: {
        name: `${user.firstName} ${user.lastName}`,
        accountNumber: user.id,
        address: user.address,
        dateOfBirth: user.dateOfBirth,
        nationality: user.nationality
      },
      beneficiary: {
        address: tx.destinationAddress
      }
    };
  }

  /**
   * Get user risk profile
   */
  getUserRiskProfile(userId: string): {
    user: UserIdentity | undefined;
    riskFactors: RiskFactor[];
    recentAlerts: ComplianceAlert[];
    transactionVolume: bigint;
  } {
    const user = this.users.get(userId);
    if (!user) {
      return {
        user: undefined,
        riskFactors: [],
        recentAlerts: [],
        transactionVolume: 0n
      };
    }

    const riskFactors = this.calculateRiskFactors(user);
    const recentAlerts = Array.from(this.alerts.values())
      .filter(a => a.userId === userId && a.status === 'open')
      .slice(0, 10);

    const userTxs = Array.from(this.transactions.values())
      .filter(tx => tx.userId === userId);
    const transactionVolume = userTxs.reduce((sum, tx) => sum + tx.amount, 0n);

    return {
      user,
      riskFactors,
      recentAlerts,
      transactionVolume
    };
  }

  /**
   * Get compliance statistics
   */
  getStatistics(): {
    totalUsers: number;
    verifiedUsers: number;
    pendingVerifications: number;
    openAlerts: number;
    totalTransactions: number;
    complianceRate: number;
  } {
    const users = Array.from(this.users.values());
    const alerts = Array.from(this.alerts.values());

    const verified = users.filter(u => u.status === VerificationStatus.APPROVED).length;
    const pending = users.filter(u => u.status === VerificationStatus.PENDING || u.status === VerificationStatus.IN_PROGRESS).length;
    const openAlerts = alerts.filter(a => a.status === 'open').length;
    const complianceRate = users.length > 0 ? (verified / users.length) * 100 : 0;

    return {
      totalUsers: users.length,
      verifiedUsers: verified,
      pendingVerifications: pending,
      openAlerts,
      totalTransactions: this.transactions.size,
      complianceRate
    };
  }

  /**
   * Update sanctions list
   */
  updateSanctionsList(entries: SanctionsEntry[]): void {
    this.sanctionsList = entries;
    this.emit('sanctionsListUpdated', { count: entries.length });

    // Re-screen all users
    for (const user of this.users.values()) {
      const match = this.screenSanctions(user);
      if (match) {
        user.status = VerificationStatus.SUSPENDED;
        this.createAlert(
          user.id,
          undefined,
          AlertType.SANCTIONS_MATCH,
          RiskLevel.CRITICAL,
          'Sanctions list match detected during routine screening',
          match
        );
      }
    }
  }

  private calculateRiskFactors(user: UserIdentity): RiskFactor[] {
    const factors: RiskFactor[] = [];

    // Geographic risk
    if (this.highRiskCountries.has(user.countryOfResidence)) {
      factors.push({
        factor: 'high_risk_country',
        weight: 0.3,
        score: 80,
        details: `Country ${user.countryOfResidence} is high risk`
      });
    } else {
      factors.push({
        factor: 'geographic',
        weight: 0.3,
        score: 10,
        details: 'Standard geographic risk'
      });
    }

    // Document quality
    const expiredDocs = user.idDocuments.filter(d => d.expiryDate < new Date());
    if (expiredDocs.length > 0) {
      factors.push({
        factor: 'expired_documents',
        weight: 0.2,
        score: 60,
        details: `${expiredDocs.length} expired documents`
      });
    }

    // Transaction history
    const userTxs = Array.from(this.transactions.values())
      .filter(tx => tx.userId === user.id);
    const highRiskTxs = userTxs.filter(tx => tx.riskScore > 50);

    if (highRiskTxs.length > userTxs.length * 0.3) {
      factors.push({
        factor: 'transaction_history',
        weight: 0.3,
        score: 70,
        details: 'High proportion of risky transactions'
      });
    } else {
      factors.push({
        factor: 'transaction_history',
        weight: 0.3,
        score: 20,
        details: 'Normal transaction pattern'
      });
    }

    // Alert history
    const userAlerts = Array.from(this.alerts.values())
      .filter(a => a.userId === user.id);

    if (userAlerts.length > 5) {
      factors.push({
        factor: 'alert_history',
        weight: 0.2,
        score: 80,
        details: `${userAlerts.length} historical alerts`
      });
    }

    return factors;
  }

  private calculateTransactionRisk(tx: MonitoredTransaction, user: UserIdentity): number {
    let score = user.riskScore * 0.3;

    // Amount-based risk
    if (tx.amount > 100000n * 10n ** 18n) {
      score += 30;
    } else if (tx.amount > 10000n * 10n ** 18n) {
      score += 15;
    }

    // Time-based risk (unusual hours)
    const hour = tx.timestamp.getHours();
    if (hour < 6 || hour > 22) {
      score += 10;
    }

    // Withdrawal vs deposit
    if (tx.type === 'withdrawal') {
      score += 10;
    }

    return Math.min(score, this.maxRiskScore);
  }

  private detectRedFlags(tx: MonitoredTransaction, user: UserIdentity): string[] {
    const flags: string[] = [];

    // Round number (potential structuring)
    if (tx.amount % (1000n * 10n ** 18n) === 0n) {
      flags.push('round_amount');
    }

    // Just below reporting threshold
    const reportingThreshold = 10000n * 10n ** 18n;
    if (tx.amount >= reportingThreshold * 95n / 100n && tx.amount < reportingThreshold) {
      flags.push('below_threshold');
    }

    // High risk country
    if (this.highRiskCountries.has(user.countryOfResidence)) {
      flags.push('high_risk_jurisdiction');
    }

    // New user large transaction
    const daysSinceRegistration = (Date.now() - user.createdAt.getTime()) / (24 * 60 * 60 * 1000);
    if (daysSinceRegistration < 7 && tx.amount > 10000n * 10n ** 18n) {
      flags.push('new_user_large_tx');
    }

    return flags;
  }

  private detectStructuring(userId: string): boolean {
    const recentTxs = this.getRecentTransactions(userId, 24);
    if (recentTxs.length < 3) return false;

    // Check for multiple transactions just below threshold
    const threshold = 10000n * 10n ** 18n;
    const suspiciousCount = recentTxs.filter(
      tx => tx.amount >= threshold * 90n / 100n && tx.amount < threshold
    ).length;

    return suspiciousCount >= 3;
  }

  private checkVolumeLimit(
    userId: string,
    amount: bigint,
    limits: TransactionLimits
  ): { allowed: boolean; reason: string } {
    const now = Date.now();
    const userTxs = Array.from(this.transactions.values())
      .filter(tx => tx.userId === userId);

    // Daily limit
    const dailyVolume = userTxs
      .filter(tx => now - tx.timestamp.getTime() < 24 * 60 * 60 * 1000)
      .reduce((sum, tx) => sum + tx.amount, 0n);

    if (dailyVolume + amount > limits.daily) {
      return { allowed: false, reason: 'Daily limit exceeded' };
    }

    // Weekly limit
    const weeklyVolume = userTxs
      .filter(tx => now - tx.timestamp.getTime() < 7 * 24 * 60 * 60 * 1000)
      .reduce((sum, tx) => sum + tx.amount, 0n);

    if (weeklyVolume + amount > limits.weekly) {
      return { allowed: false, reason: 'Weekly limit exceeded' };
    }

    // Monthly limit
    const monthlyVolume = userTxs
      .filter(tx => now - tx.timestamp.getTime() < 30 * 24 * 60 * 60 * 1000)
      .reduce((sum, tx) => sum + tx.amount, 0n);

    if (monthlyVolume + amount > limits.monthly) {
      return { allowed: false, reason: 'Monthly limit exceeded' };
    }

    return { allowed: true, reason: '' };
  }

  private getRecentTransactions(userId: string, hours: number): MonitoredTransaction[] {
    const cutoff = Date.now() - hours * 60 * 60 * 1000;
    return Array.from(this.transactions.values())
      .filter(tx => tx.userId === userId && tx.timestamp.getTime() > cutoff);
  }

  private determineRiskLevel(score: number): RiskLevel {
    if (score >= 80) return RiskLevel.CRITICAL;
    if (score >= 60) return RiskLevel.HIGH;
    if (score >= 40) return RiskLevel.MEDIUM;
    return RiskLevel.LOW;
  }

  private determineKYCLevel(user: UserIdentity): KYCLevel {
    const docTypes = new Set(user.idDocuments.map(d => d.type));

    if (
      docTypes.has('passport') &&
      docTypes.has('proof_of_address') &&
      user.riskScore < 40
    ) {
      return KYCLevel.ENHANCED;
    }

    if (docTypes.has('passport') || docTypes.has('national_id')) {
      return KYCLevel.STANDARD;
    }

    if (docTypes.has('drivers_license')) {
      return KYCLevel.BASIC;
    }

    return KYCLevel.NONE;
  }

  private encryptPII(data: any): any {
    // In production, encrypt sensitive fields
    // Simplified: return as-is
    return data;
  }

  private calculateSimilarity(str1: string, str2: string): number {
    // Simplified Levenshtein distance
    const len1 = str1.length;
    const len2 = str2.length;
    const maxLen = Math.max(len1, len2);

    if (maxLen === 0) return 1;

    let matches = 0;
    for (let i = 0; i < Math.min(len1, len2); i++) {
      if (str1[i] === str2[i]) matches++;
    }

    return matches / maxLen;
  }

  private startMonitoring(): void {
    // Periodic re-verification check
    setInterval(() => {
      const now = new Date();
      for (const user of this.users.values()) {
        if (user.expiresAt && user.expiresAt < now) {
          user.status = VerificationStatus.EXPIRED;
          this.emit('verificationExpired', { userId: user.id });
        }
      }
    }, 3600000); // Every hour

    // Clean old transactions (respect retention period)
    setInterval(() => {
      const cutoff = Date.now() - this.retentionPeriodDays * 24 * 60 * 60 * 1000;
      for (const [id, tx] of this.transactions) {
        if (tx.timestamp.getTime() < cutoff) {
          this.transactions.delete(id);
        }
      }
    }, 86400000); // Every day
  }
}

// Export types
export {
  KYCLevel,
  RiskLevel,
  VerificationStatus,
  AlertType,
  UserIdentity,
  IDDocument,
  MonitoredTransaction,
  ComplianceAlert,
  SanctionsEntry,
  TransactionLimits,
  RiskFactor,
  ComplianceReport
};
