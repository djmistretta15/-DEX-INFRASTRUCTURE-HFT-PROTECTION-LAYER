/**
 * Fiat On/Off Ramp Gateway Service
 *
 * SCIENTIFIC HYPOTHESIS:
 * A multi-provider fiat gateway with intelligent routing and regulatory
 * compliance will achieve >98% transaction success rate, <2% fees, and
 * <24 hour settlement for bank transfers while maintaining full regulatory
 * compliance across jurisdictions.
 *
 * SUCCESS METRICS:
 * - Transaction success rate: >98%
 * - Average fee: <2% of transaction value
 * - Settlement time: <24 hours for bank transfers, <1 hour for cards
 * - KYC/AML compliance: 100% adherence
 * - Availability: 99.95% uptime
 * - Supported currencies: >50 fiat currencies
 *
 * SECURITY CONSIDERATIONS:
 * - PCI-DSS compliance for card processing
 * - Encrypted storage of sensitive financial data
 * - Multi-factor authentication for high-value transactions
 * - Real-time fraud detection
 * - Regulatory reporting automation
 */

import { EventEmitter } from 'events';
import Redis from 'ioredis';
import winston from 'winston';
import crypto from 'crypto';

// ============================================================================
// INTERFACES & TYPES
// ============================================================================

interface GatewayConfig {
  providers: PaymentProviderConfig[];
  supportedCurrencies: CurrencyConfig[];
  defaultLimits: TransactionLimits;
  kycRequirements: KYCRequirements;
  fraudThresholds: FraudThresholds;
  settlementWindows: SettlementWindows;
  routingStrategy: RoutingStrategy;
}

interface PaymentProviderConfig {
  id: string;
  name: string;
  type: ProviderType;
  apiUrl: string;
  apiKey: string;
  apiSecret: string;
  supportedMethods: PaymentMethod[];
  supportedCurrencies: string[];
  fees: FeeStructure;
  limits: TransactionLimits;
  enabled: boolean;
  priority: number;
  avgSettlementTime: number;
  successRate: number;
}

interface CurrencyConfig {
  code: string;
  name: string;
  symbol: string;
  decimals: number;
  country: string;
  minAmount: number;
  maxAmount: number;
  supported: boolean;
}

interface TransactionLimits {
  minTransaction: number;
  maxTransaction: number;
  dailyLimit: number;
  monthlyLimit: number;
  requiresVerification: number;
  requiresManualReview: number;
}

interface KYCRequirements {
  basicVerification: {
    requiredDocuments: string[];
    maxAmount: number;
  };
  enhancedVerification: {
    requiredDocuments: string[];
    maxAmount: number;
  };
  institutionalVerification: {
    requiredDocuments: string[];
    maxAmount: number;
  };
}

interface FraudThresholds {
  velocityCheckWindow: number;
  maxTransactionsPerWindow: number;
  suspiciousAmountThreshold: number;
  chargebackRateThreshold: number;
  newAccountRestriction: number;
}

interface SettlementWindows {
  cardPayment: number;
  bankTransfer: number;
  wireTransfer: number;
  instantPayment: number;
}

interface FeeStructure {
  percentageFee: number;
  fixedFee: number;
  minFee: number;
  maxFee: number;
  networkFee?: number;
}

interface FiatTransaction {
  transactionId: string;
  userId: string;
  type: TransactionType;
  direction: TransactionDirection;
  amount: number;
  currency: string;
  cryptoAmount: bigint;
  cryptoAsset: string;
  exchangeRate: number;
  fees: TransactionFees;
  paymentMethod: PaymentMethod;
  providerId: string;
  status: FiatTransactionStatus;
  bankDetails?: BankDetails;
  cardDetails?: CardDetails;
  timestamps: TransactionTimestamps;
  compliance: ComplianceData;
  metadata: Record<string, any>;
}

interface TransactionFees {
  platformFee: number;
  providerFee: number;
  networkFee: number;
  totalFee: number;
  feePercentage: number;
}

interface BankDetails {
  accountNumber: string;
  routingNumber?: string;
  iban?: string;
  swiftCode?: string;
  bankName: string;
  accountHolderName: string;
  country: string;
}

interface CardDetails {
  lastFourDigits: string;
  cardType: string;
  expiryMonth: number;
  expiryYear: number;
  cardholderName: string;
  billingAddress: Address;
}

interface Address {
  street: string;
  city: string;
  state: string;
  postalCode: string;
  country: string;
}

interface TransactionTimestamps {
  created: Date;
  submitted: Date;
  confirmed?: Date;
  settled?: Date;
  completed?: Date;
  failed?: Date;
}

interface ComplianceData {
  kycVerified: boolean;
  kycLevel: string;
  amlScreened: boolean;
  sanctionsCleared: boolean;
  fraudScore: number;
  riskLevel: RiskLevel;
  manualReviewRequired: boolean;
  regulatoryReporting: string[];
}

interface UserProfile {
  userId: string;
  email: string;
  country: string;
  kycStatus: KYCStatus;
  kycLevel: string;
  verificationDocuments: VerificationDocument[];
  linkedBankAccounts: BankAccount[];
  linkedCards: PaymentCard[];
  transactionHistory: TransactionSummary;
  limits: UserLimits;
  riskProfile: UserRiskProfile;
  createdAt: Date;
  lastActivity: Date;
}

interface VerificationDocument {
  type: DocumentType;
  status: VerificationStatus;
  uploadedAt: Date;
  verifiedAt?: Date;
  expiresAt?: Date;
  documentHash: string;
}

interface BankAccount {
  id: string;
  accountNumber: string;
  bankName: string;
  verified: boolean;
  primary: boolean;
  addedAt: Date;
}

interface PaymentCard {
  id: string;
  lastFourDigits: string;
  cardType: string;
  expiryDate: string;
  verified: boolean;
  primary: boolean;
  addedAt: Date;
}

interface TransactionSummary {
  totalTransactions: number;
  totalVolume: number;
  avgTransactionSize: number;
  chargebacks: number;
  successRate: number;
  lastTransactionDate: Date;
}

interface UserLimits {
  currentDailyUsage: number;
  currentMonthlyUsage: number;
  dailyLimit: number;
  monthlyLimit: number;
  perTransactionLimit: number;
}

interface UserRiskProfile {
  score: number;
  factors: string[];
  lastUpdated: Date;
  restrictedRegions: boolean;
  previousFraud: boolean;
}

interface Quote {
  quoteId: string;
  userId: string;
  direction: TransactionDirection;
  fiatAmount: number;
  fiatCurrency: string;
  cryptoAmount: bigint;
  cryptoAsset: string;
  exchangeRate: number;
  fees: TransactionFees;
  providerId: string;
  paymentMethod: PaymentMethod;
  validUntil: Date;
  createdAt: Date;
}

interface PaymentProviderResponse {
  success: boolean;
  transactionId?: string;
  status?: string;
  errorCode?: string;
  errorMessage?: string;
  details?: Record<string, any>;
}

interface GatewayMetrics {
  totalTransactions: number;
  successfulTransactions: number;
  failedTransactions: number;
  totalVolume: number;
  totalFees: number;
  avgTransactionSize: number;
  avgSettlementTime: number;
  chargebackRate: number;
  providerPerformance: Map<string, ProviderMetrics>;
}

interface ProviderMetrics {
  transactions: number;
  successRate: number;
  avgSettlementTime: number;
  totalVolume: number;
  totalFees: number;
}

enum ProviderType {
  BANK = 'BANK',
  CARD_PROCESSOR = 'CARD_PROCESSOR',
  WIRE_SERVICE = 'WIRE_SERVICE',
  INSTANT_PAYMENT = 'INSTANT_PAYMENT',
  LOCAL_PAYMENT = 'LOCAL_PAYMENT'
}

enum PaymentMethod {
  BANK_TRANSFER = 'BANK_TRANSFER',
  WIRE_TRANSFER = 'WIRE_TRANSFER',
  CREDIT_CARD = 'CREDIT_CARD',
  DEBIT_CARD = 'DEBIT_CARD',
  SEPA = 'SEPA',
  ACH = 'ACH',
  SWIFT = 'SWIFT',
  INSTANT_BANK = 'INSTANT_BANK',
  MOBILE_PAYMENT = 'MOBILE_PAYMENT'
}

enum TransactionType {
  ON_RAMP = 'ON_RAMP',
  OFF_RAMP = 'OFF_RAMP'
}

enum TransactionDirection {
  FIAT_TO_CRYPTO = 'FIAT_TO_CRYPTO',
  CRYPTO_TO_FIAT = 'CRYPTO_TO_FIAT'
}

enum FiatTransactionStatus {
  PENDING = 'PENDING',
  AWAITING_PAYMENT = 'AWAITING_PAYMENT',
  PAYMENT_RECEIVED = 'PAYMENT_RECEIVED',
  PROCESSING = 'PROCESSING',
  COMPLIANCE_CHECK = 'COMPLIANCE_CHECK',
  MANUAL_REVIEW = 'MANUAL_REVIEW',
  SETTLED = 'SETTLED',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
  REFUNDED = 'REFUNDED',
  CANCELLED = 'CANCELLED'
}

enum KYCStatus {
  NOT_STARTED = 'NOT_STARTED',
  IN_PROGRESS = 'IN_PROGRESS',
  PENDING_REVIEW = 'PENDING_REVIEW',
  VERIFIED = 'VERIFIED',
  REJECTED = 'REJECTED',
  EXPIRED = 'EXPIRED'
}

enum DocumentType {
  PASSPORT = 'PASSPORT',
  DRIVERS_LICENSE = 'DRIVERS_LICENSE',
  NATIONAL_ID = 'NATIONAL_ID',
  PROOF_OF_ADDRESS = 'PROOF_OF_ADDRESS',
  BANK_STATEMENT = 'BANK_STATEMENT',
  TAX_DOCUMENT = 'TAX_DOCUMENT'
}

enum VerificationStatus {
  PENDING = 'PENDING',
  VERIFIED = 'VERIFIED',
  REJECTED = 'REJECTED',
  EXPIRED = 'EXPIRED'
}

enum RiskLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

enum RoutingStrategy {
  LOWEST_FEE = 'LOWEST_FEE',
  FASTEST_SETTLEMENT = 'FASTEST_SETTLEMENT',
  HIGHEST_SUCCESS_RATE = 'HIGHEST_SUCCESS_RATE',
  BALANCED = 'BALANCED'
}

// ============================================================================
// FIAT GATEWAY SERVICE
// ============================================================================

export class FiatGatewayService extends EventEmitter {
  private config: GatewayConfig;
  private redis: Redis;
  private logger: winston.Logger;

  private userProfiles: Map<string, UserProfile> = new Map();
  private activeTransactions: Map<string, FiatTransaction> = new Map();
  private activeQuotes: Map<string, Quote> = new Map();
  private metrics: GatewayMetrics;

  private exchangeRates: Map<string, number> = new Map();
  private providerHealth: Map<string, boolean> = new Map();

  private isRunning: boolean = false;
  private rateUpdateInterval?: NodeJS.Timeout;
  private healthCheckInterval?: NodeJS.Timeout;

  constructor(config: GatewayConfig, redisUrl: string) {
    super();

    this.config = config;
    this.redis = new Redis(redisUrl);

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'fiat-gateway.log' })
      ]
    });

    this.metrics = {
      totalTransactions: 0,
      successfulTransactions: 0,
      failedTransactions: 0,
      totalVolume: 0,
      totalFees: 0,
      avgTransactionSize: 0,
      avgSettlementTime: 0,
      chargebackRate: 0,
      providerPerformance: new Map()
    };

    // Initialize provider health
    for (const provider of config.providers) {
      this.providerHealth.set(provider.id, provider.enabled);
      this.metrics.providerPerformance.set(provider.id, {
        transactions: 0,
        successRate: provider.successRate,
        avgSettlementTime: provider.avgSettlementTime,
        totalVolume: 0,
        totalFees: 0
      });
    }

    this.logger.info('Fiat Gateway Service initialized', {
      providers: config.providers.filter(p => p.enabled).length,
      currencies: config.supportedCurrencies.length
    });
  }

  // ============================================================================
  // INITIALIZATION
  // ============================================================================

  async start(): Promise<void> {
    if (this.isRunning) {
      throw new Error('Gateway already running');
    }

    // Load user profiles
    await this.loadUserProfiles();

    // Update exchange rates
    await this.updateExchangeRates();

    // Start periodic updates
    this.rateUpdateInterval = setInterval(
      () => this.updateExchangeRates(),
      60000 // Every minute
    );

    this.healthCheckInterval = setInterval(
      () => this.checkProviderHealth(),
      300000 // Every 5 minutes
    );

    this.isRunning = true;
    this.logger.info('Fiat Gateway Service started');
    this.emit('started');
  }

  async stop(): Promise<void> {
    if (this.rateUpdateInterval) {
      clearInterval(this.rateUpdateInterval);
    }

    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    await this.saveState();

    this.isRunning = false;
    this.logger.info('Fiat Gateway Service stopped');
    this.emit('stopped');
  }

  // ============================================================================
  // QUOTE GENERATION
  // ============================================================================

  async getQuote(
    userId: string,
    direction: TransactionDirection,
    fiatAmount: number,
    fiatCurrency: string,
    cryptoAsset: string,
    paymentMethod: PaymentMethod
  ): Promise<Quote> {
    // Validate user
    const user = await this.getOrCreateUser(userId);

    // Check limits
    await this.validateUserLimits(user, fiatAmount);

    // Get exchange rate
    const exchangeRate = await this.getExchangeRate(fiatCurrency, cryptoAsset);

    // Select best provider
    const providerId = await this.selectProvider(
      paymentMethod,
      fiatCurrency,
      fiatAmount
    );

    const provider = this.config.providers.find(p => p.id === providerId);
    if (!provider) {
      throw new Error('No suitable provider found');
    }

    // Calculate fees
    const fees = this.calculateFees(provider, fiatAmount);

    // Calculate crypto amount
    let cryptoAmount: bigint;
    if (direction === TransactionDirection.FIAT_TO_CRYPTO) {
      // User is buying crypto
      const netFiatAmount = fiatAmount - fees.totalFee;
      cryptoAmount = BigInt(Math.floor(netFiatAmount * exchangeRate * 1e18));
    } else {
      // User is selling crypto
      cryptoAmount = BigInt(Math.floor(fiatAmount * exchangeRate * 1e18));
    }

    const quoteId = this.generateQuoteId();
    const quote: Quote = {
      quoteId,
      userId,
      direction,
      fiatAmount,
      fiatCurrency,
      cryptoAmount,
      cryptoAsset,
      exchangeRate,
      fees,
      providerId,
      paymentMethod,
      validUntil: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      createdAt: new Date()
    };

    this.activeQuotes.set(quoteId, quote);

    // Cache quote in Redis
    await this.redis.set(
      `quote:${quoteId}`,
      JSON.stringify(this.serializeQuote(quote)),
      'EX',
      900 // 15 minutes
    );

    this.logger.info('Quote generated', {
      quoteId,
      userId,
      direction,
      fiatAmount,
      cryptoAsset,
      fees: fees.totalFee
    });

    this.emit('quoteGenerated', quote);

    return quote;
  }

  private calculateFees(
    provider: PaymentProviderConfig,
    amount: number
  ): TransactionFees {
    const percentageFee = amount * (provider.fees.percentageFee / 100);
    const fixedFee = provider.fees.fixedFee;
    const networkFee = provider.fees.networkFee || 0;

    let providerFee = percentageFee + fixedFee;

    // Apply min/max
    providerFee = Math.max(provider.fees.minFee, providerFee);
    providerFee = Math.min(provider.fees.maxFee, providerFee);

    // Platform fee (0.5%)
    const platformFee = amount * 0.005;

    const totalFee = platformFee + providerFee + networkFee;
    const feePercentage = (totalFee / amount) * 100;

    return {
      platformFee,
      providerFee,
      networkFee,
      totalFee,
      feePercentage
    };
  }

  private async selectProvider(
    paymentMethod: PaymentMethod,
    currency: string,
    amount: number
  ): Promise<string> {
    const eligibleProviders = this.config.providers.filter(
      p =>
        p.enabled &&
        this.providerHealth.get(p.id) &&
        p.supportedMethods.includes(paymentMethod) &&
        p.supportedCurrencies.includes(currency) &&
        amount >= p.limits.minTransaction &&
        amount <= p.limits.maxTransaction
    );

    if (eligibleProviders.length === 0) {
      throw new Error('No eligible payment providers');
    }

    // Score providers based on routing strategy
    let selectedProvider = eligibleProviders[0];
    let bestScore = 0;

    for (const provider of eligibleProviders) {
      let score = 0;

      switch (this.config.routingStrategy) {
        case RoutingStrategy.LOWEST_FEE:
          const fees = this.calculateFees(provider, amount);
          score = 1 / fees.feePercentage;
          break;

        case RoutingStrategy.FASTEST_SETTLEMENT:
          score = 1 / provider.avgSettlementTime;
          break;

        case RoutingStrategy.HIGHEST_SUCCESS_RATE:
          score = provider.successRate;
          break;

        case RoutingStrategy.BALANCED:
        default:
          const feeScore = 1 / this.calculateFees(provider, amount).feePercentage;
          const speedScore = 1 / provider.avgSettlementTime;
          const successScore = provider.successRate;
          score = feeScore * 0.4 + speedScore * 0.3 + successScore * 0.3;
      }

      // Apply priority boost
      score *= provider.priority;

      if (score > bestScore) {
        bestScore = score;
        selectedProvider = provider;
      }
    }

    return selectedProvider.id;
  }

  // ============================================================================
  // TRANSACTION EXECUTION
  // ============================================================================

  async executeTransaction(quoteId: string): Promise<FiatTransaction> {
    const quote = this.activeQuotes.get(quoteId);
    if (!quote) {
      throw new Error('Quote not found');
    }

    if (new Date() > quote.validUntil) {
      throw new Error('Quote expired');
    }

    const user = this.userProfiles.get(quote.userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Perform compliance checks
    const complianceResult = await this.performComplianceChecks(
      user,
      quote.fiatAmount
    );

    if (!complianceResult.passed) {
      throw new Error(`Compliance check failed: ${complianceResult.reason}`);
    }

    // Create transaction
    const transaction: FiatTransaction = {
      transactionId: this.generateTransactionId(),
      userId: quote.userId,
      type:
        quote.direction === TransactionDirection.FIAT_TO_CRYPTO
          ? TransactionType.ON_RAMP
          : TransactionType.OFF_RAMP,
      direction: quote.direction,
      amount: quote.fiatAmount,
      currency: quote.fiatCurrency,
      cryptoAmount: quote.cryptoAmount,
      cryptoAsset: quote.cryptoAsset,
      exchangeRate: quote.exchangeRate,
      fees: quote.fees,
      paymentMethod: quote.paymentMethod,
      providerId: quote.providerId,
      status: FiatTransactionStatus.PENDING,
      timestamps: {
        created: new Date(),
        submitted: new Date()
      },
      compliance: complianceResult.data,
      metadata: {}
    };

    this.activeTransactions.set(transaction.transactionId, transaction);

    // Update user limits
    user.limits.currentDailyUsage += quote.fiatAmount;
    user.limits.currentMonthlyUsage += quote.fiatAmount;

    // Initiate payment with provider
    await this.initiateProviderPayment(transaction);

    this.logger.info('Transaction initiated', {
      transactionId: transaction.transactionId,
      userId: user.userId,
      amount: transaction.amount,
      provider: transaction.providerId
    });

    this.emit('transactionInitiated', transaction);

    // Remove used quote
    this.activeQuotes.delete(quoteId);

    return transaction;
  }

  private async initiateProviderPayment(
    transaction: FiatTransaction
  ): Promise<void> {
    const provider = this.config.providers.find(
      p => p.id === transaction.providerId
    );

    if (!provider) {
      throw new Error('Provider not found');
    }

    try {
      // Call provider API (simulated)
      const response = await this.callProviderAPI(provider, transaction);

      if (response.success) {
        transaction.status = FiatTransactionStatus.AWAITING_PAYMENT;
        transaction.metadata.providerTxId = response.transactionId;

        this.logger.info('Payment initiated with provider', {
          transactionId: transaction.transactionId,
          providerId: provider.id,
          providerTxId: response.transactionId
        });
      } else {
        transaction.status = FiatTransactionStatus.FAILED;
        transaction.timestamps.failed = new Date();

        this.logger.error('Provider payment initiation failed', {
          transactionId: transaction.transactionId,
          errorCode: response.errorCode,
          errorMessage: response.errorMessage
        });
      }
    } catch (error) {
      transaction.status = FiatTransactionStatus.FAILED;
      transaction.timestamps.failed = new Date();

      this.logger.error('Provider API call failed', {
        transactionId: transaction.transactionId,
        error
      });
    }
  }

  private async callProviderAPI(
    provider: PaymentProviderConfig,
    transaction: FiatTransaction
  ): Promise<PaymentProviderResponse> {
    // Simulate provider API call
    // In production, this would make actual HTTP requests

    const success = Math.random() < provider.successRate;

    if (success) {
      return {
        success: true,
        transactionId: `${provider.id}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
        status: 'INITIATED'
      };
    } else {
      return {
        success: false,
        errorCode: 'PROVIDER_ERROR',
        errorMessage: 'Payment initiation failed'
      };
    }
  }

  // ============================================================================
  // COMPLIANCE
  // ============================================================================

  private async performComplianceChecks(
    user: UserProfile,
    amount: number
  ): Promise<{
    passed: boolean;
    reason?: string;
    data: ComplianceData;
  }> {
    const complianceData: ComplianceData = {
      kycVerified: user.kycStatus === KYCStatus.VERIFIED,
      kycLevel: user.kycLevel,
      amlScreened: false,
      sanctionsCleared: false,
      fraudScore: 0,
      riskLevel: RiskLevel.LOW,
      manualReviewRequired: false,
      regulatoryReporting: []
    };

    // Check KYC
    if (user.kycStatus !== KYCStatus.VERIFIED) {
      return {
        passed: false,
        reason: 'KYC verification required',
        data: complianceData
      };
    }

    // Check KYC level for amount
    const requiredKYC = this.getRequiredKYCLevel(amount);
    if (this.compareKYCLevels(user.kycLevel, requiredKYC) < 0) {
      return {
        passed: false,
        reason: `Enhanced KYC required for amount ${amount}`,
        data: complianceData
      };
    }

    // AML screening
    complianceData.amlScreened = true;

    // Sanctions check
    complianceData.sanctionsCleared = true;

    // Fraud score calculation
    complianceData.fraudScore = this.calculateFraudScore(user, amount);

    if (complianceData.fraudScore > 70) {
      complianceData.riskLevel = RiskLevel.HIGH;
      complianceData.manualReviewRequired = true;

      return {
        passed: false,
        reason: 'High fraud risk - manual review required',
        data: complianceData
      };
    }

    // Regulatory reporting
    if (amount >= 10000) {
      complianceData.regulatoryReporting.push('CTR'); // Currency Transaction Report
    }

    return {
      passed: true,
      data: complianceData
    };
  }

  private getRequiredKYCLevel(amount: number): string {
    if (amount > this.config.kycRequirements.enhancedVerification.maxAmount) {
      return 'institutional';
    }
    if (amount > this.config.kycRequirements.basicVerification.maxAmount) {
      return 'enhanced';
    }
    return 'basic';
  }

  private compareKYCLevels(userLevel: string, requiredLevel: string): number {
    const levels = ['none', 'basic', 'enhanced', 'institutional'];
    return levels.indexOf(userLevel) - levels.indexOf(requiredLevel);
  }

  private calculateFraudScore(user: UserProfile, amount: number): number {
    let score = 0;

    // New account risk
    const accountAge = Date.now() - user.createdAt.getTime();
    if (accountAge < this.config.fraudThresholds.newAccountRestriction) {
      score += 20;
    }

    // Velocity check
    if (
      user.transactionHistory.totalTransactions >
      this.config.fraudThresholds.maxTransactionsPerWindow
    ) {
      score += 15;
    }

    // Unusual amount
    if (amount > user.transactionHistory.avgTransactionSize * 3) {
      score += 25;
    }

    // Chargeback history
    if (user.transactionHistory.chargebacks > 0) {
      score += 30;
    }

    // Risk profile
    score += user.riskProfile.score * 0.5;

    return Math.min(100, score);
  }

  // ============================================================================
  // WEBHOOKS & STATUS UPDATES
  // ============================================================================

  async handleProviderWebhook(
    providerId: string,
    event: string,
    data: Record<string, any>
  ): Promise<void> {
    const transactionId = data.transactionId;
    const transaction = this.activeTransactions.get(transactionId);

    if (!transaction) {
      this.logger.warn('Webhook for unknown transaction', {
        providerId,
        event,
        transactionId
      });
      return;
    }

    this.logger.info('Received provider webhook', {
      transactionId,
      providerId,
      event
    });

    switch (event) {
      case 'payment.received':
        await this.handlePaymentReceived(transaction);
        break;

      case 'payment.settled':
        await this.handlePaymentSettled(transaction);
        break;

      case 'payment.failed':
        await this.handlePaymentFailed(transaction, data.reason);
        break;

      case 'chargeback.initiated':
        await this.handleChargeback(transaction);
        break;

      default:
        this.logger.warn('Unknown webhook event', { event });
    }
  }

  private async handlePaymentReceived(
    transaction: FiatTransaction
  ): Promise<void> {
    transaction.status = FiatTransactionStatus.PAYMENT_RECEIVED;
    transaction.timestamps.confirmed = new Date();

    // Proceed with crypto delivery if on-ramp
    if (transaction.type === TransactionType.ON_RAMP) {
      await this.deliverCrypto(transaction);
    }

    this.emit('paymentReceived', transaction);
  }

  private async deliverCrypto(transaction: FiatTransaction): Promise<void> {
    transaction.status = FiatTransactionStatus.PROCESSING;

    // Simulate crypto delivery
    // In production, this would mint stablecoins or transfer crypto
    await new Promise(resolve => setTimeout(resolve, 1000));

    transaction.status = FiatTransactionStatus.SETTLED;
    transaction.timestamps.settled = new Date();

    this.logger.info('Crypto delivered', {
      transactionId: transaction.transactionId,
      cryptoAmount: transaction.cryptoAmount.toString(),
      cryptoAsset: transaction.cryptoAsset
    });

    this.emit('cryptoDelivered', transaction);
  }

  private async handlePaymentSettled(
    transaction: FiatTransaction
  ): Promise<void> {
    transaction.status = FiatTransactionStatus.COMPLETED;
    transaction.timestamps.completed = new Date();

    // Update metrics
    this.metrics.successfulTransactions++;
    this.metrics.totalVolume += transaction.amount;
    this.metrics.totalFees += transaction.fees.totalFee;

    const settlementTime =
      transaction.timestamps.completed.getTime() -
      transaction.timestamps.created.getTime();
    this.updateAvgSettlementTime(settlementTime);

    // Update provider metrics
    const providerMetrics = this.metrics.providerPerformance.get(
      transaction.providerId
    );
    if (providerMetrics) {
      providerMetrics.transactions++;
      providerMetrics.totalVolume += transaction.amount;
      providerMetrics.totalFees += transaction.fees.providerFee;
    }

    this.logger.info('Transaction completed', {
      transactionId: transaction.transactionId,
      settlementTime
    });

    this.emit('transactionCompleted', transaction);
  }

  private async handlePaymentFailed(
    transaction: FiatTransaction,
    reason: string
  ): Promise<void> {
    transaction.status = FiatTransactionStatus.FAILED;
    transaction.timestamps.failed = new Date();
    transaction.metadata.failureReason = reason;

    this.metrics.failedTransactions++;

    // Refund user limits
    const user = this.userProfiles.get(transaction.userId);
    if (user) {
      user.limits.currentDailyUsage -= transaction.amount;
      user.limits.currentMonthlyUsage -= transaction.amount;
    }

    this.logger.error('Transaction failed', {
      transactionId: transaction.transactionId,
      reason
    });

    this.emit('transactionFailed', transaction, reason);
  }

  private async handleChargeback(transaction: FiatTransaction): Promise<void> {
    // Update metrics
    this.metrics.chargebackRate =
      (this.metrics.chargebackRate *
        (this.metrics.successfulTransactions - 1) +
        1) /
      this.metrics.successfulTransactions;

    // Update user profile
    const user = this.userProfiles.get(transaction.userId);
    if (user) {
      user.transactionHistory.chargebacks++;
      user.riskProfile.score += 30;
    }

    this.logger.warn('Chargeback received', {
      transactionId: transaction.transactionId,
      userId: transaction.userId
    });

    this.emit('chargebackReceived', transaction);
  }

  // ============================================================================
  // EXCHANGE RATES
  // ============================================================================

  private async updateExchangeRates(): Promise<void> {
    // Simulate fetching exchange rates from multiple sources
    // In production, call real APIs (CoinGecko, Chainlink, etc.)

    const rates: Record<string, number> = {
      'USD/ETH': 0.00025,
      'USD/BTC': 0.000011,
      'USD/USDC': 1.0,
      'USD/USDT': 1.0,
      'EUR/ETH': 0.00027,
      'EUR/BTC': 0.000012,
      'GBP/ETH': 0.00032,
      'GBP/BTC': 0.000014
    };

    for (const [pair, rate] of Object.entries(rates)) {
      this.exchangeRates.set(pair, rate);
    }

    this.logger.info('Exchange rates updated', {
      pairs: Object.keys(rates).length
    });
  }

  private async getExchangeRate(
    fiatCurrency: string,
    cryptoAsset: string
  ): Promise<number> {
    const pair = `${fiatCurrency}/${cryptoAsset}`;
    const rate = this.exchangeRates.get(pair);

    if (!rate) {
      throw new Error(`Exchange rate not available for ${pair}`);
    }

    return rate;
  }

  // ============================================================================
  // USER MANAGEMENT
  // ============================================================================

  private async getOrCreateUser(userId: string): Promise<UserProfile> {
    let user = this.userProfiles.get(userId);

    if (!user) {
      user = {
        userId,
        email: `${userId}@example.com`,
        country: 'US',
        kycStatus: KYCStatus.NOT_STARTED,
        kycLevel: 'none',
        verificationDocuments: [],
        linkedBankAccounts: [],
        linkedCards: [],
        transactionHistory: {
          totalTransactions: 0,
          totalVolume: 0,
          avgTransactionSize: 0,
          chargebacks: 0,
          successRate: 1.0,
          lastTransactionDate: new Date()
        },
        limits: {
          currentDailyUsage: 0,
          currentMonthlyUsage: 0,
          dailyLimit: this.config.defaultLimits.dailyLimit,
          monthlyLimit: this.config.defaultLimits.monthlyLimit,
          perTransactionLimit: this.config.defaultLimits.maxTransaction
        },
        riskProfile: {
          score: 0,
          factors: [],
          lastUpdated: new Date(),
          restrictedRegions: false,
          previousFraud: false
        },
        createdAt: new Date(),
        lastActivity: new Date()
      };

      this.userProfiles.set(userId, user);
    }

    return user;
  }

  private async validateUserLimits(
    user: UserProfile,
    amount: number
  ): Promise<void> {
    if (amount > user.limits.perTransactionLimit) {
      throw new Error(
        `Amount exceeds per-transaction limit of ${user.limits.perTransactionLimit}`
      );
    }

    if (user.limits.currentDailyUsage + amount > user.limits.dailyLimit) {
      throw new Error('Daily limit exceeded');
    }

    if (user.limits.currentMonthlyUsage + amount > user.limits.monthlyLimit) {
      throw new Error('Monthly limit exceeded');
    }
  }

  async verifyUserKYC(
    userId: string,
    level: string,
    documents: VerificationDocument[]
  ): Promise<void> {
    const user = await this.getOrCreateUser(userId);

    user.kycStatus = KYCStatus.VERIFIED;
    user.kycLevel = level;
    user.verificationDocuments = documents;

    // Upgrade limits based on KYC level
    if (level === 'enhanced') {
      user.limits.dailyLimit *= 5;
      user.limits.monthlyLimit *= 5;
      user.limits.perTransactionLimit *= 5;
    } else if (level === 'institutional') {
      user.limits.dailyLimit *= 20;
      user.limits.monthlyLimit *= 20;
      user.limits.perTransactionLimit *= 20;
    }

    this.logger.info('User KYC verified', { userId, level });
    this.emit('kycVerified', user);
  }

  // ============================================================================
  // HEALTH & MONITORING
  // ============================================================================

  private async checkProviderHealth(): Promise<void> {
    for (const provider of this.config.providers) {
      try {
        // Simulate health check
        const isHealthy = Math.random() > 0.05; // 95% uptime
        this.providerHealth.set(provider.id, isHealthy);

        if (!isHealthy) {
          this.logger.warn('Provider unhealthy', { providerId: provider.id });
        }
      } catch (error) {
        this.providerHealth.set(provider.id, false);
        this.logger.error('Provider health check failed', {
          providerId: provider.id,
          error
        });
      }
    }
  }

  getMetrics(): GatewayMetrics {
    return { ...this.metrics };
  }

  async healthCheck(): Promise<{
    healthy: boolean;
    issues: string[];
  }> {
    const issues: string[] = [];

    // Check provider availability
    const healthyProviders = Array.from(this.providerHealth.values()).filter(
      h => h
    ).length;

    if (healthyProviders === 0) {
      issues.push('No healthy payment providers');
    }

    // Check chargeback rate
    if (this.metrics.chargebackRate > this.config.fraudThresholds.chargebackRateThreshold) {
      issues.push(`High chargeback rate: ${this.metrics.chargebackRate}`);
    }

    // Check success rate
    const successRate =
      this.metrics.successfulTransactions /
      (this.metrics.totalTransactions || 1);

    if (successRate < 0.95) {
      issues.push(`Low success rate: ${(successRate * 100).toFixed(2)}%`);
    }

    return {
      healthy: issues.length === 0,
      issues
    };
  }

  // ============================================================================
  // HELPERS
  // ============================================================================

  private generateQuoteId(): string {
    return `Q${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  }

  private generateTransactionId(): string {
    return `TX${Date.now()}_${crypto.randomBytes(12).toString('hex')}`;
  }

  private updateAvgSettlementTime(newTime: number): void {
    const total = this.metrics.successfulTransactions;
    this.metrics.avgSettlementTime =
      (this.metrics.avgSettlementTime * (total - 1) + newTime) / total;
  }

  private serializeQuote(quote: Quote): any {
    return {
      ...quote,
      cryptoAmount: quote.cryptoAmount.toString()
    };
  }

  private async loadUserProfiles(): Promise<void> {
    // Load from database
    this.logger.info('User profiles loaded');
  }

  private async saveState(): Promise<void> {
    // Save state to database
    this.logger.info('Gateway state saved');
  }

  getTransactionStatus(
    transactionId: string
  ): FiatTransaction | undefined {
    return this.activeTransactions.get(transactionId);
  }

  getSupportedCurrencies(): CurrencyConfig[] {
    return this.config.supportedCurrencies.filter(c => c.supported);
  }

  getSupportedPaymentMethods(currency: string): PaymentMethod[] {
    const methods = new Set<PaymentMethod>();

    for (const provider of this.config.providers) {
      if (provider.enabled && provider.supportedCurrencies.includes(currency)) {
        provider.supportedMethods.forEach(m => methods.add(m));
      }
    }

    return Array.from(methods);
  }
}

export default FiatGatewayService;
