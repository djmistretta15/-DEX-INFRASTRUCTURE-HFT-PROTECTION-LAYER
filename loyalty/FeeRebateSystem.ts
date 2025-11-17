import { EventEmitter } from 'events';
import * as crypto from 'crypto';

/**
 * FEE REBATE AND LOYALTY SYSTEM
 *
 * HYPOTHESIS: A tiered loyalty program with volume-based rebates and
 * maker incentives will increase user retention by 40% while maintaining
 * profitable unit economics.
 *
 * SUCCESS METRICS:
 * - User retention increase >40%
 * - Average trading volume per user increase >25%
 * - Referral program ROI >200%
 * - Fair distribution (top 10% users get <50% of rebates)
 * - Net revenue positive after rebates
 *
 * SECURITY CONSIDERATIONS:
 * - Wash trading detection
 * - Referral fraud prevention
 * - Sybil attack resistance
 * - Rate limiting on rebate claims
 * - Audit trail for all distributions
 */

// User tier levels
enum LoyaltyTier {
  BRONZE = 'bronze',
  SILVER = 'silver',
  GOLD = 'gold',
  PLATINUM = 'platinum',
  DIAMOND = 'diamond',
  VIP = 'vip'
}

// Rebate types
enum RebateType {
  TRADING_FEE = 'trading_fee',
  MAKER_REBATE = 'maker_rebate',
  VOLUME_BONUS = 'volume_bonus',
  REFERRAL_REWARD = 'referral_reward',
  STAKING_BONUS = 'staking_bonus',
  LOYALTY_POINTS = 'loyalty_points'
}

// Tier configuration
interface TierConfig {
  tier: LoyaltyTier;
  minVolume30d: bigint;
  feeDiscount: number; // basis points
  makerRebate: number; // basis points
  referralBonus: number; // basis points
  stakingMultiplier: number;
  withdrawalLimit: bigint;
  prioritySupport: boolean;
}

// User loyalty profile
interface UserLoyaltyProfile {
  userId: string;
  address: string;
  tier: LoyaltyTier;
  totalVolume: bigint;
  volume30d: bigint;
  totalFeesPaid: bigint;
  totalRebatesEarned: bigint;
  pendingRebates: bigint;
  loyaltyPoints: bigint;
  referralCode: string;
  referredBy?: string;
  referralCount: number;
  referralEarnings: bigint;
  joinedAt: Date;
  lastTradeAt?: Date;
  tierUpgradeAt?: Date;
  consecutiveTradingDays: number;
  achievements: Achievement[];
}

// Achievement system
interface Achievement {
  id: string;
  name: string;
  description: string;
  reward: bigint;
  earnedAt: Date;
  claimed: boolean;
}

// Rebate transaction
interface RebateTransaction {
  id: string;
  userId: string;
  type: RebateType;
  amount: bigint;
  sourceTransaction?: string;
  calculatedAt: Date;
  claimedAt?: Date;
  status: 'pending' | 'claimable' | 'claimed' | 'expired';
  expiresAt: Date;
}

// Trading activity for rebate calculation
interface TradingActivity {
  userId: string;
  tradeId: string;
  timestamp: Date;
  pair: string;
  side: 'buy' | 'sell';
  orderType: 'market' | 'limit';
  isMaker: boolean;
  volume: bigint;
  fee: bigint;
  price: bigint;
}

// Referral tracking
interface ReferralRecord {
  referrerCode: string;
  refereeId: string;
  registeredAt: Date;
  firstTradeAt?: Date;
  totalVolumeGenerated: bigint;
  totalRewardsEarned: bigint;
  active: boolean;
}

// Fee schedule
interface FeeSchedule {
  pair: string;
  baseMakerFee: number; // basis points
  baseTakerFee: number; // basis points
  minFee: number;
  maxFee: number;
}

// Configuration
interface LoyaltySystemConfig {
  rebateClaimPeriodDays: number;
  minClaimableAmount: bigint;
  washTradeThreshold: number; // percentage of self-trades
  referralLockupDays: number;
  maxReferralDepth: number;
  pointsToTokenRatio: bigint;
  volumeDecayRate: number; // Daily decay for 30d volume
}

/**
 * Tier Manager - handles user tier calculations
 */
class TierManager {
  private tierConfigs: Map<LoyaltyTier, TierConfig>;

  constructor() {
    this.tierConfigs = this.initializeTiers();
  }

  private initializeTiers(): Map<LoyaltyTier, TierConfig> {
    const configs = new Map<LoyaltyTier, TierConfig>();

    configs.set(LoyaltyTier.BRONZE, {
      tier: LoyaltyTier.BRONZE,
      minVolume30d: 0n,
      feeDiscount: 0,
      makerRebate: 0,
      referralBonus: 1000, // 10%
      stakingMultiplier: 1.0,
      withdrawalLimit: 10000000000000000000000n, // 10k tokens
      prioritySupport: false
    });

    configs.set(LoyaltyTier.SILVER, {
      tier: LoyaltyTier.SILVER,
      minVolume30d: 10000000000000000000000n, // 10k
      feeDiscount: 500, // 5%
      makerRebate: 100, // 1%
      referralBonus: 1500,
      stakingMultiplier: 1.1,
      withdrawalLimit: 50000000000000000000000n,
      prioritySupport: false
    });

    configs.set(LoyaltyTier.GOLD, {
      tier: LoyaltyTier.GOLD,
      minVolume30d: 100000000000000000000000n, // 100k
      feeDiscount: 1000, // 10%
      makerRebate: 200, // 2%
      referralBonus: 2000,
      stakingMultiplier: 1.25,
      withdrawalLimit: 200000000000000000000000n,
      prioritySupport: true
    });

    configs.set(LoyaltyTier.PLATINUM, {
      tier: LoyaltyTier.PLATINUM,
      minVolume30d: 500000000000000000000000n, // 500k
      feeDiscount: 1500, // 15%
      makerRebate: 300, // 3%
      referralBonus: 2500,
      stakingMultiplier: 1.5,
      withdrawalLimit: 1000000000000000000000000n,
      prioritySupport: true
    });

    configs.set(LoyaltyTier.DIAMOND, {
      tier: LoyaltyTier.DIAMOND,
      minVolume30d: 1000000000000000000000000n, // 1M
      feeDiscount: 2000, // 20%
      makerRebate: 400, // 4%
      referralBonus: 3000,
      stakingMultiplier: 2.0,
      withdrawalLimit: 10000000000000000000000000n,
      prioritySupport: true
    });

    configs.set(LoyaltyTier.VIP, {
      tier: LoyaltyTier.VIP,
      minVolume30d: 10000000000000000000000000n, // 10M
      feeDiscount: 3000, // 30%
      makerRebate: 500, // 5%
      referralBonus: 4000,
      stakingMultiplier: 3.0,
      withdrawalLimit: 0n, // Unlimited
      prioritySupport: true
    });

    return configs;
  }

  /**
   * Calculate user's tier based on 30-day volume
   */
  calculateTier(volume30d: bigint): LoyaltyTier {
    const tiers = [
      LoyaltyTier.VIP,
      LoyaltyTier.DIAMOND,
      LoyaltyTier.PLATINUM,
      LoyaltyTier.GOLD,
      LoyaltyTier.SILVER,
      LoyaltyTier.BRONZE
    ];

    for (const tier of tiers) {
      const config = this.tierConfigs.get(tier)!;
      if (volume30d >= config.minVolume30d) {
        return tier;
      }
    }

    return LoyaltyTier.BRONZE;
  }

  /**
   * Get tier configuration
   */
  getTierConfig(tier: LoyaltyTier): TierConfig {
    return this.tierConfigs.get(tier)!;
  }

  /**
   * Get all tier configs
   */
  getAllTiers(): TierConfig[] {
    return Array.from(this.tierConfigs.values());
  }

  /**
   * Calculate progress to next tier
   */
  getProgressToNextTier(
    currentTier: LoyaltyTier,
    currentVolume: bigint
  ): { nextTier: LoyaltyTier | null; progress: number; volumeNeeded: bigint } {
    const tierOrder = [
      LoyaltyTier.BRONZE,
      LoyaltyTier.SILVER,
      LoyaltyTier.GOLD,
      LoyaltyTier.PLATINUM,
      LoyaltyTier.DIAMOND,
      LoyaltyTier.VIP
    ];

    const currentIndex = tierOrder.indexOf(currentTier);

    if (currentIndex === tierOrder.length - 1) {
      // Already at highest tier
      return { nextTier: null, progress: 100, volumeNeeded: 0n };
    }

    const nextTier = tierOrder[currentIndex + 1];
    const nextTierConfig = this.tierConfigs.get(nextTier)!;
    const currentTierConfig = this.tierConfigs.get(currentTier)!;

    const volumeRange = nextTierConfig.minVolume30d - currentTierConfig.minVolume30d;
    const volumeProgress = currentVolume - currentTierConfig.minVolume30d;

    const progress = Math.min(100, Number((volumeProgress * 10000n) / volumeRange) / 100);
    const volumeNeeded = nextTierConfig.minVolume30d - currentVolume;

    return {
      nextTier,
      progress: progress > 0 ? progress : 0,
      volumeNeeded: volumeNeeded > 0n ? volumeNeeded : 0n
    };
  }
}

/**
 * Wash Trade Detector
 */
class WashTradeDetector {
  private threshold: number;
  private recentTrades: Map<string, TradingActivity[]> = new Map();
  private windowMs: number = 24 * 60 * 60 * 1000; // 24 hours

  constructor(threshold: number) {
    this.threshold = threshold;
  }

  /**
   * Record trade for analysis
   */
  recordTrade(activity: TradingActivity): void {
    if (!this.recentTrades.has(activity.userId)) {
      this.recentTrades.set(activity.userId, []);
    }

    this.recentTrades.get(activity.userId)!.push(activity);

    // Clean old trades
    this.cleanOldTrades(activity.userId);
  }

  /**
   * Detect wash trading patterns
   */
  detectWashTrading(userId: string): {
    isWashTrading: boolean;
    score: number;
    patterns: string[];
  } {
    const trades = this.recentTrades.get(userId) || [];
    if (trades.length < 10) {
      return { isWashTrading: false, score: 0, patterns: [] };
    }

    const patterns: string[] = [];
    let score = 0;

    // Pattern 1: High frequency same-pair trading
    const pairFrequency = this.analyzePairFrequency(trades);
    if (pairFrequency.maxFrequency > 0.8) {
      score += 30;
      patterns.push('High concentration on single pair');
    }

    // Pattern 2: Opposite trades within short time
    const oppositeTradeRatio = this.analyzeOppositeTrades(trades);
    if (oppositeTradeRatio > 0.7) {
      score += 40;
      patterns.push('High ratio of opposite trades');
    }

    // Pattern 3: Consistent loss-making patterns
    const profitPattern = this.analyzeProfitPattern(trades);
    if (profitPattern.consistentLosses) {
      score += 20;
      patterns.push('Consistent loss pattern');
    }

    // Pattern 4: Unusual timing patterns
    const timingScore = this.analyzeTimingPatterns(trades);
    if (timingScore > 0.7) {
      score += 10;
      patterns.push('Suspicious timing patterns');
    }

    return {
      isWashTrading: score >= this.threshold,
      score,
      patterns
    };
  }

  private cleanOldTrades(userId: string): void {
    const trades = this.recentTrades.get(userId);
    if (!trades) return;

    const cutoff = Date.now() - this.windowMs;
    const filtered = trades.filter(t => t.timestamp.getTime() > cutoff);
    this.recentTrades.set(userId, filtered);
  }

  private analyzePairFrequency(trades: TradingActivity[]): { maxFrequency: number } {
    const pairCounts = new Map<string, number>();

    for (const trade of trades) {
      const count = pairCounts.get(trade.pair) || 0;
      pairCounts.set(trade.pair, count + 1);
    }

    const maxCount = Math.max(...Array.from(pairCounts.values()));
    return { maxFrequency: maxCount / trades.length };
  }

  private analyzeOppositeTrades(trades: TradingActivity[]): number {
    let oppositeCount = 0;

    for (let i = 0; i < trades.length - 1; i++) {
      const current = trades[i];
      const next = trades[i + 1];

      // Check if trades are opposite within 5 minutes
      const timeDiff = next.timestamp.getTime() - current.timestamp.getTime();
      if (
        timeDiff < 5 * 60 * 1000 &&
        current.pair === next.pair &&
        current.side !== next.side
      ) {
        oppositeCount++;
      }
    }

    return trades.length > 1 ? oppositeCount / (trades.length - 1) : 0;
  }

  private analyzeProfitPattern(
    trades: TradingActivity[]
  ): { consistentLosses: boolean } {
    // Simplified: would analyze actual P&L in production
    return { consistentLosses: false };
  }

  private analyzeTimingPatterns(trades: TradingActivity[]): number {
    // Check for bot-like precision timing
    const intervals: number[] = [];

    for (let i = 1; i < trades.length; i++) {
      const interval = trades[i].timestamp.getTime() - trades[i - 1].timestamp.getTime();
      intervals.push(interval);
    }

    if (intervals.length < 5) return 0;

    // Calculate variance - low variance indicates automated trading
    const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / intervals.length;
    const cv = Math.sqrt(variance) / avg; // Coefficient of variation

    // Low CV indicates suspicious regularity
    return cv < 0.3 ? 0.8 : cv < 0.5 ? 0.5 : 0;
  }
}

/**
 * Rebate Calculator
 */
class RebateCalculator {
  private tierManager: TierManager;
  private feeSchedules: Map<string, FeeSchedule> = new Map();

  constructor(tierManager: TierManager) {
    this.tierManager = tierManager;
    this.initializeDefaultSchedules();
  }

  private initializeDefaultSchedules(): void {
    // Default fee schedule
    this.feeSchedules.set('default', {
      pair: 'default',
      baseMakerFee: 10, // 0.1%
      baseTakerFee: 30, // 0.3%
      minFee: 5,
      maxFee: 50
    });
  }

  /**
   * Calculate effective fee for a trade
   */
  calculateEffectiveFee(
    userProfile: UserLoyaltyProfile,
    volume: bigint,
    isMaker: boolean,
    pair: string = 'default'
  ): {
    baseFee: bigint;
    discount: bigint;
    rebate: bigint;
    netFee: bigint;
  } {
    const tierConfig = this.tierManager.getTierConfig(userProfile.tier);
    const feeSchedule = this.feeSchedules.get(pair) || this.feeSchedules.get('default')!;

    // Base fee calculation
    const baseFeeRate = isMaker ? feeSchedule.baseMakerFee : feeSchedule.baseTakerFee;
    const baseFee = (volume * BigInt(baseFeeRate)) / 10000n;

    // Tier discount
    const discount = (baseFee * BigInt(tierConfig.feeDiscount)) / 10000n;

    // Maker rebate
    const rebate = isMaker
      ? (volume * BigInt(tierConfig.makerRebate)) / 10000n
      : 0n;

    // Net fee (can be negative for makers with high rebates)
    const netFee = baseFee - discount - rebate;

    return {
      baseFee,
      discount,
      rebate,
      netFee: netFee > 0n ? netFee : 0n
    };
  }

  /**
   * Calculate volume bonus
   */
  calculateVolumeBonus(
    userProfile: UserLoyaltyProfile,
    volumeThisEpoch: bigint
  ): bigint {
    // Volume milestones
    const milestones = [
      { volume: 100000000000000000000000n, bonus: 100000000000000000000n }, // 100k -> 100 tokens
      { volume: 500000000000000000000000n, bonus: 500000000000000000000n }, // 500k -> 500 tokens
      { volume: 1000000000000000000000000n, bonus: 1500000000000000000000n } // 1M -> 1500 tokens
    ];

    let totalBonus = 0n;

    for (const milestone of milestones) {
      if (volumeThisEpoch >= milestone.volume) {
        totalBonus += milestone.bonus;
      }
    }

    // Apply tier multiplier
    const tierConfig = this.tierManager.getTierConfig(userProfile.tier);
    totalBonus = (totalBonus * BigInt(Math.floor(tierConfig.stakingMultiplier * 100))) / 100n;

    return totalBonus;
  }

  /**
   * Calculate referral reward
   */
  calculateReferralReward(
    referrerProfile: UserLoyaltyProfile,
    refereeVolume: bigint,
    refereeFee: bigint
  ): bigint {
    const tierConfig = this.tierManager.getTierConfig(referrerProfile.tier);
    return (refereeFee * BigInt(tierConfig.referralBonus)) / 10000n;
  }
}

/**
 * Main Fee Rebate and Loyalty System
 */
export class FeeRebateSystem extends EventEmitter {
  private config: LoyaltySystemConfig;
  private tierManager: TierManager;
  private washTradeDetector: WashTradeDetector;
  private rebateCalculator: RebateCalculator;
  private userProfiles: Map<string, UserLoyaltyProfile> = new Map();
  private rebateTransactions: Map<string, RebateTransaction[]> = new Map();
  private referralRecords: Map<string, ReferralRecord[]> = new Map();
  private achievements: Achievement[] = [];

  constructor(config: LoyaltySystemConfig) {
    super();
    this.config = config;
    this.tierManager = new TierManager();
    this.washTradeDetector = new WashTradeDetector(config.washTradeThreshold);
    this.rebateCalculator = new RebateCalculator(this.tierManager);

    this.initializeAchievements();
  }

  /**
   * Register new user
   */
  registerUser(address: string, referralCode?: string): UserLoyaltyProfile {
    const userId = crypto.randomBytes(16).toString('hex');

    const profile: UserLoyaltyProfile = {
      userId,
      address,
      tier: LoyaltyTier.BRONZE,
      totalVolume: 0n,
      volume30d: 0n,
      totalFeesPaid: 0n,
      totalRebatesEarned: 0n,
      pendingRebates: 0n,
      loyaltyPoints: 0n,
      referralCode: this.generateReferralCode(userId),
      referredBy: referralCode,
      referralCount: 0,
      referralEarnings: 0n,
      joinedAt: new Date(),
      consecutiveTradingDays: 0,
      achievements: []
    };

    this.userProfiles.set(userId, profile);

    // Process referral
    if (referralCode) {
      this.processReferralRegistration(referralCode, userId);
    }

    this.emit('userRegistered', profile);
    return profile;
  }

  /**
   * Process a trade and calculate rebates
   */
  processTrade(activity: TradingActivity): {
    fee: bigint;
    discount: bigint;
    rebate: bigint;
    netFee: bigint;
    pointsEarned: bigint;
  } {
    const profile = this.userProfiles.get(activity.userId);
    if (!profile) {
      throw new Error('User not found');
    }

    // Check for wash trading
    this.washTradeDetector.recordTrade(activity);
    const washTradeCheck = this.washTradeDetector.detectWashTrading(activity.userId);

    if (washTradeCheck.isWashTrading) {
      this.emit('washTradingDetected', {
        userId: activity.userId,
        score: washTradeCheck.score,
        patterns: washTradeCheck.patterns
      });

      // No rebates for wash traders
      return {
        fee: activity.fee,
        discount: 0n,
        rebate: 0n,
        netFee: activity.fee,
        pointsEarned: 0n
      };
    }

    // Calculate fees and rebates
    const feeCalc = this.rebateCalculator.calculateEffectiveFee(
      profile,
      activity.volume,
      activity.isMaker
    );

    // Update user stats
    profile.totalVolume += activity.volume;
    profile.volume30d += activity.volume;
    profile.totalFeesPaid += feeCalc.netFee;

    // Calculate loyalty points (1 point per 1 unit of volume)
    const pointsEarned = activity.volume / 1000000000000000n; // Simplified
    profile.loyaltyPoints += pointsEarned;

    // Create rebate transaction if applicable
    if (feeCalc.discount + feeCalc.rebate > 0n) {
      this.createRebateTransaction(
        profile.userId,
        RebateType.TRADING_FEE,
        feeCalc.discount + feeCalc.rebate,
        activity.tradeId
      );
    }

    // Process referral rewards
    if (profile.referredBy) {
      this.processReferralTrade(profile.referredBy, profile.userId, activity.volume, feeCalc.netFee);
    }

    // Update consecutive trading days
    this.updateTradingStreak(profile);

    // Check for tier upgrade
    this.checkTierUpgrade(profile);

    // Check for achievements
    this.checkAchievements(profile);

    // Update last trade
    profile.lastTradeAt = activity.timestamp;

    this.emit('tradeProcessed', {
      userId: activity.userId,
      volume: activity.volume,
      netFee: feeCalc.netFee,
      pointsEarned
    });

    return {
      fee: feeCalc.baseFee,
      discount: feeCalc.discount,
      rebate: feeCalc.rebate,
      netFee: feeCalc.netFee,
      pointsEarned
    };
  }

  /**
   * Claim pending rebates
   */
  claimRebates(userId: string): bigint {
    const userRebates = this.rebateTransactions.get(userId);
    if (!userRebates) return 0n;

    let totalClaimed = 0n;
    const now = new Date();

    for (const rebate of userRebates) {
      if (rebate.status === 'claimable' && now < rebate.expiresAt) {
        if (rebate.amount >= this.config.minClaimableAmount) {
          rebate.status = 'claimed';
          rebate.claimedAt = now;
          totalClaimed += rebate.amount;
        }
      }
    }

    const profile = this.userProfiles.get(userId);
    if (profile) {
      profile.totalRebatesEarned += totalClaimed;
      profile.pendingRebates -= totalClaimed;
    }

    this.emit('rebatesClaimed', { userId, amount: totalClaimed });

    return totalClaimed;
  }

  /**
   * Get user's loyalty dashboard
   */
  getUserDashboard(userId: string): {
    profile: UserLoyaltyProfile;
    tierProgress: any;
    pendingRebates: RebateTransaction[];
    referralStats: any;
    achievements: Achievement[];
  } {
    const profile = this.userProfiles.get(userId);
    if (!profile) {
      throw new Error('User not found');
    }

    const tierProgress = this.tierManager.getProgressToNextTier(profile.tier, profile.volume30d);

    const pendingRebates = (this.rebateTransactions.get(userId) || []).filter(
      r => r.status === 'claimable' || r.status === 'pending'
    );

    const referrals = this.referralRecords.get(profile.referralCode) || [];
    const referralStats = {
      totalReferrals: referrals.length,
      activeReferrals: referrals.filter(r => r.active).length,
      totalVolume: referrals.reduce((sum, r) => sum + r.totalVolumeGenerated, 0n),
      totalEarnings: profile.referralEarnings
    };

    return {
      profile,
      tierProgress,
      pendingRebates,
      referralStats,
      achievements: profile.achievements
    };
  }

  /**
   * Get system statistics
   */
  getSystemStats(): {
    totalUsers: number;
    tierDistribution: Map<LoyaltyTier, number>;
    totalRebatesDistributed: bigint;
    totalReferralRewards: bigint;
    averageLoyaltyPoints: bigint;
  } {
    const tierDistribution = new Map<LoyaltyTier, number>();
    let totalRebates = 0n;
    let totalReferral = 0n;
    let totalPoints = 0n;

    for (const profile of this.userProfiles.values()) {
      const count = tierDistribution.get(profile.tier) || 0;
      tierDistribution.set(profile.tier, count + 1);

      totalRebates += profile.totalRebatesEarned;
      totalReferral += profile.referralEarnings;
      totalPoints += profile.loyaltyPoints;
    }

    const avgPoints =
      this.userProfiles.size > 0
        ? totalPoints / BigInt(this.userProfiles.size)
        : 0n;

    return {
      totalUsers: this.userProfiles.size,
      tierDistribution,
      totalRebatesDistributed: totalRebates,
      totalReferralRewards: totalReferral,
      averageLoyaltyPoints: avgPoints
    };
  }

  private createRebateTransaction(
    userId: string,
    type: RebateType,
    amount: bigint,
    sourceTransaction?: string
  ): void {
    const transaction: RebateTransaction = {
      id: crypto.randomBytes(16).toString('hex'),
      userId,
      type,
      amount,
      sourceTransaction,
      calculatedAt: new Date(),
      status: 'pending',
      expiresAt: new Date(
        Date.now() + this.config.rebateClaimPeriodDays * 24 * 60 * 60 * 1000
      )
    };

    if (!this.rebateTransactions.has(userId)) {
      this.rebateTransactions.set(userId, []);
    }

    this.rebateTransactions.get(userId)!.push(transaction);

    const profile = this.userProfiles.get(userId);
    if (profile) {
      profile.pendingRebates += amount;
    }

    // Make claimable after settlement period
    setTimeout(() => {
      transaction.status = 'claimable';
      this.emit('rebateClaimable', { userId, amount });
    }, 1000); // 1 second for demo

    this.emit('rebateCreated', transaction);
  }

  private processReferralRegistration(referralCode: string, refereeId: string): void {
    // Find referrer
    let referrerId: string | null = null;

    for (const [userId, profile] of this.userProfiles) {
      if (profile.referralCode === referralCode) {
        referrerId = userId;
        break;
      }
    }

    if (!referrerId) return;

    const referrerProfile = this.userProfiles.get(referrerId)!;
    referrerProfile.referralCount++;

    const record: ReferralRecord = {
      referrerCode: referralCode,
      refereeId,
      registeredAt: new Date(),
      totalVolumeGenerated: 0n,
      totalRewardsEarned: 0n,
      active: true
    };

    if (!this.referralRecords.has(referralCode)) {
      this.referralRecords.set(referralCode, []);
    }

    this.referralRecords.get(referralCode)!.push(record);

    this.emit('referralRegistered', { referrer: referrerId, referee: refereeId });
  }

  private processReferralTrade(
    referrerCode: string,
    refereeId: string,
    volume: bigint,
    fee: bigint
  ): void {
    const referrals = this.referralRecords.get(referrerCode);
    if (!referrals) return;

    const record = referrals.find(r => r.refereeId === refereeId && r.active);
    if (!record) return;

    // Find referrer profile
    let referrerProfile: UserLoyaltyProfile | null = null;
    for (const profile of this.userProfiles.values()) {
      if (profile.referralCode === referrerCode) {
        referrerProfile = profile;
        break;
      }
    }

    if (!referrerProfile) return;

    // Calculate reward
    const reward = this.rebateCalculator.calculateReferralReward(referrerProfile, volume, fee);

    record.totalVolumeGenerated += volume;
    record.totalRewardsEarned += reward;
    referrerProfile.referralEarnings += reward;

    // Create rebate transaction for referrer
    this.createRebateTransaction(referrerProfile.userId, RebateType.REFERRAL_REWARD, reward);

    // Update first trade if not set
    if (!record.firstTradeAt) {
      record.firstTradeAt = new Date();
    }
  }

  private checkTierUpgrade(profile: UserLoyaltyProfile): void {
    const newTier = this.tierManager.calculateTier(profile.volume30d);

    if (newTier !== profile.tier) {
      const oldTier = profile.tier;
      profile.tier = newTier;
      profile.tierUpgradeAt = new Date();

      this.emit('tierChanged', {
        userId: profile.userId,
        oldTier,
        newTier
      });
    }
  }

  private updateTradingStreak(profile: UserLoyaltyProfile): void {
    const now = new Date();
    const lastTrade = profile.lastTradeAt;

    if (!lastTrade) {
      profile.consecutiveTradingDays = 1;
      return;
    }

    const daysDiff = Math.floor(
      (now.getTime() - lastTrade.getTime()) / (24 * 60 * 60 * 1000)
    );

    if (daysDiff === 1) {
      profile.consecutiveTradingDays++;
    } else if (daysDiff > 1) {
      profile.consecutiveTradingDays = 1;
    }
  }

  private checkAchievements(profile: UserLoyaltyProfile): void {
    for (const achievement of this.achievements) {
      const alreadyEarned = profile.achievements.find(a => a.id === achievement.id);
      if (alreadyEarned) continue;

      const earned = this.evaluateAchievement(achievement, profile);
      if (earned) {
        const userAchievement = { ...achievement, earnedAt: new Date(), claimed: false };
        profile.achievements.push(userAchievement);

        this.emit('achievementUnlocked', {
          userId: profile.userId,
          achievement: userAchievement
        });
      }
    }
  }

  private evaluateAchievement(achievement: Achievement, profile: UserLoyaltyProfile): boolean {
    // Simplified achievement evaluation
    switch (achievement.id) {
      case 'first_trade':
        return profile.totalVolume > 0n;
      case 'volume_10k':
        return profile.totalVolume >= 10000000000000000000000n;
      case 'streak_7':
        return profile.consecutiveTradingDays >= 7;
      case 'referral_5':
        return profile.referralCount >= 5;
      default:
        return false;
    }
  }

  private initializeAchievements(): void {
    this.achievements = [
      {
        id: 'first_trade',
        name: 'First Steps',
        description: 'Complete your first trade',
        reward: 100000000000000000000n, // 100 tokens
        earnedAt: new Date(),
        claimed: false
      },
      {
        id: 'volume_10k',
        name: 'Volume Trader',
        description: 'Trade over 10,000 in volume',
        reward: 500000000000000000000n,
        earnedAt: new Date(),
        claimed: false
      },
      {
        id: 'streak_7',
        name: 'Consistent Trader',
        description: 'Trade for 7 consecutive days',
        reward: 200000000000000000000n,
        earnedAt: new Date(),
        claimed: false
      },
      {
        id: 'referral_5',
        name: 'Influencer',
        description: 'Refer 5 active traders',
        reward: 1000000000000000000000n,
        earnedAt: new Date(),
        claimed: false
      }
    ];
  }

  private generateReferralCode(userId: string): string {
    const hash = crypto.createHash('sha256').update(userId).digest('hex');
    return 'REF' + hash.substring(0, 8).toUpperCase();
  }
}

// Export types
export {
  LoyaltyTier,
  RebateType,
  UserLoyaltyProfile,
  TierConfig,
  RebateTransaction,
  TradingActivity,
  Achievement,
  TierManager,
  WashTradeDetector,
  RebateCalculator
};

// Default configuration
export const defaultLoyaltyConfig: LoyaltySystemConfig = {
  rebateClaimPeriodDays: 30,
  minClaimableAmount: 1000000000000000000n, // 1 token
  washTradeThreshold: 70,
  referralLockupDays: 7,
  maxReferralDepth: 2,
  pointsToTokenRatio: 1000n,
  volumeDecayRate: 0.967 // ~50% decay over 30 days
};
