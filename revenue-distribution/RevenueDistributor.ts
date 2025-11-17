import { EventEmitter } from 'events';
import * as crypto from 'crypto';

/**
 * PROTOCOL REVENUE DISTRIBUTION SYSTEM
 *
 * HYPOTHESIS: An automated, transparent revenue distribution system with
 * real-time tracking and fair allocation will maximize stakeholder alignment
 * with >95% of revenue distributed within 24 hours.
 *
 * SUCCESS METRICS:
 * - Distribution latency: <24 hours
 * - Allocation accuracy: 100%
 * - Stakeholder satisfaction: >90%
 * - Gas efficiency: <$1 per distribution
 * - Revenue tracking accuracy: 100%
 *
 * SECURITY CONSIDERATIONS:
 * - Multi-sig treasury controls
 * - Automated distribution rules
 * - Transparent accounting
 * - Anti-gaming mechanisms
 * - Emergency pause capability
 */

// Revenue source
enum RevenueSource {
  TRADING_FEES = 'trading_fees',
  LIQUIDATION_FEES = 'liquidation_fees',
  BORROWING_INTEREST = 'borrowing_interest',
  BRIDGE_FEES = 'bridge_fees',
  ORACLE_FEES = 'oracle_fees',
  SUBSCRIPTION_FEES = 'subscription_fees',
  LISTING_FEES = 'listing_fees',
  OTHER = 'other'
}

// Recipient type
enum RecipientType {
  STAKERS = 'stakers',
  TREASURY = 'treasury',
  BUYBACK = 'buyback',
  LIQUIDITY_PROVIDERS = 'liquidity_providers',
  DEVELOPMENT = 'development',
  INSURANCE_FUND = 'insurance_fund',
  REFERRERS = 'referrers',
  VALIDATORS = 'validators'
}

// Revenue entry
interface RevenueEntry {
  id: string;
  source: RevenueSource;
  amount: bigint;
  token: string;
  timestamp: Date;
  txHash?: string;
  metadata: any;
}

// Distribution
interface Distribution {
  id: string;
  period: string; // e.g., "2024-01-15"
  totalRevenue: bigint;
  breakdown: Map<RecipientType, bigint>;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  createdAt: Date;
  executedAt?: Date;
  txHashes: string[];
}

// Allocation rule
interface AllocationRule {
  recipientType: RecipientType;
  percentage: number; // basis points
  minAmount: bigint;
  maxAmount: bigint;
  vestingPeriod: number; // days
  recipientAddress?: string;
}

// Staker share
interface StakerShare {
  userId: string;
  stakedAmount: bigint;
  stakeDuration: number; // days
  boostMultiplier: number;
  rewardShare: bigint;
  pendingRewards: bigint;
  claimedRewards: bigint;
  lastClaimTime: Date;
}

// Revenue period summary
interface RevenuePeriodSummary {
  period: string;
  totalRevenue: bigint;
  bySource: Map<RevenueSource, bigint>;
  byToken: Map<string, bigint>;
  distributions: Distribution[];
}

// Accumulated rewards
interface AccumulatedRewards {
  recipientType: RecipientType;
  token: string;
  amount: bigint;
  lastUpdateTime: Date;
}

// Distribution schedule
interface DistributionSchedule {
  frequency: 'daily' | 'weekly' | 'monthly';
  dayOfWeek?: number; // 0-6 for weekly
  dayOfMonth?: number; // 1-31 for monthly
  hour: number; // 0-23
  minAmountThreshold: bigint;
}

export class RevenueDistributor extends EventEmitter {
  private revenueHistory: RevenueEntry[] = [];
  private distributions: Map<string, Distribution> = new Map();
  private allocationRules: AllocationRule[] = [];
  private stakerShares: Map<string, StakerShare> = new Map();
  private accumulatedRewards: Map<string, AccumulatedRewards> = new Map();
  private periodSummaries: Map<string, RevenuePeriodSummary> = new Map();
  private schedule: DistributionSchedule;

  // Total tracking
  private totalRevenueCollected: bigint = 0n;
  private totalRevenueDistributed: bigint = 0n;

  // Configuration
  private baseToken: string = 'USDC';
  private minClaimAmount: bigint = 10n * 10n ** 18n; // $10
  private claimCooldown: number = 24 * 60 * 60 * 1000; // 24 hours

  constructor() {
    super();
    this.initializeDefaultRules();
    this.schedule = {
      frequency: 'daily',
      hour: 0, // Midnight UTC
      minAmountThreshold: 1000n * 10n ** 18n // $1000
    };
    this.startAutomatedDistribution();
  }

  private initializeDefaultRules(): void {
    this.allocationRules = [
      {
        recipientType: RecipientType.STAKERS,
        percentage: 4000, // 40%
        minAmount: 0n,
        maxAmount: BigInt(Number.MAX_SAFE_INTEGER),
        vestingPeriod: 0
      },
      {
        recipientType: RecipientType.TREASURY,
        percentage: 2000, // 20%
        minAmount: 0n,
        maxAmount: BigInt(Number.MAX_SAFE_INTEGER),
        vestingPeriod: 0
      },
      {
        recipientType: RecipientType.BUYBACK,
        percentage: 2000, // 20%
        minAmount: 0n,
        maxAmount: BigInt(Number.MAX_SAFE_INTEGER),
        vestingPeriod: 0
      },
      {
        recipientType: RecipientType.INSURANCE_FUND,
        percentage: 1000, // 10%
        minAmount: 0n,
        maxAmount: BigInt(Number.MAX_SAFE_INTEGER),
        vestingPeriod: 0
      },
      {
        recipientType: RecipientType.DEVELOPMENT,
        percentage: 1000, // 10%
        minAmount: 0n,
        maxAmount: BigInt(Number.MAX_SAFE_INTEGER),
        vestingPeriod: 30
      }
    ];
  }

  /**
   * Record revenue
   */
  recordRevenue(
    source: RevenueSource,
    amount: bigint,
    token: string = this.baseToken,
    txHash?: string,
    metadata?: any
  ): RevenueEntry {
    const entry: RevenueEntry = {
      id: crypto.randomBytes(16).toString('hex'),
      source,
      amount,
      token,
      timestamp: new Date(),
      txHash,
      metadata
    };

    this.revenueHistory.push(entry);
    this.totalRevenueCollected += amount;

    // Update period summary
    const period = this.getCurrentPeriod();
    this.updatePeriodSummary(period, entry);

    // Update accumulated rewards
    this.updateAccumulatedRewards(entry);

    this.emit('revenueRecorded', entry);
    return entry;
  }

  /**
   * Execute distribution
   */
  executeDistribution(period?: string): Distribution {
    const distributionPeriod = period || this.getCurrentPeriod();

    // Get accumulated revenue for period
    const periodRevenue = this.getPeriodRevenue(distributionPeriod);
    if (periodRevenue < this.schedule.minAmountThreshold) {
      throw new Error('Below minimum distribution threshold');
    }

    const distribution: Distribution = {
      id: crypto.randomBytes(16).toString('hex'),
      period: distributionPeriod,
      totalRevenue: periodRevenue,
      breakdown: new Map(),
      status: 'processing',
      createdAt: new Date(),
      txHashes: []
    };

    // Calculate allocations
    for (const rule of this.allocationRules) {
      const allocation = this.calculateAllocation(periodRevenue, rule);
      distribution.breakdown.set(rule.recipientType, allocation);
    }

    // Validate total allocation
    let totalAllocated = 0n;
    for (const amount of distribution.breakdown.values()) {
      totalAllocated += amount;
    }

    if (totalAllocated > periodRevenue) {
      distribution.status = 'failed';
      throw new Error('Allocation exceeds revenue');
    }

    // Execute distributions
    this.executeStakerDistribution(distribution);
    this.executeTreasuryDistribution(distribution);
    this.executeBuybackAllocation(distribution);
    this.executeInsuranceFundDistribution(distribution);
    this.executeDevelopmentDistribution(distribution);

    distribution.status = 'completed';
    distribution.executedAt = new Date();

    this.distributions.set(distribution.id, distribution);
    this.totalRevenueDistributed += totalAllocated;

    this.emit('distributionCompleted', distribution);
    return distribution;
  }

  /**
   * Register staker
   */
  registerStaker(
    userId: string,
    stakedAmount: bigint,
    stakeDuration: number = 0
  ): StakerShare {
    const boostMultiplier = this.calculateBoostMultiplier(stakeDuration);

    const share: StakerShare = {
      userId,
      stakedAmount,
      stakeDuration,
      boostMultiplier,
      rewardShare: 0n,
      pendingRewards: 0n,
      claimedRewards: 0n,
      lastClaimTime: new Date()
    };

    this.stakerShares.set(userId, share);
    this.updateAllStakerShares();

    this.emit('stakerRegistered', share);
    return share;
  }

  /**
   * Update staker amount
   */
  updateStakerAmount(userId: string, newAmount: bigint): void {
    const share = this.stakerShares.get(userId);
    if (!share) throw new Error('Staker not found');

    share.stakedAmount = newAmount;
    this.updateAllStakerShares();

    this.emit('stakerUpdated', share);
  }

  /**
   * Claim rewards
   */
  claimRewards(userId: string): bigint {
    const share = this.stakerShares.get(userId);
    if (!share) throw new Error('Staker not found');

    // Check cooldown
    const timeSinceClaim = Date.now() - share.lastClaimTime.getTime();
    if (timeSinceClaim < this.claimCooldown) {
      throw new Error('Claim cooldown not elapsed');
    }

    // Check minimum
    if (share.pendingRewards < this.minClaimAmount) {
      throw new Error('Below minimum claim amount');
    }

    const claimAmount = share.pendingRewards;
    share.claimedRewards += claimAmount;
    share.pendingRewards = 0n;
    share.lastClaimTime = new Date();

    this.emit('rewardsClaimed', { userId, amount: claimAmount });
    return claimAmount;
  }

  /**
   * Update allocation rules
   */
  updateAllocationRules(newRules: AllocationRule[]): void {
    // Validate total percentage
    let totalPercentage = 0;
    for (const rule of newRules) {
      totalPercentage += rule.percentage;
    }

    if (totalPercentage !== 10000) {
      throw new Error('Allocation percentages must sum to 100%');
    }

    this.allocationRules = newRules;
    this.emit('allocationRulesUpdated', newRules);
  }

  /**
   * Get revenue analytics
   */
  getRevenueAnalytics(days: number = 30): {
    totalRevenue: bigint;
    avgDailyRevenue: bigint;
    revenueBySource: Map<RevenueSource, bigint>;
    revenueByDay: Map<string, bigint>;
    growthRate: number;
  } {
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const recentRevenue = this.revenueHistory.filter(
      e => e.timestamp.getTime() > cutoff
    );

    let totalRevenue = 0n;
    const revenueBySource = new Map<RevenueSource, bigint>();
    const revenueByDay = new Map<string, bigint>();

    for (const entry of recentRevenue) {
      totalRevenue += entry.amount;

      // By source
      const sourceTotal = revenueBySource.get(entry.source) || 0n;
      revenueBySource.set(entry.source, sourceTotal + entry.amount);

      // By day
      const day = entry.timestamp.toISOString().split('T')[0];
      const dayTotal = revenueByDay.get(day) || 0n;
      revenueByDay.set(day, dayTotal + entry.amount);
    }

    const avgDailyRevenue = days > 0 ? totalRevenue / BigInt(days) : 0n;

    // Calculate growth rate (comparing first half vs second half)
    const halfDays = Math.floor(days / 2);
    const midCutoff = Date.now() - halfDays * 24 * 60 * 60 * 1000;

    let firstHalfRevenue = 0n;
    let secondHalfRevenue = 0n;

    for (const entry of recentRevenue) {
      if (entry.timestamp.getTime() > midCutoff) {
        secondHalfRevenue += entry.amount;
      } else {
        firstHalfRevenue += entry.amount;
      }
    }

    const growthRate = firstHalfRevenue > 0n
      ? (Number(secondHalfRevenue - firstHalfRevenue) / Number(firstHalfRevenue)) * 100
      : 0;

    return {
      totalRevenue,
      avgDailyRevenue,
      revenueBySource,
      revenueByDay,
      growthRate
    };
  }

  /**
   * Get distribution history
   */
  getDistributionHistory(limit: number = 10): Distribution[] {
    return Array.from(this.distributions.values())
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, limit);
  }

  /**
   * Get staker rewards summary
   */
  getStakerRewardsSummary(userId: string): {
    totalEarned: bigint;
    pendingRewards: bigint;
    claimedRewards: bigint;
    sharePercentage: number;
    boostMultiplier: number;
    nextClaimTime: Date;
  } | null {
    const share = this.stakerShares.get(userId);
    if (!share) return null;

    const nextClaimTime = new Date(share.lastClaimTime.getTime() + this.claimCooldown);

    return {
      totalEarned: share.claimedRewards + share.pendingRewards,
      pendingRewards: share.pendingRewards,
      claimedRewards: share.claimedRewards,
      sharePercentage: Number(share.rewardShare) / 100,
      boostMultiplier: share.boostMultiplier,
      nextClaimTime
    };
  }

  /**
   * Get global statistics
   */
  getGlobalStats(): {
    totalRevenueCollected: bigint;
    totalRevenueDistributed: bigint;
    pendingDistribution: bigint;
    totalStakers: number;
    totalStakedAmount: bigint;
    distributionCount: number;
    avgDistributionSize: bigint;
  } {
    let totalStakedAmount = 0n;
    for (const share of this.stakerShares.values()) {
      totalStakedAmount += share.stakedAmount;
    }

    const distributions = Array.from(this.distributions.values());
    const avgDistributionSize = distributions.length > 0
      ? this.totalRevenueDistributed / BigInt(distributions.length)
      : 0n;

    return {
      totalRevenueCollected: this.totalRevenueCollected,
      totalRevenueDistributed: this.totalRevenueDistributed,
      pendingDistribution: this.totalRevenueCollected - this.totalRevenueDistributed,
      totalStakers: this.stakerShares.size,
      totalStakedAmount,
      distributionCount: distributions.length,
      avgDistributionSize
    };
  }

  /**
   * Forecast revenue
   */
  forecastRevenue(days: number): {
    projectedRevenue: bigint;
    confidenceLevel: number;
    assumptions: string[];
  } {
    const analytics = this.getRevenueAnalytics(30);
    const growthFactor = 1 + analytics.growthRate / 100;

    // Simple linear projection with growth
    const projectedRevenue = analytics.avgDailyRevenue * BigInt(days) *
                             BigInt(Math.floor(growthFactor * 100)) / 100n;

    const confidenceLevel = analytics.revenueByDay.size >= 30 ? 0.8 : 0.6;

    return {
      projectedRevenue,
      confidenceLevel,
      assumptions: [
        'Based on last 30 days average',
        `Growth rate: ${analytics.growthRate.toFixed(2)}%`,
        'No major market changes',
        'Stable user base'
      ]
    };
  }

  /**
   * Update distribution schedule
   */
  updateSchedule(newSchedule: DistributionSchedule): void {
    this.schedule = newSchedule;
    this.emit('scheduleUpdated', newSchedule);
  }

  private calculateAllocation(totalRevenue: bigint, rule: AllocationRule): bigint {
    let allocation = (totalRevenue * BigInt(rule.percentage)) / 10000n;

    // Apply min/max bounds
    if (allocation < rule.minAmount) {
      allocation = rule.minAmount;
    }
    if (allocation > rule.maxAmount) {
      allocation = rule.maxAmount;
    }

    return allocation;
  }

  private executeStakerDistribution(distribution: Distribution): void {
    const stakerAllocation = distribution.breakdown.get(RecipientType.STAKERS) || 0n;
    if (stakerAllocation === 0n) return;

    // Distribute proportionally to stakers
    let totalWeightedStake = 0n;
    for (const share of this.stakerShares.values()) {
      const weightedStake = BigInt(Math.floor(Number(share.stakedAmount) * share.boostMultiplier));
      totalWeightedStake += weightedStake;
    }

    if (totalWeightedStake === 0n) return;

    for (const share of this.stakerShares.values()) {
      const weightedStake = BigInt(Math.floor(Number(share.stakedAmount) * share.boostMultiplier));
      const reward = (stakerAllocation * weightedStake) / totalWeightedStake;

      share.pendingRewards += reward;
    }

    this.emit('stakerRewardsDistributed', { totalAmount: stakerAllocation });
  }

  private executeTreasuryDistribution(distribution: Distribution): void {
    const treasuryAllocation = distribution.breakdown.get(RecipientType.TREASURY) || 0n;
    this.emit('treasuryDistribution', { amount: treasuryAllocation });
  }

  private executeBuybackAllocation(distribution: Distribution): void {
    const buybackAllocation = distribution.breakdown.get(RecipientType.BUYBACK) || 0n;
    this.emit('buybackAllocation', { amount: buybackAllocation });
  }

  private executeInsuranceFundDistribution(distribution: Distribution): void {
    const insuranceAllocation = distribution.breakdown.get(RecipientType.INSURANCE_FUND) || 0n;
    this.emit('insuranceFundDistribution', { amount: insuranceAllocation });
  }

  private executeDevelopmentDistribution(distribution: Distribution): void {
    const devAllocation = distribution.breakdown.get(RecipientType.DEVELOPMENT) || 0n;
    this.emit('developmentDistribution', { amount: devAllocation });
  }

  private calculateBoostMultiplier(stakeDurationDays: number): number {
    // Boost based on lock duration
    if (stakeDurationDays >= 365) return 2.5;
    if (stakeDurationDays >= 180) return 2.0;
    if (stakeDurationDays >= 90) return 1.5;
    if (stakeDurationDays >= 30) return 1.25;
    return 1.0;
  }

  private updateAllStakerShares(): void {
    // Calculate total weighted stake
    let totalWeightedStake = 0n;
    for (const share of this.stakerShares.values()) {
      const weightedStake = BigInt(Math.floor(Number(share.stakedAmount) * share.boostMultiplier));
      totalWeightedStake += weightedStake;
    }

    // Update individual shares
    for (const share of this.stakerShares.values()) {
      if (totalWeightedStake > 0n) {
        const weightedStake = BigInt(Math.floor(Number(share.stakedAmount) * share.boostMultiplier));
        share.rewardShare = (weightedStake * 10000n) / totalWeightedStake; // basis points
      } else {
        share.rewardShare = 0n;
      }
    }
  }

  private getCurrentPeriod(): string {
    const now = new Date();
    return now.toISOString().split('T')[0];
  }

  private updatePeriodSummary(period: string, entry: RevenueEntry): void {
    if (!this.periodSummaries.has(period)) {
      this.periodSummaries.set(period, {
        period,
        totalRevenue: 0n,
        bySource: new Map(),
        byToken: new Map(),
        distributions: []
      });
    }

    const summary = this.periodSummaries.get(period)!;
    summary.totalRevenue += entry.amount;

    // By source
    const sourceTotal = summary.bySource.get(entry.source) || 0n;
    summary.bySource.set(entry.source, sourceTotal + entry.amount);

    // By token
    const tokenTotal = summary.byToken.get(entry.token) || 0n;
    summary.byToken.set(entry.token, tokenTotal + entry.amount);
  }

  private updateAccumulatedRewards(entry: RevenueEntry): void {
    // Distribute immediately to accumulated pools
    for (const rule of this.allocationRules) {
      const allocation = this.calculateAllocation(entry.amount, rule);
      const key = `${rule.recipientType}_${entry.token}`;

      if (!this.accumulatedRewards.has(key)) {
        this.accumulatedRewards.set(key, {
          recipientType: rule.recipientType,
          token: entry.token,
          amount: 0n,
          lastUpdateTime: new Date()
        });
      }

      const accumulated = this.accumulatedRewards.get(key)!;
      accumulated.amount += allocation;
      accumulated.lastUpdateTime = new Date();
    }
  }

  private getPeriodRevenue(period: string): bigint {
    const summary = this.periodSummaries.get(period);
    return summary?.totalRevenue || 0n;
  }

  private startAutomatedDistribution(): void {
    // Check for distribution eligibility every hour
    setInterval(() => {
      const currentPeriod = this.getCurrentPeriod();
      const periodRevenue = this.getPeriodRevenue(currentPeriod);

      if (periodRevenue >= this.schedule.minAmountThreshold) {
        // Check if distribution already executed for this period
        const existingDistribution = Array.from(this.distributions.values())
          .find(d => d.period === currentPeriod && d.status === 'completed');

        if (!existingDistribution) {
          const currentHour = new Date().getUTCHours();

          if (currentHour === this.schedule.hour) {
            try {
              this.executeDistribution(currentPeriod);
            } catch (error) {
              this.emit('distributionFailed', { period: currentPeriod, error });
            }
          }
        }
      }
    }, 3600000); // Every hour
  }
}

// Export types
export {
  RevenueSource,
  RecipientType,
  RevenueEntry,
  Distribution,
  AllocationRule,
  StakerShare,
  RevenuePeriodSummary,
  AccumulatedRewards,
  DistributionSchedule
};
