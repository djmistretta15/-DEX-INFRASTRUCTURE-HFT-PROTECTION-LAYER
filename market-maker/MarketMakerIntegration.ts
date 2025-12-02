import { EventEmitter } from 'events';
import * as crypto from 'crypto';

/**
 * MARKET MAKER INTEGRATION SYSTEM
 *
 * HYPOTHESIS: Integrating professional market makers with algorithmic quoting
 * will reduce spreads by 60% and improve fill rates to >99%.
 *
 * SUCCESS METRICS:
 * - Spread reduction >60%
 * - Fill rate >99%
 * - Market maker participation >5 active MMs
 * - Quote refresh rate <100ms
 * - Uptime >99.9%
 *
 * SECURITY CONSIDERATIONS:
 * - Fair access policies
 * - Position limits enforcement
 * - Real-time risk monitoring
 * - Manipulation detection
 * - Transparent quoting rules
 */

// Market maker status
enum MMStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  SUSPENDED = 'suspended',
  PROBATION = 'probation'
}

// Quote type
enum QuoteType {
  TWO_SIDED = 'two_sided',
  ONE_SIDED_BID = 'one_sided_bid',
  ONE_SIDED_ASK = 'one_sided_ask'
}

// Market maker profile
interface MarketMaker {
  id: string;
  name: string;
  address: string;
  status: MMStatus;
  tier: MMTier;
  assignedPairs: string[];
  bondAmount: bigint;
  reputation: number;
  totalVolume: bigint;
  uptimePercent: number;
  avgSpread: number;
  avgQuoteSize: bigint;
  violationCount: number;
  lastQuoteTime: Date;
  registeredAt: Date;
  metrics: MMPerformanceMetrics;
}

// MM tier with benefits
interface MMTier {
  level: number;
  name: string;
  feeRebate: number; // basis points
  minQuoteObligation: number; // percent of time
  maxSpread: number; // basis points
  minQuoteSize: bigint;
  priorityAccess: boolean;
}

// Quote from market maker
interface Quote {
  quoteId: string;
  mmId: string;
  pair: string;
  type: QuoteType;
  bidPrice: bigint;
  bidSize: bigint;
  askPrice: bigint;
  askSize: bigint;
  validUntil: Date;
  createdAt: Date;
  spread: number; // basis points
}

// Performance metrics
interface MMPerformanceMetrics {
  quoteCount24h: number;
  fillRate: number;
  avgResponseTime: number; // ms
  inventoryTurnover: number;
  pnl24h: bigint;
  riskExposure: bigint;
  spreadConsistency: number;
  uptimeLast24h: number;
}

// Obligation requirements
interface MMObligation {
  pair: string;
  minQuoteTimePercent: number;
  maxSpread: number; // basis points
  minSize: bigint;
  refreshRateMs: number;
}

// Quote evaluation
interface QuoteEvaluation {
  quoteId: string;
  meetsObligations: boolean;
  spreadScore: number;
  sizeScore: number;
  competitivenessScore: number;
  violations: string[];
}

// Market maker manager
export class MarketMakerManager extends EventEmitter {
  private marketMakers: Map<string, MarketMaker> = new Map();
  private activeQuotes: Map<string, Quote[]> = new Map(); // pair -> quotes
  private obligations: Map<string, MMObligation[]> = new Map(); // mmId -> obligations
  private tiers: MMTier[] = [];
  private quoteHistory: Quote[] = [];
  private violationThreshold: number = 10;

  constructor() {
    super();
    this.initializeTiers();
    this.startMonitoring();
  }

  private initializeTiers(): void {
    this.tiers = [
      {
        level: 1,
        name: 'Bronze',
        feeRebate: 2000, // 20%
        minQuoteObligation: 80,
        maxSpread: 100, // 1%
        minQuoteSize: 1000000000000000000000n, // 1000 tokens
        priorityAccess: false
      },
      {
        level: 2,
        name: 'Silver',
        feeRebate: 4000, // 40%
        minQuoteObligation: 85,
        maxSpread: 75,
        minQuoteSize: 5000000000000000000000n,
        priorityAccess: false
      },
      {
        level: 3,
        name: 'Gold',
        feeRebate: 6000, // 60%
        minQuoteObligation: 90,
        maxSpread: 50,
        minQuoteSize: 10000000000000000000000n,
        priorityAccess: true
      },
      {
        level: 4,
        name: 'Platinum',
        feeRebate: 8000, // 80%
        minQuoteObligation: 95,
        maxSpread: 30,
        minQuoteSize: 50000000000000000000000n,
        priorityAccess: true
      }
    ];
  }

  /**
   * Register new market maker
   */
  registerMarketMaker(
    name: string,
    address: string,
    bondAmount: bigint,
    pairs: string[]
  ): MarketMaker {
    const id = crypto.randomBytes(16).toString('hex');
    const tier = this.tiers[0]; // Start at Bronze

    const mm: MarketMaker = {
      id,
      name,
      address,
      status: MMStatus.PROBATION,
      tier,
      assignedPairs: pairs,
      bondAmount,
      reputation: 100,
      totalVolume: 0n,
      uptimePercent: 100,
      avgSpread: 0,
      avgQuoteSize: 0n,
      violationCount: 0,
      lastQuoteTime: new Date(),
      registeredAt: new Date(),
      metrics: {
        quoteCount24h: 0,
        fillRate: 0,
        avgResponseTime: 0,
        inventoryTurnover: 0,
        pnl24h: 0n,
        riskExposure: 0n,
        spreadConsistency: 0,
        uptimeLast24h: 100
      }
    };

    this.marketMakers.set(id, mm);

    // Set obligations for each pair
    const obligations: MMObligation[] = pairs.map(pair => ({
      pair,
      minQuoteTimePercent: tier.minQuoteObligation,
      maxSpread: tier.maxSpread,
      minSize: tier.minQuoteSize,
      refreshRateMs: 5000 // 5 seconds max quote age
    }));

    this.obligations.set(id, obligations);

    this.emit('marketMakerRegistered', mm);
    return mm;
  }

  /**
   * Submit quote
   */
  submitQuote(
    mmId: string,
    pair: string,
    bidPrice: bigint,
    bidSize: bigint,
    askPrice: bigint,
    askSize: bigint,
    validityMs: number = 30000
  ): Quote | null {
    const mm = this.marketMakers.get(mmId);
    if (!mm || mm.status === MMStatus.SUSPENDED) {
      return null;
    }

    // Calculate spread
    const midPrice = (bidPrice + askPrice) / 2n;
    const spread = Number((askPrice - bidPrice) * 10000n / midPrice);

    const quote: Quote = {
      quoteId: crypto.randomBytes(16).toString('hex'),
      mmId,
      pair,
      type: QuoteType.TWO_SIDED,
      bidPrice,
      bidSize,
      askPrice,
      askSize,
      validUntil: new Date(Date.now() + validityMs),
      createdAt: new Date(),
      spread
    };

    // Evaluate quote
    const evaluation = this.evaluateQuote(quote, mm);

    if (!evaluation.meetsObligations) {
      this.emit('quoteRejected', { quote, violations: evaluation.violations });
      return null;
    }

    // Add to active quotes
    if (!this.activeQuotes.has(pair)) {
      this.activeQuotes.set(pair, []);
    }

    // Remove old quotes from same MM
    const pairQuotes = this.activeQuotes.get(pair)!;
    const filteredQuotes = pairQuotes.filter(q => q.mmId !== mmId);
    filteredQuotes.push(quote);
    this.activeQuotes.set(pair, filteredQuotes);

    // Update MM stats
    mm.lastQuoteTime = new Date();
    mm.metrics.quoteCount24h++;

    // Update average spread
    mm.avgSpread = (mm.avgSpread * 0.9 + spread * 0.1);

    this.quoteHistory.push(quote);
    this.emit('quoteSubmitted', quote);

    return quote;
  }

  /**
   * Get best quotes for pair
   */
  getBestQuotes(pair: string): { bestBid: Quote | null; bestAsk: Quote | null } {
    const quotes = this.activeQuotes.get(pair) || [];
    const now = new Date();

    // Filter valid quotes
    const validQuotes = quotes.filter(q => q.validUntil > now);

    let bestBid: Quote | null = null;
    let bestAsk: Quote | null = null;

    for (const quote of validQuotes) {
      if (!bestBid || quote.bidPrice > bestBid.bidPrice) {
        bestBid = quote;
      }
      if (!bestAsk || quote.askPrice < bestAsk.askPrice) {
        bestAsk = quote;
      }
    }

    return { bestBid, bestAsk };
  }

  /**
   * Check MM obligations
   */
  checkObligations(): Map<string, { compliant: boolean; violations: string[] }> {
    const results = new Map<string, { compliant: boolean; violations: string[] }>();
    const now = new Date();

    for (const [mmId, mm] of this.marketMakers) {
      if (mm.status === MMStatus.SUSPENDED) continue;

      const obligations = this.obligations.get(mmId) || [];
      const violations: string[] = [];

      for (const obligation of obligations) {
        // Check if MM has active quote for pair
        const pairQuotes = this.activeQuotes.get(obligation.pair) || [];
        const mmQuote = pairQuotes.find(q => q.mmId === mmId && q.validUntil > now);

        if (!mmQuote) {
          violations.push(`No active quote for ${obligation.pair}`);
        } else {
          if (mmQuote.spread > obligation.maxSpread) {
            violations.push(`Spread too wide for ${obligation.pair}: ${mmQuote.spread}bp vs max ${obligation.maxSpread}bp`);
          }
          if (mmQuote.bidSize < obligation.minSize || mmQuote.askSize < obligation.minSize) {
            violations.push(`Quote size below minimum for ${obligation.pair}`);
          }
        }
      }

      if (violations.length > 0) {
        mm.violationCount++;

        if (mm.violationCount >= this.violationThreshold) {
          this.suspendMarketMaker(mmId, 'Excessive violations');
        }
      }

      results.set(mmId, {
        compliant: violations.length === 0,
        violations
      });
    }

    return results;
  }

  /**
   * Upgrade MM tier
   */
  upgradeTier(mmId: string): boolean {
    const mm = this.marketMakers.get(mmId);
    if (!mm) return false;

    const currentLevel = mm.tier.level;
    const nextTier = this.tiers.find(t => t.level === currentLevel + 1);

    if (!nextTier) return false; // Already at highest tier

    // Check if MM qualifies for upgrade
    if (
      mm.uptimePercent >= nextTier.minQuoteObligation &&
      mm.avgSpread <= nextTier.maxSpread &&
      mm.violationCount === 0 &&
      mm.reputation >= 120
    ) {
      mm.tier = nextTier;
      mm.status = MMStatus.ACTIVE;

      // Update obligations
      const obligations = this.obligations.get(mmId) || [];
      for (const ob of obligations) {
        ob.minQuoteTimePercent = nextTier.minQuoteObligation;
        ob.maxSpread = nextTier.maxSpread;
        ob.minSize = nextTier.minQuoteSize;
      }

      this.emit('tierUpgraded', { mmId, newTier: nextTier });
      return true;
    }

    return false;
  }

  /**
   * Suspend market maker
   */
  suspendMarketMaker(mmId: string, reason: string): void {
    const mm = this.marketMakers.get(mmId);
    if (!mm) return;

    mm.status = MMStatus.SUSPENDED;

    // Remove all active quotes
    for (const [pair, quotes] of this.activeQuotes) {
      this.activeQuotes.set(pair, quotes.filter(q => q.mmId !== mmId));
    }

    this.emit('marketMakerSuspended', { mmId, reason });
  }

  /**
   * Get market maker leaderboard
   */
  getLeaderboard(): MarketMaker[] {
    const mms = Array.from(this.marketMakers.values());

    // Score based on multiple factors
    return mms.sort((a, b) => {
      const scoreA = this.calculateMMScore(a);
      const scoreB = this.calculateMMScore(b);
      return scoreB - scoreA;
    });
  }

  /**
   * Get market maker statistics
   */
  getStatistics(): {
    totalMMs: number;
    activeMMs: number;
    avgSpread: number;
    totalVolume: bigint;
    avgUptime: number;
  } {
    const mms = Array.from(this.marketMakers.values());
    const active = mms.filter(mm => mm.status === MMStatus.ACTIVE);

    const avgSpread = active.length > 0
      ? active.reduce((sum, mm) => sum + mm.avgSpread, 0) / active.length
      : 0;

    const totalVolume = mms.reduce((sum, mm) => sum + mm.totalVolume, 0n);

    const avgUptime = active.length > 0
      ? active.reduce((sum, mm) => sum + mm.uptimePercent, 0) / active.length
      : 0;

    return {
      totalMMs: mms.length,
      activeMMs: active.length,
      avgSpread,
      totalVolume,
      avgUptime
    };
  }

  private evaluateQuote(quote: Quote, mm: MarketMaker): QuoteEvaluation {
    const violations: string[] = [];

    // Check spread
    if (quote.spread > mm.tier.maxSpread) {
      violations.push(`Spread ${quote.spread}bp exceeds max ${mm.tier.maxSpread}bp`);
    }

    // Check size
    if (quote.bidSize < mm.tier.minQuoteSize || quote.askSize < mm.tier.minQuoteSize) {
      violations.push(`Quote size below tier minimum ${mm.tier.minQuoteSize}`);
    }

    // Check price sanity (simplified)
    if (quote.bidPrice >= quote.askPrice) {
      violations.push('Bid price >= Ask price');
    }

    const spreadScore = Math.max(0, 100 - quote.spread);
    const sizeScore = Math.min(100, Number((quote.bidSize + quote.askSize) / (mm.tier.minQuoteSize * 2n)) * 100);
    const competitivenessScore = (spreadScore + sizeScore) / 2;

    return {
      quoteId: quote.quoteId,
      meetsObligations: violations.length === 0,
      spreadScore,
      sizeScore,
      competitivenessScore,
      violations
    };
  }

  private calculateMMScore(mm: MarketMaker): number {
    // Weight factors
    const volumeScore = Number(mm.totalVolume / 1000000000000000000000n) * 10;
    const uptimeScore = mm.uptimePercent * 0.5;
    const spreadScore = (100 - mm.avgSpread) * 0.3;
    const reputationScore = mm.reputation * 0.2;

    return volumeScore + uptimeScore + spreadScore + reputationScore;
  }

  private startMonitoring(): void {
    // Check obligations every minute
    setInterval(() => {
      const results = this.checkObligations();
      this.emit('obligationCheckComplete', results);
    }, 60000);

    // Clean expired quotes every 10 seconds
    setInterval(() => {
      const now = new Date();
      for (const [pair, quotes] of this.activeQuotes) {
        this.activeQuotes.set(pair, quotes.filter(q => q.validUntil > now));
      }
    }, 10000);

    // Update uptime metrics every hour
    setInterval(() => {
      for (const mm of this.marketMakers.values()) {
        // Calculate actual uptime based on quote history
        const quotesLast24h = this.quoteHistory.filter(
          q => q.mmId === mm.id &&
               q.createdAt.getTime() > Date.now() - 24 * 60 * 60 * 1000
        );

        mm.metrics.quoteCount24h = quotesLast24h.length;

        // Expected quotes (one per 5 seconds = 17280 per day)
        const expectedQuotes = 17280 * mm.assignedPairs.length;
        mm.uptimePercent = Math.min(100, (quotesLast24h.length / expectedQuotes) * 100);
      }
    }, 3600000);
  }
}

// Export types
export {
  MMStatus,
  QuoteType,
  MarketMaker,
  MMTier,
  Quote,
  MMPerformanceMetrics,
  MMObligation,
  QuoteEvaluation
};
