import { EventEmitter } from 'events';
import * as crypto from 'crypto';

/**
 * BATCH AUCTION MATCHING ENGINE
 *
 * HYPOTHESIS: A fair batch auction mechanism with uniform clearing price
 * will eliminate front-running, reduce manipulation by 95%, and achieve
 * optimal price discovery with <0.1% price deviation from fair value.
 *
 * SUCCESS METRICS:
 * - Front-running elimination: 100%
 * - Price discovery efficiency: >99.9%
 * - Order fill rate: >98%
 * - Settlement latency: <5 seconds per batch
 * - Gas efficiency: >50% savings vs continuous
 *
 * SECURITY CONSIDERATIONS:
 * - Sealed-bid commitment scheme
 * - Anti-manipulation safeguards
 * - MEV protection
 * - Fair clearing price calculation
 * - Order privacy until settlement
 */

// Auction state
enum AuctionState {
  COLLECTING = 'collecting',
  SEALED = 'sealed',
  CALCULATING = 'calculating',
  SETTLING = 'settling',
  COMPLETED = 'completed',
  CANCELLED = 'cancelled'
}

// Order type
enum AuctionOrderType {
  MARKET = 'market',
  LIMIT = 'limit',
  FILL_OR_KILL = 'fill_or_kill',
  IMMEDIATE_OR_CANCEL = 'immediate_or_cancel'
}

// Order side
enum OrderSide {
  BUY = 'buy',
  SELL = 'sell'
}

// Sealed order (commitment)
interface SealedOrder {
  commitment: string;
  userId: string;
  timestamp: Date;
  revealed: boolean;
}

// Revealed order
interface AuctionOrder {
  orderId: string;
  userId: string;
  pair: string;
  side: OrderSide;
  type: AuctionOrderType;
  quantity: bigint;
  limitPrice?: bigint; // Only for limit orders
  salt: string;
  timestamp: Date;
  filled: boolean;
  filledQuantity: bigint;
  filledPrice?: bigint;
}

// Batch auction
interface BatchAuction {
  auctionId: string;
  pair: string;
  state: AuctionState;
  startTime: Date;
  endTime: Date;
  revealDeadline: Date;
  sealedOrders: Map<string, SealedOrder>; // commitment -> sealed order
  revealedOrders: Map<string, AuctionOrder>;
  clearingPrice?: bigint;
  matchedVolume?: bigint;
  totalBuyVolume: bigint;
  totalSellVolume: bigint;
  settlements: Settlement[];
  metadata: AuctionMetadata;
}

// Settlement
interface Settlement {
  settlementId: string;
  buyOrderId: string;
  sellOrderId: string;
  quantity: bigint;
  price: bigint;
  buyerFee: bigint;
  sellerFee: bigint;
  timestamp: Date;
}

// Auction metadata
interface AuctionMetadata {
  participantCount: number;
  orderCount: number;
  priceRange: { min: bigint; max: bigint };
  imbalanceRatio: number;
  clearingVolumePercent: number;
}

// Auction configuration
interface AuctionConfig {
  pair: string;
  collectionDuration: number; // ms
  revealDuration: number; // ms
  minOrderSize: bigint;
  maxOrderSize: bigint;
  tickSize: bigint;
  makerFee: number; // basis points
  takerFee: number; // basis points
  minParticipants: number;
  maxOrders: number;
}

// Clearing result
interface ClearingResult {
  clearingPrice: bigint;
  matchedBuyVolume: bigint;
  matchedSellVolume: bigint;
  unfilledBuyVolume: bigint;
  unfilledSellVolume: bigint;
  priceImpact: number;
}

// Order book snapshot for auction
interface AuctionOrderBook {
  bids: { price: bigint; quantity: bigint }[];
  asks: { price: bigint; quantity: bigint }[];
  midPrice: bigint;
}

export class BatchAuctionEngine extends EventEmitter {
  private auctions: Map<string, BatchAuction> = new Map();
  private orderCommitments: Map<string, string> = new Map(); // orderId -> auctionId
  private configs: Map<string, AuctionConfig> = new Map();
  private auctionHistory: BatchAuction[] = [];

  // Global settings
  private defaultCollectionDuration: number = 30000; // 30 seconds
  private defaultRevealDuration: number = 15000; // 15 seconds
  private maxAuctionsPerPair: number = 1;

  constructor() {
    super();
    this.startAuctionScheduler();
  }

  /**
   * Create auction configuration
   */
  createConfig(config: AuctionConfig): void {
    this.configs.set(config.pair, config);
    this.emit('configCreated', config);
  }

  /**
   * Start new batch auction
   */
  startAuction(pair: string): BatchAuction {
    const config = this.configs.get(pair);
    if (!config) throw new Error('No config for pair');

    // Check if auction already running
    const existingAuction = Array.from(this.auctions.values())
      .find(a => a.pair === pair && a.state === AuctionState.COLLECTING);

    if (existingAuction) {
      throw new Error('Auction already running for this pair');
    }

    const now = new Date();
    const auction: BatchAuction = {
      auctionId: crypto.randomBytes(16).toString('hex'),
      pair,
      state: AuctionState.COLLECTING,
      startTime: now,
      endTime: new Date(now.getTime() + config.collectionDuration),
      revealDeadline: new Date(now.getTime() + config.collectionDuration + config.revealDuration),
      sealedOrders: new Map(),
      revealedOrders: new Map(),
      totalBuyVolume: 0n,
      totalSellVolume: 0n,
      settlements: [],
      metadata: {
        participantCount: 0,
        orderCount: 0,
        priceRange: { min: 0n, max: 0n },
        imbalanceRatio: 0,
        clearingVolumePercent: 0
      }
    };

    this.auctions.set(auction.auctionId, auction);
    this.emit('auctionStarted', auction);

    // Schedule state transitions
    this.scheduleStateTransition(auction);

    return auction;
  }

  /**
   * Submit sealed order (commitment phase)
   */
  submitSealedOrder(
    auctionId: string,
    userId: string,
    commitment: string
  ): boolean {
    const auction = this.auctions.get(auctionId);
    if (!auction) throw new Error('Auction not found');

    if (auction.state !== AuctionState.COLLECTING) {
      throw new Error('Auction not in collection phase');
    }

    if (new Date() > auction.endTime) {
      throw new Error('Collection period ended');
    }

    const config = this.configs.get(auction.pair)!;
    if (auction.sealedOrders.size >= config.maxOrders) {
      throw new Error('Auction order limit reached');
    }

    const sealedOrder: SealedOrder = {
      commitment,
      userId,
      timestamp: new Date(),
      revealed: false
    };

    auction.sealedOrders.set(commitment, sealedOrder);
    this.orderCommitments.set(commitment, auctionId);

    this.emit('orderCommitted', { auctionId, userId, commitment });
    return true;
  }

  /**
   * Reveal order (reveal phase)
   */
  revealOrder(
    commitment: string,
    orderId: string,
    side: OrderSide,
    type: AuctionOrderType,
    quantity: bigint,
    limitPrice: bigint | undefined,
    salt: string
  ): AuctionOrder | null {
    const auctionId = this.orderCommitments.get(commitment);
    if (!auctionId) throw new Error('Commitment not found');

    const auction = this.auctions.get(auctionId);
    if (!auction) throw new Error('Auction not found');

    if (auction.state !== AuctionState.SEALED) {
      throw new Error('Not in reveal phase');
    }

    if (new Date() > auction.revealDeadline) {
      throw new Error('Reveal deadline passed');
    }

    const sealedOrder = auction.sealedOrders.get(commitment);
    if (!sealedOrder) throw new Error('Sealed order not found');
    if (sealedOrder.revealed) throw new Error('Already revealed');

    // Verify commitment
    const computedCommitment = this.computeCommitment(
      orderId,
      sealedOrder.userId,
      side,
      type,
      quantity,
      limitPrice,
      salt
    );

    if (computedCommitment !== commitment) {
      this.emit('invalidReveal', { commitment, reason: 'Commitment mismatch' });
      return null;
    }

    // Validate order
    const config = this.configs.get(auction.pair)!;
    if (quantity < config.minOrderSize || quantity > config.maxOrderSize) {
      throw new Error('Invalid order size');
    }

    if (type === AuctionOrderType.LIMIT && !limitPrice) {
      throw new Error('Limit price required');
    }

    if (limitPrice && limitPrice % config.tickSize !== 0n) {
      throw new Error('Price not aligned to tick size');
    }

    const order: AuctionOrder = {
      orderId,
      userId: sealedOrder.userId,
      pair: auction.pair,
      side,
      type,
      quantity,
      limitPrice,
      salt,
      timestamp: sealedOrder.timestamp,
      filled: false,
      filledQuantity: 0n
    };

    sealedOrder.revealed = true;
    auction.revealedOrders.set(orderId, order);

    // Update volumes
    if (side === OrderSide.BUY) {
      auction.totalBuyVolume += quantity;
    } else {
      auction.totalSellVolume += quantity;
    }

    this.emit('orderRevealed', order);
    return order;
  }

  /**
   * Calculate clearing price
   */
  calculateClearingPrice(auctionId: string): ClearingResult {
    const auction = this.auctions.get(auctionId);
    if (!auction) throw new Error('Auction not found');

    if (auction.state !== AuctionState.CALCULATING) {
      throw new Error('Not in calculation phase');
    }

    const orders = Array.from(auction.revealedOrders.values());

    // Separate buy and sell orders
    const buyOrders = orders
      .filter(o => o.side === OrderSide.BUY)
      .sort((a, b) => {
        // Market orders have highest priority, then by price descending
        if (a.type === AuctionOrderType.MARKET) return -1;
        if (b.type === AuctionOrderType.MARKET) return 1;
        return Number(b.limitPrice! - a.limitPrice!);
      });

    const sellOrders = orders
      .filter(o => o.side === OrderSide.SELL)
      .sort((a, b) => {
        // Market orders have highest priority, then by price ascending
        if (a.type === AuctionOrderType.MARKET) return -1;
        if (b.type === AuctionOrderType.MARKET) return 1;
        return Number(a.limitPrice! - b.limitPrice!);
      });

    // Find uniform clearing price using supply/demand intersection
    const result = this.findClearingPrice(buyOrders, sellOrders);

    auction.clearingPrice = result.clearingPrice;
    auction.matchedVolume = result.matchedBuyVolume;

    // Update metadata
    auction.metadata.clearingVolumePercent = auction.totalBuyVolume > 0n
      ? Number((result.matchedBuyVolume * 10000n) / auction.totalBuyVolume) / 100
      : 0;

    const imbalance = Number(auction.totalBuyVolume) - Number(auction.totalSellVolume);
    const totalVolume = Number(auction.totalBuyVolume) + Number(auction.totalSellVolume);
    auction.metadata.imbalanceRatio = totalVolume > 0 ? imbalance / totalVolume : 0;

    this.emit('clearingPriceCalculated', { auctionId, result });
    return result;
  }

  /**
   * Execute settlement
   */
  executeSettlement(auctionId: string): Settlement[] {
    const auction = this.auctions.get(auctionId);
    if (!auction) throw new Error('Auction not found');

    if (!auction.clearingPrice) {
      throw new Error('Clearing price not calculated');
    }

    auction.state = AuctionState.SETTLING;

    const config = this.configs.get(auction.pair)!;
    const clearingPrice = auction.clearingPrice;

    // Get eligible orders at clearing price
    const buyOrders = Array.from(auction.revealedOrders.values())
      .filter(o => o.side === OrderSide.BUY && this.isEligibleAtPrice(o, clearingPrice, true));

    const sellOrders = Array.from(auction.revealedOrders.values())
      .filter(o => o.side === OrderSide.SELL && this.isEligibleAtPrice(o, clearingPrice, false));

    // Match orders pro-rata
    const settlements: Settlement[] = [];
    let remainingBuyVolume = buyOrders.reduce((sum, o) => sum + o.quantity - o.filledQuantity, 0n);
    let remainingSellVolume = sellOrders.reduce((sum, o) => sum + o.quantity - o.filledQuantity, 0n);

    const matchableVolume = remainingBuyVolume < remainingSellVolume
      ? remainingBuyVolume
      : remainingSellVolume;

    // Pro-rata matching
    for (const buyOrder of buyOrders) {
      if (matchableVolume === 0n) break;

      const buyProportion = (buyOrder.quantity * 10000n) / remainingBuyVolume;

      for (const sellOrder of sellOrders) {
        const sellProportion = (sellOrder.quantity * 10000n) / remainingSellVolume;
        const minProportion = buyProportion < sellProportion ? buyProportion : sellProportion;

        const matchQuantity = (matchableVolume * minProportion) / 10000n;

        if (matchQuantity > 0n) {
          const buyerFee = (matchQuantity * clearingPrice * BigInt(config.takerFee)) / (10n ** 18n * 10000n);
          const sellerFee = (matchQuantity * clearingPrice * BigInt(config.makerFee)) / (10n ** 18n * 10000n);

          const settlement: Settlement = {
            settlementId: crypto.randomBytes(16).toString('hex'),
            buyOrderId: buyOrder.orderId,
            sellOrderId: sellOrder.orderId,
            quantity: matchQuantity,
            price: clearingPrice,
            buyerFee,
            sellerFee,
            timestamp: new Date()
          };

          settlements.push(settlement);

          buyOrder.filledQuantity += matchQuantity;
          sellOrder.filledQuantity += matchQuantity;

          if (buyOrder.filledQuantity >= buyOrder.quantity) {
            buyOrder.filled = true;
          }
          if (sellOrder.filledQuantity >= sellOrder.quantity) {
            sellOrder.filled = true;
          }
        }
      }
    }

    auction.settlements = settlements;
    auction.state = AuctionState.COMPLETED;

    // Update metadata
    const participants = new Set<string>();
    for (const order of auction.revealedOrders.values()) {
      participants.add(order.userId);
    }
    auction.metadata.participantCount = participants.size;
    auction.metadata.orderCount = auction.revealedOrders.size;

    const prices = Array.from(auction.revealedOrders.values())
      .filter(o => o.limitPrice)
      .map(o => o.limitPrice!);

    if (prices.length > 0) {
      auction.metadata.priceRange = {
        min: prices.reduce((min, p) => p < min ? p : min),
        max: prices.reduce((max, p) => p > max ? p : max)
      };
    }

    this.auctionHistory.push(auction);
    this.emit('settlementCompleted', { auctionId, settlements });

    return settlements;
  }

  /**
   * Get auction status
   */
  getAuctionStatus(auctionId: string): {
    state: AuctionState;
    timeRemaining: number;
    orderCount: number;
    revealedCount: number;
    totalBuyVolume: bigint;
    totalSellVolume: bigint;
    clearingPrice?: bigint;
  } | null {
    const auction = this.auctions.get(auctionId);
    if (!auction) return null;

    let timeRemaining = 0;
    if (auction.state === AuctionState.COLLECTING) {
      timeRemaining = auction.endTime.getTime() - Date.now();
    } else if (auction.state === AuctionState.SEALED) {
      timeRemaining = auction.revealDeadline.getTime() - Date.now();
    }

    const revealedCount = Array.from(auction.sealedOrders.values())
      .filter(so => so.revealed).length;

    return {
      state: auction.state,
      timeRemaining: Math.max(0, timeRemaining),
      orderCount: auction.sealedOrders.size,
      revealedCount,
      totalBuyVolume: auction.totalBuyVolume,
      totalSellVolume: auction.totalSellVolume,
      clearingPrice: auction.clearingPrice
    };
  }

  /**
   * Get auction history
   */
  getAuctionHistory(pair: string, limit: number = 10): BatchAuction[] {
    return this.auctionHistory
      .filter(a => a.pair === pair)
      .slice(-limit);
  }

  /**
   * Compute order commitment
   */
  computeCommitment(
    orderId: string,
    userId: string,
    side: OrderSide,
    type: AuctionOrderType,
    quantity: bigint,
    limitPrice: bigint | undefined,
    salt: string
  ): string {
    const data = `${orderId}:${userId}:${side}:${type}:${quantity.toString()}:${limitPrice?.toString() || ''}:${salt}`;
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Get order book at current state
   */
  getAuctionOrderBook(auctionId: string): AuctionOrderBook | null {
    const auction = this.auctions.get(auctionId);
    if (!auction) return null;

    const bids: { price: bigint; quantity: bigint }[] = [];
    const asks: { price: bigint; quantity: bigint }[] = [];

    // Group orders by price
    const bidMap = new Map<string, bigint>();
    const askMap = new Map<string, bigint>();

    for (const order of auction.revealedOrders.values()) {
      if (!order.limitPrice) continue;

      const priceKey = order.limitPrice.toString();

      if (order.side === OrderSide.BUY) {
        const current = bidMap.get(priceKey) || 0n;
        bidMap.set(priceKey, current + order.quantity);
      } else {
        const current = askMap.get(priceKey) || 0n;
        askMap.set(priceKey, current + order.quantity);
      }
    }

    // Convert to arrays
    for (const [price, quantity] of bidMap) {
      bids.push({ price: BigInt(price), quantity });
    }
    for (const [price, quantity] of askMap) {
      asks.push({ price: BigInt(price), quantity });
    }

    // Sort
    bids.sort((a, b) => Number(b.price - a.price));
    asks.sort((a, b) => Number(a.price - b.price));

    const midPrice = bids.length > 0 && asks.length > 0
      ? (bids[0].price + asks[0].price) / 2n
      : 0n;

    return { bids, asks, midPrice };
  }

  private findClearingPrice(
    buyOrders: AuctionOrder[],
    sellOrders: AuctionOrder[]
  ): ClearingResult {
    // Build cumulative supply and demand curves
    const demandCurve: { price: bigint; cumulativeQuantity: bigint }[] = [];
    const supplyCurve: { price: bigint; cumulativeQuantity: bigint }[] = [];

    // Demand curve (high to low price)
    let cumulativeBuy = 0n;
    for (const order of buyOrders) {
      cumulativeBuy += order.quantity;
      if (order.type !== AuctionOrderType.MARKET && order.limitPrice) {
        demandCurve.push({
          price: order.limitPrice,
          cumulativeQuantity: cumulativeBuy
        });
      }
    }

    // Supply curve (low to high price)
    let cumulativeSell = 0n;
    for (const order of sellOrders) {
      cumulativeSell += order.quantity;
      if (order.type !== AuctionOrderType.MARKET && order.limitPrice) {
        supplyCurve.push({
          price: order.limitPrice,
          cumulativeQuantity: cumulativeSell
        });
      }
    }

    // Find intersection (clearing price)
    let clearingPrice = 0n;
    let maxVolume = 0n;

    // Check all possible prices
    const allPrices = new Set<bigint>();
    for (const point of demandCurve) allPrices.add(point.price);
    for (const point of supplyCurve) allPrices.add(point.price);

    for (const price of allPrices) {
      // Find demand at this price (buyers willing to pay >= price)
      let demand = 0n;
      for (const order of buyOrders) {
        if (order.type === AuctionOrderType.MARKET || (order.limitPrice && order.limitPrice >= price)) {
          demand += order.quantity;
        }
      }

      // Find supply at this price (sellers willing to accept <= price)
      let supply = 0n;
      for (const order of sellOrders) {
        if (order.type === AuctionOrderType.MARKET || (order.limitPrice && order.limitPrice <= price)) {
          supply += order.quantity;
        }
      }

      const matchableVolume = demand < supply ? demand : supply;

      if (matchableVolume > maxVolume) {
        maxVolume = matchableVolume;
        clearingPrice = price;
      }
    }

    // Calculate unfilled volumes
    let totalBuyVolume = 0n;
    let totalSellVolume = 0n;
    for (const order of buyOrders) totalBuyVolume += order.quantity;
    for (const order of sellOrders) totalSellVolume += order.quantity;

    const unfilledBuy = totalBuyVolume - maxVolume;
    const unfilledSell = totalSellVolume - maxVolume;

    // Price impact (simplified)
    const priceImpact = demandCurve.length > 0 && supplyCurve.length > 0
      ? Number((clearingPrice - demandCurve[0].price) * 10000n / demandCurve[0].price) / 100
      : 0;

    return {
      clearingPrice,
      matchedBuyVolume: maxVolume,
      matchedSellVolume: maxVolume,
      unfilledBuyVolume: unfilledBuy,
      unfilledSellVolume: unfilledSell,
      priceImpact
    };
  }

  private isEligibleAtPrice(order: AuctionOrder, clearingPrice: bigint, isBuy: boolean): boolean {
    if (order.type === AuctionOrderType.MARKET) return true;
    if (!order.limitPrice) return false;

    if (isBuy) {
      return order.limitPrice >= clearingPrice;
    } else {
      return order.limitPrice <= clearingPrice;
    }
  }

  private scheduleStateTransition(auction: BatchAuction): void {
    // Transition to SEALED after collection ends
    const collectionRemaining = auction.endTime.getTime() - Date.now();
    setTimeout(() => {
      if (this.auctions.has(auction.auctionId)) {
        auction.state = AuctionState.SEALED;
        this.emit('collectionEnded', auction.auctionId);
      }
    }, Math.max(0, collectionRemaining));

    // Transition to CALCULATING after reveal deadline
    const revealRemaining = auction.revealDeadline.getTime() - Date.now();
    setTimeout(() => {
      if (this.auctions.has(auction.auctionId)) {
        auction.state = AuctionState.CALCULATING;
        this.emit('revealEnded', auction.auctionId);

        // Auto-calculate and settle
        try {
          this.calculateClearingPrice(auction.auctionId);
          this.executeSettlement(auction.auctionId);
        } catch (error) {
          this.emit('auctionError', { auctionId: auction.auctionId, error });
        }
      }
    }, Math.max(0, revealRemaining));
  }

  private startAuctionScheduler(): void {
    // Start new auctions periodically for configured pairs
    setInterval(() => {
      for (const [pair, config] of this.configs) {
        const activeAuction = Array.from(this.auctions.values())
          .find(a => a.pair === pair && a.state !== AuctionState.COMPLETED && a.state !== AuctionState.CANCELLED);

        if (!activeAuction) {
          try {
            this.startAuction(pair);
          } catch (error) {
            this.emit('schedulerError', { pair, error });
          }
        }
      }
    }, 60000); // Check every minute
  }
}

// Export types
export {
  AuctionState,
  AuctionOrderType,
  OrderSide,
  SealedOrder,
  AuctionOrder,
  BatchAuction,
  Settlement,
  AuctionMetadata,
  AuctionConfig,
  ClearingResult,
  AuctionOrderBook
};
