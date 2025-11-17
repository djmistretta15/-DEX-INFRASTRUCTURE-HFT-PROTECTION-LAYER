import { EventEmitter } from 'events';
import * as crypto from 'crypto';

/**
 * ADVANCED ORDER TYPE ENGINE
 *
 * HYPOTHESIS: Supporting professional order types (stop-loss, OCO, trailing stop)
 * will attract institutional traders and increase average order size by 300%.
 *
 * SUCCESS METRICS:
 * - Order type usage >40% for advanced types
 * - Average order size increase >300%
 * - Order execution precision >99.5%
 * - Trigger accuracy within 0.01%
 * - Zero missed stop-losses during high volatility
 *
 * SECURITY CONSIDERATIONS:
 * - Price oracle manipulation protection
 * - Gas-efficient trigger monitoring
 * - Slippage protection for stop orders
 * - Order confidentiality until trigger
 * - Front-running prevention
 */

// Order types
enum AdvancedOrderType {
  STOP_LOSS = 'stop_loss',
  STOP_LIMIT = 'stop_limit',
  TAKE_PROFIT = 'take_profit',
  TRAILING_STOP = 'trailing_stop',
  OCO = 'oco', // One-Cancels-Other
  BRACKET = 'bracket',
  ICEBERG = 'iceberg',
  TWAP = 'twap', // Time-Weighted Average Price
  VWAP = 'vwap', // Volume-Weighted Average Price
  FILL_OR_KILL = 'fill_or_kill',
  IMMEDIATE_OR_CANCEL = 'immediate_or_cancel',
  POST_ONLY = 'post_only',
  REDUCE_ONLY = 'reduce_only'
}

// Order status
enum OrderStatus {
  PENDING = 'pending',
  ACTIVE = 'active',
  TRIGGERED = 'triggered',
  EXECUTING = 'executing',
  PARTIALLY_FILLED = 'partially_filled',
  FILLED = 'filled',
  CANCELLED = 'cancelled',
  EXPIRED = 'expired',
  REJECTED = 'rejected'
}

// Trigger condition
interface TriggerCondition {
  type: 'price_above' | 'price_below' | 'price_crosses' | 'time' | 'volume' | 'oracle';
  value: bigint | number;
  currentValue?: bigint | number;
  triggered: boolean;
  triggeredAt?: Date;
}

// Advanced order structure
interface AdvancedOrder {
  id: string;
  userId: string;
  type: AdvancedOrderType;
  symbol: string;
  side: 'buy' | 'sell';
  quantity: bigint;
  filledQuantity: bigint;
  triggerPrice?: bigint;
  limitPrice?: bigint;
  trailingPercent?: number;
  trailingDelta?: bigint;
  peakPrice?: bigint;
  conditions: TriggerCondition[];
  linkedOrders?: string[];
  childOrders?: AdvancedOrder[];
  status: OrderStatus;
  createdAt: Date;
  activatedAt?: Date;
  triggeredAt?: Date;
  filledAt?: Date;
  expiresAt?: Date;
  slippageProtection: number; // basis points
  retries: number;
  maxRetries: number;
  metadata: Map<string, any>;
}

// TWAP configuration
interface TWAPConfig {
  totalQuantity: bigint;
  duration: number; // seconds
  intervals: number;
  randomization: number; // percentage
  minTradeSize: bigint;
  maxDeviation: number; // from TWAP price
}

// Iceberg configuration
interface IcebergConfig {
  totalQuantity: bigint;
  visibleQuantity: bigint;
  priceVariance: number; // basis points
  refillThreshold: number; // percentage
}

// Bracket order configuration
interface BracketConfig {
  entryOrder: {
    side: 'buy' | 'sell';
    quantity: bigint;
    limitPrice: bigint;
  };
  takeProfitPrice: bigint;
  stopLossPrice: bigint;
}

// Price feed
interface PriceFeed {
  symbol: string;
  currentPrice: bigint;
  lastUpdate: Date;
  high24h: bigint;
  low24h: bigint;
  volume24h: bigint;
}

// Configuration
interface AdvancedOrderConfig {
  maxActiveOrders: number;
  maxTriggerCheckInterval: number; // ms
  defaultSlippageProtection: number;
  maxOrderLifetime: number; // seconds
  oracleStaleThreshold: number; // seconds
  minTrailingPercent: number;
  maxTrailingPercent: number;
}

/**
 * Price Oracle Manager
 */
class PriceOracleManager extends EventEmitter {
  private prices: Map<string, PriceFeed> = new Map();
  private updateInterval: number;
  private staleThreshold: number;

  constructor(updateIntervalMs: number, staleThresholdSeconds: number) {
    super();
    this.updateInterval = updateIntervalMs;
    this.staleThreshold = staleThresholdSeconds;
    this.startPriceUpdates();
  }

  /**
   * Update price for symbol
   */
  updatePrice(symbol: string, price: bigint): void {
    const existing = this.prices.get(symbol);
    const now = new Date();

    const feed: PriceFeed = {
      symbol,
      currentPrice: price,
      lastUpdate: now,
      high24h: existing ? (price > existing.high24h ? price : existing.high24h) : price,
      low24h: existing ? (price < existing.low24h ? price : existing.low24h) : price,
      volume24h: existing?.volume24h || 0n
    };

    this.prices.set(symbol, feed);
    this.emit('priceUpdate', { symbol, price, timestamp: now });
  }

  /**
   * Get current price
   */
  getPrice(symbol: string): bigint | null {
    const feed = this.prices.get(symbol);
    if (!feed) return null;

    // Check for staleness
    const age = (Date.now() - feed.lastUpdate.getTime()) / 1000;
    if (age > this.staleThreshold) {
      this.emit('stalePriceWarning', { symbol, age });
      return null;
    }

    return feed.currentPrice;
  }

  /**
   * Check if price crosses threshold
   */
  checkPriceCross(
    symbol: string,
    threshold: bigint,
    direction: 'above' | 'below'
  ): boolean {
    const price = this.getPrice(symbol);
    if (!price) return false;

    if (direction === 'above') {
      return price >= threshold;
    } else {
      return price <= threshold;
    }
  }

  /**
   * Get all price feeds
   */
  getAllPrices(): Map<string, PriceFeed> {
    return new Map(this.prices);
  }

  private startPriceUpdates(): void {
    setInterval(() => {
      this.emit('priceCheckCycle');
    }, this.updateInterval);
  }
}

/**
 * Trigger Monitor - watches for order trigger conditions
 */
class TriggerMonitor extends EventEmitter {
  private orders: Map<string, AdvancedOrder> = new Map();
  private oracleManager: PriceOracleManager;
  private checkInterval: number;

  constructor(oracleManager: PriceOracleManager, checkIntervalMs: number) {
    super();
    this.oracleManager = oracleManager;
    this.checkInterval = checkIntervalMs;

    // Listen for price updates
    this.oracleManager.on('priceUpdate', ({ symbol }) => {
      this.checkTriggersForSymbol(symbol);
    });

    // Periodic check for time-based triggers
    setInterval(() => this.checkTimeBasedTriggers(), this.checkInterval);
  }

  /**
   * Add order to monitoring
   */
  addOrder(order: AdvancedOrder): void {
    this.orders.set(order.id, order);
    this.emit('orderMonitored', order.id);
  }

  /**
   * Remove order from monitoring
   */
  removeOrder(orderId: string): void {
    this.orders.delete(orderId);
  }

  /**
   * Check triggers for specific symbol
   */
  private checkTriggersForSymbol(symbol: string): void {
    for (const [orderId, order] of this.orders) {
      if (order.symbol !== symbol) continue;
      if (order.status !== OrderStatus.ACTIVE) continue;

      const triggered = this.evaluateOrderTriggers(order);

      if (triggered) {
        order.status = OrderStatus.TRIGGERED;
        order.triggeredAt = new Date();
        this.emit('orderTriggered', order);
      }
    }
  }

  /**
   * Check time-based triggers
   */
  private checkTimeBasedTriggers(): void {
    const now = new Date();

    for (const [orderId, order] of this.orders) {
      if (order.status !== OrderStatus.ACTIVE) continue;

      // Check expiration
      if (order.expiresAt && now >= order.expiresAt) {
        order.status = OrderStatus.EXPIRED;
        this.emit('orderExpired', order);
        continue;
      }

      // Check time-based conditions
      for (const condition of order.conditions) {
        if (condition.type === 'time' && !condition.triggered) {
          const triggerTime = new Date(condition.value as number);
          if (now >= triggerTime) {
            condition.triggered = true;
            condition.triggeredAt = now;
          }
        }
      }

      // Re-evaluate all triggers
      const allTriggered = this.evaluateOrderTriggers(order);
      if (allTriggered && order.status === OrderStatus.ACTIVE) {
        order.status = OrderStatus.TRIGGERED;
        order.triggeredAt = now;
        this.emit('orderTriggered', order);
      }
    }
  }

  /**
   * Evaluate all triggers for an order
   */
  private evaluateOrderTriggers(order: AdvancedOrder): boolean {
    const currentPrice = this.oracleManager.getPrice(order.symbol);
    if (!currentPrice) return false;

    // Update trailing stop if applicable
    if (order.type === AdvancedOrderType.TRAILING_STOP) {
      this.updateTrailingStop(order, currentPrice);
    }

    // Check all conditions
    for (const condition of order.conditions) {
      if (condition.triggered) continue;

      switch (condition.type) {
        case 'price_above':
          if (currentPrice >= (condition.value as bigint)) {
            condition.triggered = true;
            condition.triggeredAt = new Date();
            condition.currentValue = currentPrice;
          }
          break;

        case 'price_below':
          if (currentPrice <= (condition.value as bigint)) {
            condition.triggered = true;
            condition.triggeredAt = new Date();
            condition.currentValue = currentPrice;
          }
          break;

        case 'price_crosses':
          // Would need historical price to detect crossing
          break;
      }
    }

    // All conditions must be met
    return order.conditions.every(c => c.triggered);
  }

  /**
   * Update trailing stop price
   */
  private updateTrailingStop(order: AdvancedOrder, currentPrice: bigint): void {
    if (!order.peakPrice) {
      order.peakPrice = currentPrice;
    }

    // Update peak price if going in favorable direction
    if (order.side === 'sell' && currentPrice > order.peakPrice) {
      order.peakPrice = currentPrice;
      // Update stop price based on new peak
      if (order.trailingPercent) {
        order.triggerPrice =
          order.peakPrice - (order.peakPrice * BigInt(Math.floor(order.trailingPercent * 100))) / 10000n;
      } else if (order.trailingDelta) {
        order.triggerPrice = order.peakPrice - order.trailingDelta;
      }
      this.emit('trailingStopUpdated', {
        orderId: order.id,
        newTrigger: order.triggerPrice
      });
    } else if (order.side === 'buy' && currentPrice < order.peakPrice) {
      order.peakPrice = currentPrice;
      if (order.trailingPercent) {
        order.triggerPrice =
          order.peakPrice + (order.peakPrice * BigInt(Math.floor(order.trailingPercent * 100))) / 10000n;
      } else if (order.trailingDelta) {
        order.triggerPrice = order.peakPrice + order.trailingDelta;
      }
      this.emit('trailingStopUpdated', {
        orderId: order.id,
        newTrigger: order.triggerPrice
      });
    }

    // Update trigger condition
    const priceCondition = order.conditions.find(
      c => c.type === 'price_below' || c.type === 'price_above'
    );
    if (priceCondition && order.triggerPrice) {
      priceCondition.value = order.triggerPrice;
    }
  }

  /**
   * Get monitored order count
   */
  getMonitoredOrderCount(): number {
    return this.orders.size;
  }
}

/**
 * Order Execution Engine
 */
class OrderExecutionEngine extends EventEmitter {
  private pendingExecutions: Map<string, AdvancedOrder> = new Map();

  /**
   * Execute triggered order
   */
  async executeOrder(order: AdvancedOrder): Promise<{
    success: boolean;
    filledQuantity: bigint;
    avgPrice: bigint;
    error?: string;
  }> {
    order.status = OrderStatus.EXECUTING;
    this.pendingExecutions.set(order.id, order);

    try {
      let result: { success: boolean; filledQuantity: bigint; avgPrice: bigint; error?: string };

      switch (order.type) {
        case AdvancedOrderType.STOP_LOSS:
        case AdvancedOrderType.STOP_LIMIT:
          result = await this.executeStopOrder(order);
          break;

        case AdvancedOrderType.TAKE_PROFIT:
          result = await this.executeTakeProfitOrder(order);
          break;

        case AdvancedOrderType.TRAILING_STOP:
          result = await this.executeTrailingStopOrder(order);
          break;

        case AdvancedOrderType.ICEBERG:
          result = await this.executeIcebergOrder(order);
          break;

        case AdvancedOrderType.TWAP:
          result = await this.executeTWAPOrder(order);
          break;

        case AdvancedOrderType.FILL_OR_KILL:
          result = await this.executeFillOrKillOrder(order);
          break;

        case AdvancedOrderType.IMMEDIATE_OR_CANCEL:
          result = await this.executeIOCOrder(order);
          break;

        default:
          result = await this.executeMarketOrder(order);
      }

      if (result.success) {
        order.filledQuantity = result.filledQuantity;

        if (result.filledQuantity >= order.quantity) {
          order.status = OrderStatus.FILLED;
          order.filledAt = new Date();
        } else if (result.filledQuantity > 0n) {
          order.status = OrderStatus.PARTIALLY_FILLED;
        } else {
          order.status = OrderStatus.REJECTED;
        }
      } else {
        order.status = OrderStatus.REJECTED;
      }

      this.pendingExecutions.delete(order.id);
      this.emit('orderExecuted', { order, result });

      return result;
    } catch (error) {
      order.status = OrderStatus.REJECTED;
      this.pendingExecutions.delete(order.id);

      return {
        success: false,
        filledQuantity: 0n,
        avgPrice: 0n,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  private async executeStopOrder(order: AdvancedOrder): Promise<any> {
    // Execute at market or limit price
    const executionPrice = order.limitPrice || order.triggerPrice;

    // Apply slippage protection
    const maxSlippage = BigInt(order.slippageProtection);
    const minAcceptablePrice = executionPrice! * (10000n - maxSlippage) / 10000n;

    // Simulate execution (would call actual DEX in production)
    return {
      success: true,
      filledQuantity: order.quantity,
      avgPrice: executionPrice!
    };
  }

  private async executeTakeProfitOrder(order: AdvancedOrder): Promise<any> {
    return this.executeStopOrder(order);
  }

  private async executeTrailingStopOrder(order: AdvancedOrder): Promise<any> {
    return this.executeStopOrder(order);
  }

  private async executeIcebergOrder(order: AdvancedOrder): Promise<any> {
    const config = order.metadata.get('icebergConfig') as IcebergConfig;
    if (!config) {
      return { success: false, filledQuantity: 0n, avgPrice: 0n, error: 'Invalid iceberg config' };
    }

    // Execute visible portion
    return {
      success: true,
      filledQuantity: config.visibleQuantity,
      avgPrice: order.limitPrice || 0n
    };
  }

  private async executeTWAPOrder(order: AdvancedOrder): Promise<any> {
    const config = order.metadata.get('twapConfig') as TWAPConfig;
    if (!config) {
      return { success: false, filledQuantity: 0n, avgPrice: 0n, error: 'Invalid TWAP config' };
    }

    const intervalQuantity = config.totalQuantity / BigInt(config.intervals);

    // Execute one interval
    return {
      success: true,
      filledQuantity: intervalQuantity,
      avgPrice: 0n // Would be actual execution price
    };
  }

  private async executeFillOrKillOrder(order: AdvancedOrder): Promise<any> {
    // Must fill entire quantity or nothing
    // Simulate liquidity check
    const availableLiquidity = order.quantity; // Simplified

    if (availableLiquidity >= order.quantity) {
      return {
        success: true,
        filledQuantity: order.quantity,
        avgPrice: order.limitPrice || 0n
      };
    }

    return {
      success: false,
      filledQuantity: 0n,
      avgPrice: 0n,
      error: 'Insufficient liquidity for FOK order'
    };
  }

  private async executeIOCOrder(order: AdvancedOrder): Promise<any> {
    // Fill what's available immediately
    const availableLiquidity = order.quantity * 80n / 100n; // Simulate 80% fill

    return {
      success: true,
      filledQuantity: availableLiquidity,
      avgPrice: order.limitPrice || 0n
    };
  }

  private async executeMarketOrder(order: AdvancedOrder): Promise<any> {
    return {
      success: true,
      filledQuantity: order.quantity,
      avgPrice: 0n
    };
  }
}

/**
 * Main Advanced Order Engine
 */
export class AdvancedOrderEngine extends EventEmitter {
  private config: AdvancedOrderConfig;
  private oracleManager: PriceOracleManager;
  private triggerMonitor: TriggerMonitor;
  private executionEngine: OrderExecutionEngine;
  private orders: Map<string, AdvancedOrder> = new Map();
  private userOrders: Map<string, string[]> = new Map();

  constructor(config: AdvancedOrderConfig) {
    super();
    this.config = config;

    this.oracleManager = new PriceOracleManager(100, config.oracleStaleThreshold);
    this.triggerMonitor = new TriggerMonitor(this.oracleManager, config.maxTriggerCheckInterval);
    this.executionEngine = new OrderExecutionEngine();

    this.setupEventHandlers();
  }

  /**
   * Create stop-loss order
   */
  createStopLossOrder(
    userId: string,
    symbol: string,
    side: 'buy' | 'sell',
    quantity: bigint,
    triggerPrice: bigint,
    slippageProtection: number = this.config.defaultSlippageProtection
  ): AdvancedOrder {
    const order = this.createBaseOrder(
      userId,
      AdvancedOrderType.STOP_LOSS,
      symbol,
      side,
      quantity
    );

    order.triggerPrice = triggerPrice;
    order.slippageProtection = slippageProtection;

    // Add trigger condition
    order.conditions.push({
      type: side === 'sell' ? 'price_below' : 'price_above',
      value: triggerPrice,
      triggered: false
    });

    this.registerOrder(order);
    return order;
  }

  /**
   * Create take-profit order
   */
  createTakeProfitOrder(
    userId: string,
    symbol: string,
    side: 'buy' | 'sell',
    quantity: bigint,
    triggerPrice: bigint,
    slippageProtection: number = this.config.defaultSlippageProtection
  ): AdvancedOrder {
    const order = this.createBaseOrder(
      userId,
      AdvancedOrderType.TAKE_PROFIT,
      symbol,
      side,
      quantity
    );

    order.triggerPrice = triggerPrice;
    order.slippageProtection = slippageProtection;

    order.conditions.push({
      type: side === 'sell' ? 'price_above' : 'price_below',
      value: triggerPrice,
      triggered: false
    });

    this.registerOrder(order);
    return order;
  }

  /**
   * Create trailing stop order
   */
  createTrailingStopOrder(
    userId: string,
    symbol: string,
    side: 'buy' | 'sell',
    quantity: bigint,
    trailingPercent: number,
    slippageProtection: number = this.config.defaultSlippageProtection
  ): AdvancedOrder {
    if (
      trailingPercent < this.config.minTrailingPercent ||
      trailingPercent > this.config.maxTrailingPercent
    ) {
      throw new Error(`Trailing percent must be between ${this.config.minTrailingPercent} and ${this.config.maxTrailingPercent}`);
    }

    const order = this.createBaseOrder(
      userId,
      AdvancedOrderType.TRAILING_STOP,
      symbol,
      side,
      quantity
    );

    order.trailingPercent = trailingPercent;
    order.slippageProtection = slippageProtection;

    // Initial trigger will be set based on current price
    const currentPrice = this.oracleManager.getPrice(symbol);
    if (currentPrice) {
      order.peakPrice = currentPrice;
      if (side === 'sell') {
        order.triggerPrice = currentPrice - (currentPrice * BigInt(Math.floor(trailingPercent * 100))) / 10000n;
      } else {
        order.triggerPrice = currentPrice + (currentPrice * BigInt(Math.floor(trailingPercent * 100))) / 10000n;
      }

      order.conditions.push({
        type: side === 'sell' ? 'price_below' : 'price_above',
        value: order.triggerPrice,
        triggered: false
      });
    }

    this.registerOrder(order);
    return order;
  }

  /**
   * Create OCO (One-Cancels-Other) order pair
   */
  createOCOOrder(
    userId: string,
    symbol: string,
    side: 'buy' | 'sell',
    quantity: bigint,
    takeProfitPrice: bigint,
    stopLossPrice: bigint
  ): { takeProfitOrder: AdvancedOrder; stopLossOrder: AdvancedOrder } {
    const takeProfitOrder = this.createTakeProfitOrder(
      userId,
      symbol,
      side,
      quantity,
      takeProfitPrice
    );

    const stopLossOrder = this.createStopLossOrder(
      userId,
      symbol,
      side,
      quantity,
      stopLossPrice
    );

    // Link orders
    takeProfitOrder.linkedOrders = [stopLossOrder.id];
    stopLossOrder.linkedOrders = [takeProfitOrder.id];

    takeProfitOrder.type = AdvancedOrderType.OCO;
    stopLossOrder.type = AdvancedOrderType.OCO;

    return { takeProfitOrder, stopLossOrder };
  }

  /**
   * Create bracket order (entry + take profit + stop loss)
   */
  createBracketOrder(
    userId: string,
    symbol: string,
    config: BracketConfig
  ): AdvancedOrder {
    const entryOrder = this.createBaseOrder(
      userId,
      AdvancedOrderType.BRACKET,
      symbol,
      config.entryOrder.side,
      config.entryOrder.quantity
    );

    entryOrder.limitPrice = config.entryOrder.limitPrice;

    // Create child orders (will be activated when entry fills)
    const exitSide = config.entryOrder.side === 'buy' ? 'sell' : 'buy';

    const takeProfitChild = this.createBaseOrder(
      userId,
      AdvancedOrderType.TAKE_PROFIT,
      symbol,
      exitSide,
      config.entryOrder.quantity
    );
    takeProfitChild.triggerPrice = config.takeProfitPrice;
    takeProfitChild.status = OrderStatus.PENDING;

    const stopLossChild = this.createBaseOrder(
      userId,
      AdvancedOrderType.STOP_LOSS,
      symbol,
      exitSide,
      config.entryOrder.quantity
    );
    stopLossChild.triggerPrice = config.stopLossPrice;
    stopLossChild.status = OrderStatus.PENDING;

    entryOrder.childOrders = [takeProfitChild, stopLossChild];
    entryOrder.metadata.set('bracketConfig', config);

    this.registerOrder(entryOrder);
    return entryOrder;
  }

  /**
   * Create iceberg order
   */
  createIcebergOrder(
    userId: string,
    symbol: string,
    side: 'buy' | 'sell',
    config: IcebergConfig,
    limitPrice: bigint
  ): AdvancedOrder {
    const order = this.createBaseOrder(
      userId,
      AdvancedOrderType.ICEBERG,
      symbol,
      side,
      config.totalQuantity
    );

    order.limitPrice = limitPrice;
    order.metadata.set('icebergConfig', config);

    this.registerOrder(order);
    return order;
  }

  /**
   * Create TWAP order
   */
  createTWAPOrder(
    userId: string,
    symbol: string,
    side: 'buy' | 'sell',
    config: TWAPConfig
  ): AdvancedOrder {
    const order = this.createBaseOrder(
      userId,
      AdvancedOrderType.TWAP,
      symbol,
      side,
      config.totalQuantity
    );

    order.metadata.set('twapConfig', config);
    order.expiresAt = new Date(Date.now() + config.duration * 1000);

    this.registerOrder(order);
    return order;
  }

  /**
   * Update price feed
   */
  updatePrice(symbol: string, price: bigint): void {
    this.oracleManager.updatePrice(symbol, price);
  }

  /**
   * Cancel order
   */
  cancelOrder(orderId: string, userId: string): boolean {
    const order = this.orders.get(orderId);
    if (!order) return false;

    if (order.userId !== userId) {
      throw new Error('Not authorized to cancel this order');
    }

    if (order.status !== OrderStatus.ACTIVE && order.status !== OrderStatus.PENDING) {
      throw new Error(`Cannot cancel order in ${order.status} status`);
    }

    order.status = OrderStatus.CANCELLED;
    this.triggerMonitor.removeOrder(orderId);

    // Cancel linked orders (OCO)
    if (order.linkedOrders) {
      for (const linkedId of order.linkedOrders) {
        const linkedOrder = this.orders.get(linkedId);
        if (linkedOrder && linkedOrder.status === OrderStatus.ACTIVE) {
          linkedOrder.status = OrderStatus.CANCELLED;
          this.triggerMonitor.removeOrder(linkedId);
        }
      }
    }

    this.emit('orderCancelled', order);
    return true;
  }

  /**
   * Get user's orders
   */
  getUserOrders(userId: string): AdvancedOrder[] {
    const orderIds = this.userOrders.get(userId) || [];
    return orderIds.map(id => this.orders.get(id)!).filter(o => o);
  }

  /**
   * Get order by ID
   */
  getOrder(orderId: string): AdvancedOrder | undefined {
    return this.orders.get(orderId);
  }

  /**
   * Get system statistics
   */
  getStatistics(): {
    totalOrders: number;
    activeOrders: number;
    triggeredOrders: number;
    filledOrders: number;
    ordersByType: Map<AdvancedOrderType, number>;
  } {
    const ordersByType = new Map<AdvancedOrderType, number>();
    let active = 0;
    let triggered = 0;
    let filled = 0;

    for (const order of this.orders.values()) {
      const count = ordersByType.get(order.type) || 0;
      ordersByType.set(order.type, count + 1);

      if (order.status === OrderStatus.ACTIVE) active++;
      if (order.status === OrderStatus.TRIGGERED) triggered++;
      if (order.status === OrderStatus.FILLED) filled++;
    }

    return {
      totalOrders: this.orders.size,
      activeOrders: active,
      triggeredOrders: triggered,
      filledOrders: filled,
      ordersByType
    };
  }

  private createBaseOrder(
    userId: string,
    type: AdvancedOrderType,
    symbol: string,
    side: 'buy' | 'sell',
    quantity: bigint
  ): AdvancedOrder {
    // Check user order limit
    const userOrderCount = (this.userOrders.get(userId) || []).length;
    if (userOrderCount >= this.config.maxActiveOrders) {
      throw new Error(`Maximum active orders (${this.config.maxActiveOrders}) reached`);
    }

    return {
      id: crypto.randomBytes(16).toString('hex'),
      userId,
      type,
      symbol,
      side,
      quantity,
      filledQuantity: 0n,
      conditions: [],
      status: OrderStatus.PENDING,
      createdAt: new Date(),
      slippageProtection: this.config.defaultSlippageProtection,
      retries: 0,
      maxRetries: 3,
      metadata: new Map()
    };
  }

  private registerOrder(order: AdvancedOrder): void {
    this.orders.set(order.id, order);

    if (!this.userOrders.has(order.userId)) {
      this.userOrders.set(order.userId, []);
    }
    this.userOrders.get(order.userId)!.push(order.id);

    // Activate order
    order.status = OrderStatus.ACTIVE;
    order.activatedAt = new Date();

    // Set expiration if not set
    if (!order.expiresAt) {
      order.expiresAt = new Date(Date.now() + this.config.maxOrderLifetime * 1000);
    }

    // Add to monitoring
    this.triggerMonitor.addOrder(order);

    this.emit('orderCreated', order);
  }

  private setupEventHandlers(): void {
    // Handle triggered orders
    this.triggerMonitor.on('orderTriggered', async (order: AdvancedOrder) => {
      this.emit('orderTriggered', order);

      // Execute the order
      const result = await this.executionEngine.executeOrder(order);

      // Handle OCO cancellation
      if (order.linkedOrders && result.success) {
        for (const linkedId of order.linkedOrders) {
          const linkedOrder = this.orders.get(linkedId);
          if (linkedOrder && linkedOrder.status === OrderStatus.ACTIVE) {
            linkedOrder.status = OrderStatus.CANCELLED;
            this.triggerMonitor.removeOrder(linkedId);
            this.emit('ocoOrderCancelled', linkedOrder);
          }
        }
      }

      // Activate child orders for bracket orders
      if (order.childOrders && result.success) {
        for (const child of order.childOrders) {
          child.status = OrderStatus.ACTIVE;
          this.registerOrder(child);
        }
      }
    });

    // Handle expired orders
    this.triggerMonitor.on('orderExpired', (order: AdvancedOrder) => {
      this.emit('orderExpired', order);
      this.triggerMonitor.removeOrder(order.id);
    });

    // Forward execution events
    this.executionEngine.on('orderExecuted', (data) => {
      this.emit('orderExecuted', data);
    });
  }
}

// Export types and configurations
export {
  AdvancedOrderType,
  OrderStatus,
  AdvancedOrder,
  TriggerCondition,
  TWAPConfig,
  IcebergConfig,
  BracketConfig,
  PriceOracleManager,
  TriggerMonitor,
  OrderExecutionEngine
};

// Default configuration
export const defaultAdvancedOrderConfig: AdvancedOrderConfig = {
  maxActiveOrders: 100,
  maxTriggerCheckInterval: 1000, // 1 second
  defaultSlippageProtection: 50, // 0.5%
  maxOrderLifetime: 30 * 24 * 60 * 60, // 30 days
  oracleStaleThreshold: 60, // 60 seconds
  minTrailingPercent: 0.1, // 0.1%
  maxTrailingPercent: 20 // 20%
};
