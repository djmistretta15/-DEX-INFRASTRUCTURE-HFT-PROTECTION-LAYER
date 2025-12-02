import { EventEmitter } from 'events';
import * as crypto from 'crypto';

/**
 * MARGIN TRADING SYSTEM
 *
 * HYPOTHESIS: A sophisticated margin trading system with isolated and cross-margin
 * modes, automatic position management, and risk controls will enable professional
 * trading with <0.1% bad debt rate.
 *
 * SUCCESS METRICS:
 * - Bad debt rate: <0.1%
 * - Liquidation efficiency: >98%
 * - User capital efficiency: >10x leverage available
 * - Risk management accuracy: >99%
 * - Order execution success: >99.5%
 *
 * SECURITY CONSIDERATIONS:
 * - Isolated vs cross margin risk separation
 * - Real-time position monitoring
 * - Automated deleveraging
 * - Insurance fund protection
 * - Maximum leverage limits
 * - Position size limits
 */

// Margin mode
enum MarginMode {
  ISOLATED = 'isolated',
  CROSS = 'cross'
}

// Position side
enum PositionSide {
  LONG = 'long',
  SHORT = 'short'
}

// Order type
enum OrderType {
  MARKET = 'market',
  LIMIT = 'limit',
  STOP_MARKET = 'stop_market',
  STOP_LIMIT = 'stop_limit',
  TAKE_PROFIT = 'take_profit',
  TRAILING_STOP = 'trailing_stop'
}

// Position status
enum PositionStatus {
  OPEN = 'open',
  CLOSING = 'closing',
  CLOSED = 'closed',
  LIQUIDATING = 'liquidating',
  LIQUIDATED = 'liquidated',
  ADL = 'adl' // Auto-deleveraging
}

// Margin account
interface MarginAccount {
  userId: string;
  mode: MarginMode;
  totalBalance: bigint;
  availableBalance: bigint;
  lockedBalance: bigint;
  unrealizedPnL: bigint;
  marginLevel: number; // percentage
  maintenanceMargin: bigint;
  initialMargin: bigint;
  positions: Map<string, MarginPosition>;
  orders: Map<string, MarginOrder>;
  riskScore: number;
  lastUpdateTime: Date;
}

// Margin position
interface MarginPosition {
  positionId: string;
  userId: string;
  symbol: string;
  side: PositionSide;
  entryPrice: bigint;
  markPrice: bigint;
  quantity: bigint;
  notionalValue: bigint;
  leverage: number;
  marginMode: MarginMode;
  isolatedMargin: bigint; // Only for isolated mode
  unrealizedPnL: bigint;
  realizedPnL: bigint;
  liquidationPrice: bigint;
  bankruptcyPrice: bigint;
  takeProfitPrice?: bigint;
  stopLossPrice?: bigint;
  fundingAccrued: bigint;
  status: PositionStatus;
  openTime: Date;
  lastFundingTime: Date;
}

// Margin order
interface MarginOrder {
  orderId: string;
  userId: string;
  symbol: string;
  side: PositionSide;
  type: OrderType;
  price: bigint;
  quantity: bigint;
  filledQuantity: bigint;
  leverage: number;
  marginMode: MarginMode;
  reduceOnly: boolean;
  postOnly: boolean;
  timeInForce: 'GTC' | 'IOC' | 'FOK';
  status: 'pending' | 'open' | 'partial' | 'filled' | 'cancelled' | 'rejected';
  createdAt: Date;
  updatedAt: Date;
}

// Market configuration
interface MarketConfig {
  symbol: string;
  baseAsset: string;
  quoteAsset: string;
  maxLeverage: number;
  minQuantity: bigint;
  maxQuantity: bigint;
  tickSize: bigint;
  stepSize: bigint;
  initialMarginRate: number; // basis points
  maintenanceMarginRate: number; // basis points
  takerFee: number; // basis points
  makerFee: number; // basis points
  fundingInterval: number; // hours
  maxFundingRate: number; // basis points
  isActive: boolean;
}

// Risk parameters
interface RiskParameters {
  maxAccountLeverage: number;
  maxPositionSize: bigint;
  maxOrderSize: bigint;
  maxOpenOrders: number;
  maxPositionsPerUser: number;
  marginCallLevel: number; // percentage
  liquidationLevel: number; // percentage
  adlEnabled: boolean;
}

// Funding rate
interface FundingRate {
  symbol: string;
  rate: number; // basis points
  timestamp: Date;
  nextFundingTime: Date;
}

// PnL calculation
interface PnLCalculation {
  entryValue: bigint;
  currentValue: bigint;
  unrealizedPnL: bigint;
  unrealizedPnLPercent: number;
  roe: number; // return on equity
  fees: bigint;
  funding: bigint;
}

// Risk metrics
interface RiskMetrics {
  totalExposure: bigint;
  netExposure: bigint;
  marginRatio: number;
  liquidationRisk: number;
  concentrationRisk: number;
  deltaExposure: bigint;
}

export class MarginTradingSystem extends EventEmitter {
  private accounts: Map<string, MarginAccount> = new Map();
  private markets: Map<string, MarketConfig> = new Map();
  private fundingRates: Map<string, FundingRate> = new Map();
  private riskParams: RiskParameters;

  // Price oracle
  private markPrices: Map<string, bigint> = new Map();
  private indexPrices: Map<string, bigint> = new Map();

  // Insurance fund
  private insuranceFund: bigint = 0n;

  // ADL queue
  private adlQueue: Map<string, string[]> = new Map(); // symbol -> userId[]

  constructor() {
    super();
    this.riskParams = this.initializeRiskParams();
    this.startRiskMonitoring();
    this.startFundingCalculation();
  }

  private initializeRiskParams(): RiskParameters {
    return {
      maxAccountLeverage: 125,
      maxPositionSize: 10000000n * 10n ** 18n, // $10M
      maxOrderSize: 1000000n * 10n ** 18n, // $1M
      maxOpenOrders: 200,
      maxPositionsPerUser: 50,
      marginCallLevel: 80, // 80% margin level warning
      liquidationLevel: 50, // 50% = liquidation
      adlEnabled: true
    };
  }

  /**
   * Create margin account
   */
  createAccount(userId: string, mode: MarginMode, initialDeposit: bigint): MarginAccount {
    if (this.accounts.has(userId)) {
      throw new Error('Account already exists');
    }

    const account: MarginAccount = {
      userId,
      mode,
      totalBalance: initialDeposit,
      availableBalance: initialDeposit,
      lockedBalance: 0n,
      unrealizedPnL: 0n,
      marginLevel: 100,
      maintenanceMargin: 0n,
      initialMargin: 0n,
      positions: new Map(),
      orders: new Map(),
      riskScore: 0,
      lastUpdateTime: new Date()
    };

    this.accounts.set(userId, account);
    this.emit('accountCreated', account);

    return account;
  }

  /**
   * Deposit to margin account
   */
  deposit(userId: string, amount: bigint): void {
    const account = this.accounts.get(userId);
    if (!account) throw new Error('Account not found');

    account.totalBalance += amount;
    account.availableBalance += amount;
    account.lastUpdateTime = new Date();

    this.updateAccountMetrics(userId);
    this.emit('deposit', { userId, amount });
  }

  /**
   * Withdraw from margin account
   */
  withdraw(userId: string, amount: bigint): boolean {
    const account = this.accounts.get(userId);
    if (!account) throw new Error('Account not found');

    if (amount > account.availableBalance) {
      return false;
    }

    // Check if withdrawal would cause margin call
    const newBalance = account.totalBalance - amount;
    const requiredMargin = account.maintenanceMargin;

    if (newBalance < requiredMargin * 2n) {
      return false; // Need at least 2x maintenance margin after withdrawal
    }

    account.totalBalance -= amount;
    account.availableBalance -= amount;
    account.lastUpdateTime = new Date();

    this.updateAccountMetrics(userId);
    this.emit('withdrawal', { userId, amount });

    return true;
  }

  /**
   * Open position
   */
  openPosition(
    userId: string,
    symbol: string,
    side: PositionSide,
    quantity: bigint,
    leverage: number,
    isolatedMargin?: bigint
  ): MarginPosition | null {
    const account = this.accounts.get(userId);
    if (!account) throw new Error('Account not found');

    const market = this.markets.get(symbol);
    if (!market || !market.isActive) throw new Error('Market not found');

    // Validate leverage
    if (leverage > market.maxLeverage) {
      throw new Error(`Leverage exceeds maximum ${market.maxLeverage}x`);
    }

    // Validate quantity
    if (quantity < market.minQuantity || quantity > market.maxQuantity) {
      throw new Error('Invalid quantity');
    }

    // Check position limit
    if (account.positions.size >= this.riskParams.maxPositionsPerUser) {
      throw new Error('Max positions reached');
    }

    // Get mark price
    const markPrice = this.markPrices.get(symbol);
    if (!markPrice) throw new Error('Price not available');

    // Calculate notional value
    const notionalValue = (quantity * markPrice) / 10n ** 18n;

    // Check position size limit
    if (notionalValue > this.riskParams.maxPositionSize) {
      throw new Error('Position size exceeds limit');
    }

    // Calculate required margin
    const initialMarginRate = BigInt(market.initialMarginRate);
    const requiredMargin = (notionalValue * initialMarginRate) / 10000n / BigInt(leverage);

    // Check if user has sufficient margin
    if (account.mode === MarginMode.ISOLATED) {
      if (!isolatedMargin || isolatedMargin < requiredMargin) {
        throw new Error('Insufficient isolated margin');
      }
      if (isolatedMargin > account.availableBalance) {
        throw new Error('Insufficient available balance');
      }
    } else {
      // Cross margin
      if (requiredMargin > account.availableBalance) {
        throw new Error('Insufficient available balance');
      }
    }

    // Calculate liquidation and bankruptcy prices
    const liquidationPrice = this.calculateLiquidationPrice(
      side,
      markPrice,
      leverage,
      market.maintenanceMarginRate
    );

    const bankruptcyPrice = this.calculateBankruptcyPrice(
      side,
      markPrice,
      leverage
    );

    const positionId = crypto.randomBytes(16).toString('hex');
    const position: MarginPosition = {
      positionId,
      userId,
      symbol,
      side,
      entryPrice: markPrice,
      markPrice,
      quantity,
      notionalValue,
      leverage,
      marginMode: account.mode,
      isolatedMargin: account.mode === MarginMode.ISOLATED ? isolatedMargin! : 0n,
      unrealizedPnL: 0n,
      realizedPnL: 0n,
      liquidationPrice,
      bankruptcyPrice,
      fundingAccrued: 0n,
      status: PositionStatus.OPEN,
      openTime: new Date(),
      lastFundingTime: new Date()
    };

    // Lock margin
    if (account.mode === MarginMode.ISOLATED) {
      account.lockedBalance += isolatedMargin!;
      account.availableBalance -= isolatedMargin!;
    } else {
      account.lockedBalance += requiredMargin;
      account.availableBalance -= requiredMargin;
    }

    account.positions.set(positionId, position);
    account.initialMargin += requiredMargin;

    this.updateAccountMetrics(userId);
    this.updateADLQueue(symbol);

    this.emit('positionOpened', position);
    return position;
  }

  /**
   * Close position
   */
  closePosition(userId: string, positionId: string, quantity?: bigint): boolean {
    const account = this.accounts.get(userId);
    if (!account) return false;

    const position = account.positions.get(positionId);
    if (!position) return false;

    const closeQuantity = quantity || position.quantity;
    if (closeQuantity > position.quantity) return false;

    // Calculate PnL
    const pnl = this.calculatePositionPnL(position);

    // Update account balance
    const realizedPnL = (pnl.unrealizedPnL * closeQuantity) / position.quantity;

    if (closeQuantity === position.quantity) {
      // Full close
      position.status = PositionStatus.CLOSED;
      position.realizedPnL += realizedPnL;

      // Release margin
      if (position.marginMode === MarginMode.ISOLATED) {
        account.lockedBalance -= position.isolatedMargin;
        account.availableBalance += position.isolatedMargin + realizedPnL;
      } else {
        const marginToRelease = (position.notionalValue * BigInt(10000 / position.leverage)) / 10000n;
        account.lockedBalance -= marginToRelease;
        account.availableBalance += marginToRelease + realizedPnL;
      }

      account.totalBalance = account.availableBalance + account.lockedBalance;
      account.positions.delete(positionId);
    } else {
      // Partial close
      const closeFraction = closeQuantity * 10000n / position.quantity;
      position.quantity -= closeQuantity;
      position.notionalValue = (position.notionalValue * (10000n - closeFraction)) / 10000n;
      position.realizedPnL += realizedPnL;

      if (position.marginMode === MarginMode.ISOLATED) {
        const marginToRelease = (position.isolatedMargin * closeFraction) / 10000n;
        position.isolatedMargin -= marginToRelease;
        account.lockedBalance -= marginToRelease;
        account.availableBalance += marginToRelease + realizedPnL;
      }

      account.totalBalance = account.availableBalance + account.lockedBalance;
    }

    this.updateAccountMetrics(userId);
    this.emit('positionClosed', { positionId, realizedPnL, closeQuantity });

    return true;
  }

  /**
   * Set take profit / stop loss
   */
  setTPSL(
    userId: string,
    positionId: string,
    takeProfitPrice?: bigint,
    stopLossPrice?: bigint
  ): boolean {
    const account = this.accounts.get(userId);
    if (!account) return false;

    const position = account.positions.get(positionId);
    if (!position) return false;

    if (takeProfitPrice) {
      // Validate TP price
      if (position.side === PositionSide.LONG && takeProfitPrice <= position.entryPrice) {
        throw new Error('Take profit must be above entry for long');
      }
      if (position.side === PositionSide.SHORT && takeProfitPrice >= position.entryPrice) {
        throw new Error('Take profit must be below entry for short');
      }
      position.takeProfitPrice = takeProfitPrice;
    }

    if (stopLossPrice) {
      // Validate SL price
      if (position.side === PositionSide.LONG && stopLossPrice >= position.entryPrice) {
        throw new Error('Stop loss must be below entry for long');
      }
      if (position.side === PositionSide.SHORT && stopLossPrice <= position.entryPrice) {
        throw new Error('Stop loss must be above entry for short');
      }
      position.stopLossPrice = stopLossPrice;
    }

    this.emit('tpslUpdated', { positionId, takeProfitPrice, stopLossPrice });
    return true;
  }

  /**
   * Add isolated margin
   */
  addIsolatedMargin(userId: string, positionId: string, amount: bigint): boolean {
    const account = this.accounts.get(userId);
    if (!account) return false;

    const position = account.positions.get(positionId);
    if (!position || position.marginMode !== MarginMode.ISOLATED) return false;

    if (amount > account.availableBalance) return false;

    position.isolatedMargin += amount;
    account.availableBalance -= amount;
    account.lockedBalance += amount;

    // Recalculate liquidation price
    position.liquidationPrice = this.calculateLiquidationPrice(
      position.side,
      position.entryPrice,
      position.leverage,
      this.markets.get(position.symbol)!.maintenanceMarginRate
    );

    this.updateAccountMetrics(userId);
    this.emit('isolatedMarginAdded', { positionId, amount });

    return true;
  }

  /**
   * Update mark price
   */
  updateMarkPrice(symbol: string, price: bigint): void {
    const oldPrice = this.markPrices.get(symbol);
    this.markPrices.set(symbol, price);

    // Update all positions for this symbol
    for (const account of this.accounts.values()) {
      for (const position of account.positions.values()) {
        if (position.symbol === symbol) {
          position.markPrice = price;
          position.unrealizedPnL = this.calculatePositionPnL(position).unrealizedPnL;

          // Check for TP/SL
          this.checkTPSL(position);

          // Check for liquidation
          this.checkLiquidation(account, position);
        }
      }
      this.updateAccountMetrics(account.userId);
    }

    this.emit('markPriceUpdated', { symbol, price, previousPrice: oldPrice });
  }

  /**
   * Apply funding rate
   */
  applyFunding(symbol: string): void {
    const fundingRate = this.fundingRates.get(symbol);
    if (!fundingRate) return;

    for (const account of this.accounts.values()) {
      for (const position of account.positions.values()) {
        if (position.symbol === symbol && position.status === PositionStatus.OPEN) {
          const fundingPayment = this.calculateFundingPayment(position, fundingRate.rate);

          position.fundingAccrued += fundingPayment;
          position.lastFundingTime = new Date();

          // Apply to account
          if (account.mode === MarginMode.CROSS) {
            account.totalBalance += fundingPayment;
            account.availableBalance += fundingPayment;
          } else {
            position.isolatedMargin += fundingPayment;
          }
        }
      }
      this.updateAccountMetrics(account.userId);
    }

    this.emit('fundingApplied', { symbol, rate: fundingRate.rate });
  }

  /**
   * Get account risk metrics
   */
  getAccountRiskMetrics(userId: string): RiskMetrics | null {
    const account = this.accounts.get(userId);
    if (!account) return null;

    let totalExposure = 0n;
    let longExposure = 0n;
    let shortExposure = 0n;

    for (const position of account.positions.values()) {
      const exposure = position.notionalValue;
      totalExposure += exposure;

      if (position.side === PositionSide.LONG) {
        longExposure += exposure;
      } else {
        shortExposure += exposure;
      }
    }

    const netExposure = longExposure > shortExposure
      ? longExposure - shortExposure
      : shortExposure - longExposure;

    const marginRatio = account.totalBalance > 0n
      ? Number((account.maintenanceMargin * 10000n) / account.totalBalance) / 100
      : 0;

    const liquidationRisk = marginRatio > 0
      ? Math.min(100, marginRatio / (this.riskParams.liquidationLevel / 100))
      : 0;

    // Concentration risk (if single position > 50% of total exposure)
    let maxPositionExposure = 0n;
    for (const position of account.positions.values()) {
      if (position.notionalValue > maxPositionExposure) {
        maxPositionExposure = position.notionalValue;
      }
    }
    const concentrationRisk = totalExposure > 0n
      ? Number((maxPositionExposure * 100n) / totalExposure)
      : 0;

    return {
      totalExposure,
      netExposure,
      marginRatio,
      liquidationRisk,
      concentrationRisk,
      deltaExposure: netExposure
    };
  }

  /**
   * Get system statistics
   */
  getSystemStats(): {
    totalAccounts: number;
    totalOpenPositions: number;
    totalNotionalValue: bigint;
    insuranceFund: bigint;
    averageAccountLeverage: number;
  } {
    let totalPositions = 0;
    let totalNotional = 0n;
    let totalLeverage = 0;
    let leverageCount = 0;

    for (const account of this.accounts.values()) {
      totalPositions += account.positions.size;

      for (const position of account.positions.values()) {
        totalNotional += position.notionalValue;
        totalLeverage += position.leverage;
        leverageCount++;
      }
    }

    return {
      totalAccounts: this.accounts.size,
      totalOpenPositions: totalPositions,
      totalNotionalValue: totalNotional,
      insuranceFund: this.insuranceFund,
      averageAccountLeverage: leverageCount > 0 ? totalLeverage / leverageCount : 0
    };
  }

  /**
   * Create market
   */
  createMarket(config: MarketConfig): void {
    this.markets.set(config.symbol, config);
    this.fundingRates.set(config.symbol, {
      symbol: config.symbol,
      rate: 0,
      timestamp: new Date(),
      nextFundingTime: new Date(Date.now() + config.fundingInterval * 60 * 60 * 1000)
    });
    this.emit('marketCreated', config);
  }

  private calculateLiquidationPrice(
    side: PositionSide,
    entryPrice: bigint,
    leverage: number,
    maintenanceMarginRate: number
  ): bigint {
    const mmRate = BigInt(maintenanceMarginRate);

    if (side === PositionSide.LONG) {
      // Liq price = Entry * (1 - 1/leverage + mmRate/10000)
      return entryPrice * (10000n - 10000n / BigInt(leverage) + mmRate) / 10000n;
    } else {
      // Liq price = Entry * (1 + 1/leverage - mmRate/10000)
      return entryPrice * (10000n + 10000n / BigInt(leverage) - mmRate) / 10000n;
    }
  }

  private calculateBankruptcyPrice(
    side: PositionSide,
    entryPrice: bigint,
    leverage: number
  ): bigint {
    if (side === PositionSide.LONG) {
      return entryPrice * (BigInt(leverage) - 1n) / BigInt(leverage);
    } else {
      return entryPrice * (BigInt(leverage) + 1n) / BigInt(leverage);
    }
  }

  private calculatePositionPnL(position: MarginPosition): PnLCalculation {
    const entryValue = (position.quantity * position.entryPrice) / 10n ** 18n;
    const currentValue = (position.quantity * position.markPrice) / 10n ** 18n;

    let unrealizedPnL: bigint;
    if (position.side === PositionSide.LONG) {
      unrealizedPnL = currentValue - entryValue;
    } else {
      unrealizedPnL = entryValue - currentValue;
    }

    const unrealizedPnLPercent = entryValue > 0n
      ? Number((unrealizedPnL * 10000n) / entryValue) / 100
      : 0;

    const margin = position.marginMode === MarginMode.ISOLATED
      ? position.isolatedMargin
      : entryValue / BigInt(position.leverage);

    const roe = margin > 0n
      ? Number((unrealizedPnL * 10000n) / margin) / 100
      : 0;

    return {
      entryValue,
      currentValue,
      unrealizedPnL,
      unrealizedPnLPercent,
      roe,
      fees: 0n, // Simplified
      funding: position.fundingAccrued
    };
  }

  private calculateFundingPayment(position: MarginPosition, rate: number): bigint {
    // Funding = Position Size * Mark Price * Funding Rate
    const fundingAmount = (position.notionalValue * BigInt(Math.abs(rate))) / 10000n;

    // Long pays short when rate is positive
    if (rate > 0) {
      return position.side === PositionSide.LONG ? -fundingAmount : fundingAmount;
    } else {
      return position.side === PositionSide.LONG ? fundingAmount : -fundingAmount;
    }
  }

  private updateAccountMetrics(userId: string): void {
    const account = this.accounts.get(userId);
    if (!account) return;

    let totalUnrealizedPnL = 0n;
    let totalMaintenanceMargin = 0n;
    let totalInitialMargin = 0n;

    for (const position of account.positions.values()) {
      const pnl = this.calculatePositionPnL(position);
      totalUnrealizedPnL += pnl.unrealizedPnL;

      const market = this.markets.get(position.symbol);
      if (market) {
        totalMaintenanceMargin += (position.notionalValue * BigInt(market.maintenanceMarginRate)) / 10000n;
        totalInitialMargin += (position.notionalValue * BigInt(market.initialMarginRate)) / 10000n / BigInt(position.leverage);
      }
    }

    account.unrealizedPnL = totalUnrealizedPnL;
    account.maintenanceMargin = totalMaintenanceMargin;
    account.initialMargin = totalInitialMargin;

    // Calculate margin level
    const equity = account.totalBalance + totalUnrealizedPnL;
    account.marginLevel = totalMaintenanceMargin > 0n
      ? Number((equity * 10000n) / totalMaintenanceMargin) / 100
      : 100;

    account.lastUpdateTime = new Date();
  }

  private checkTPSL(position: MarginPosition): void {
    const markPrice = position.markPrice;

    // Check take profit
    if (position.takeProfitPrice) {
      const tpTriggered = position.side === PositionSide.LONG
        ? markPrice >= position.takeProfitPrice
        : markPrice <= position.takeProfitPrice;

      if (tpTriggered) {
        this.emit('takeProfitTriggered', { positionId: position.positionId });
      }
    }

    // Check stop loss
    if (position.stopLossPrice) {
      const slTriggered = position.side === PositionSide.LONG
        ? markPrice <= position.stopLossPrice
        : markPrice >= position.stopLossPrice;

      if (slTriggered) {
        this.emit('stopLossTriggered', { positionId: position.positionId });
      }
    }
  }

  private checkLiquidation(account: MarginAccount, position: MarginPosition): void {
    const markPrice = position.markPrice;
    const liquidatable = position.side === PositionSide.LONG
      ? markPrice <= position.liquidationPrice
      : markPrice >= position.liquidationPrice;

    if (liquidatable) {
      position.status = PositionStatus.LIQUIDATING;
      this.emit('liquidationTriggered', {
        userId: account.userId,
        positionId: position.positionId,
        markPrice,
        liquidationPrice: position.liquidationPrice
      });
    }

    // Check margin call
    if (account.marginLevel < this.riskParams.marginCallLevel) {
      this.emit('marginCall', { userId: account.userId, marginLevel: account.marginLevel });
    }
  }

  private updateADLQueue(symbol: string): void {
    // Sort positions by profit and leverage for ADL
    const positionsForSymbol: { userId: string; profit: bigint; leverage: number }[] = [];

    for (const account of this.accounts.values()) {
      for (const position of account.positions.values()) {
        if (position.symbol === symbol && position.status === PositionStatus.OPEN) {
          const pnl = this.calculatePositionPnL(position);
          positionsForSymbol.push({
            userId: account.userId,
            profit: pnl.unrealizedPnL,
            leverage: position.leverage
          });
        }
      }
    }

    // Sort by profit (highest first) and leverage (highest first)
    positionsForSymbol.sort((a, b) => {
      const profitDiff = Number(b.profit - a.profit);
      if (profitDiff !== 0) return profitDiff;
      return b.leverage - a.leverage;
    });

    this.adlQueue.set(symbol, positionsForSymbol.map(p => p.userId));
  }

  private startRiskMonitoring(): void {
    // Check account health every second
    setInterval(() => {
      for (const account of this.accounts.values()) {
        if (account.marginLevel < this.riskParams.liquidationLevel) {
          this.emit('accountLiquidation', { userId: account.userId, marginLevel: account.marginLevel });
        }
      }
    }, 1000);
  }

  private startFundingCalculation(): void {
    // Calculate funding every 8 hours (or configured interval)
    setInterval(() => {
      for (const [symbol, fundingRate] of this.fundingRates) {
        if (new Date() >= fundingRate.nextFundingTime) {
          const market = this.markets.get(symbol);
          if (market) {
            // Calculate new funding rate based on mark-index price difference
            const markPrice = this.markPrices.get(symbol) || 0n;
            const indexPrice = this.indexPrices.get(symbol) || markPrice;

            if (indexPrice > 0n) {
              const priceDiff = Number((markPrice - indexPrice) * 10000n / indexPrice);
              const newRate = Math.max(-market.maxFundingRate, Math.min(market.maxFundingRate, priceDiff / 8));

              fundingRate.rate = newRate;
              fundingRate.timestamp = new Date();
              fundingRate.nextFundingTime = new Date(Date.now() + market.fundingInterval * 60 * 60 * 1000);

              this.applyFunding(symbol);
            }
          }
        }
      }
    }, 60000); // Check every minute
  }
}

// Export types
export {
  MarginMode,
  PositionSide,
  OrderType,
  PositionStatus,
  MarginAccount,
  MarginPosition,
  MarginOrder,
  MarketConfig,
  RiskParameters,
  FundingRate,
  PnLCalculation,
  RiskMetrics
};
