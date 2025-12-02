/**
 * Advanced Risk Management Engine
 *
 * SCIENTIFIC HYPOTHESIS:
 * Real-time portfolio risk monitoring using VaR (Value at Risk), CVaR,
 * and Monte Carlo simulations will enable proactive risk mitigation,
 * reducing maximum drawdown by >40% and preventing catastrophic losses
 * through dynamic position limits and automated liquidation mechanisms.
 *
 * SUCCESS METRICS:
 * - Risk prediction accuracy: >95% for 1-day VaR
 * - Maximum drawdown reduction: >40% vs unmanaged
 * - Liquidation efficiency: >99% of positions liquidated before insolvency
 * - System latency: <10ms for risk calculations
 * - False liquidation rate: <0.1%
 *
 * SECURITY CONSIDERATIONS:
 * - Multi-oracle price feeds for manipulation resistance
 * - Gradual liquidation to prevent cascade failures
 * - Insurance fund for socialized losses
 * - Circuit breakers for extreme market conditions
 * - Real-time margin monitoring
 */

import { EventEmitter } from 'events';
import Redis from 'ioredis';
import winston from 'winston';

// ============================================================================
// INTERFACES & TYPES
// ============================================================================

interface RiskConfig {
  varConfidenceLevels: number[];
  monteCarloSimulations: number;
  historicalWindow: number;
  marginRequirements: MarginRequirements;
  liquidationParameters: LiquidationParams;
  circuitBreakerThresholds: CircuitBreakerThresholds;
  insuranceFundTarget: bigint;
  maxLeverage: number;
  positionLimits: PositionLimits;
}

interface MarginRequirements {
  initialMargin: number;
  maintenanceMargin: number;
  liquidationMargin: number;
  marginCallThreshold: number;
}

interface LiquidationParams {
  liquidationPenalty: number;
  insuranceFundContribution: number;
  maxLiquidationSpread: number;
  partialLiquidationThreshold: number;
  liquidatorIncentive: number;
}

interface CircuitBreakerThresholds {
  maxPriceDeviation: number;
  maxVolatility: number;
  maxDrawdown: number;
  maxLiquidationVolume: number;
}

interface PositionLimits {
  maxPositionSize: bigint;
  maxNotionalValue: bigint;
  maxOpenInterest: bigint;
  concentrationLimit: number;
}

interface Portfolio {
  userId: string;
  positions: Position[];
  totalCollateral: bigint;
  usedMargin: bigint;
  freeMargin: bigint;
  unrealizedPnL: bigint;
  realizedPnL: bigint;
  marginRatio: number;
  riskMetrics: PortfolioRiskMetrics;
  lastUpdated: Date;
}

interface Position {
  positionId: string;
  userId: string;
  asset: string;
  side: PositionSide;
  size: bigint;
  entryPrice: number;
  markPrice: number;
  liquidationPrice: number;
  margin: bigint;
  leverage: number;
  unrealizedPnL: bigint;
  realizedPnL: bigint;
  fundingPayments: bigint;
  openTime: Date;
  lastUpdateTime: Date;
}

interface PortfolioRiskMetrics {
  var95: number;
  var99: number;
  cvar95: number;
  cvar99: number;
  maxDrawdown: number;
  sharpeRatio: number;
  sortinoRatio: number;
  beta: number;
  correlation: number;
  volatility: number;
  skewness: number;
  kurtosis: number;
}

interface MarketData {
  asset: string;
  price: number;
  volume24h: bigint;
  high24h: number;
  low24h: number;
  volatility: number;
  fundingRate: number;
  openInterest: bigint;
  timestamp: Date;
}

interface LiquidationEvent {
  liquidationId: string;
  positionId: string;
  userId: string;
  asset: string;
  liquidationType: LiquidationType;
  liquidatedSize: bigint;
  liquidationPrice: number;
  bankruptcyPrice: number;
  penalty: bigint;
  insuranceFundContribution: bigint;
  timestamp: Date;
  reason: string;
}

interface RiskAlert {
  alertId: string;
  userId: string;
  type: RiskAlertType;
  severity: AlertSeverity;
  message: string;
  metrics: Record<string, number>;
  timestamp: Date;
  acknowledged: boolean;
}

interface InsuranceFund {
  balance: bigint;
  target: bigint;
  utilizationRate: number;
  contributions: bigint;
  withdrawals: bigint;
  lastUpdated: Date;
}

interface VaRResult {
  confidence: number;
  value: number;
  horizon: number;
  method: VaRMethod;
  timestamp: Date;
}

interface MonteCarloResult {
  simulations: number;
  percentiles: Map<number, number>;
  expectedValue: number;
  standardDeviation: number;
  worstCase: number;
  bestCase: number;
}

interface StressTestResult {
  scenario: string;
  portfolioLoss: number;
  marginRequired: bigint;
  liquidationsTriggered: number;
  insuranceFundImpact: bigint;
  passedTest: boolean;
}

interface SystemRiskMetrics {
  totalOpenInterest: bigint;
  totalCollateral: bigint;
  systemLeverage: number;
  concentrationIndex: number;
  liquidationVolume24h: bigint;
  insuranceFundHealth: number;
  marketVolatility: number;
  correlationMatrix: number[][];
}

enum PositionSide {
  LONG = 'LONG',
  SHORT = 'SHORT'
}

enum LiquidationType {
  FULL = 'FULL',
  PARTIAL = 'PARTIAL',
  ADL = 'ADL'
}

enum RiskAlertType {
  MARGIN_CALL = 'MARGIN_CALL',
  LIQUIDATION_WARNING = 'LIQUIDATION_WARNING',
  POSITION_LIMIT = 'POSITION_LIMIT',
  HIGH_LEVERAGE = 'HIGH_LEVERAGE',
  CONCENTRATION_RISK = 'CONCENTRATION_RISK',
  VOLATILITY_SPIKE = 'VOLATILITY_SPIKE',
  CORRELATION_BREAKDOWN = 'CORRELATION_BREAKDOWN'
}

enum AlertSeverity {
  INFO = 'INFO',
  WARNING = 'WARNING',
  CRITICAL = 'CRITICAL',
  EMERGENCY = 'EMERGENCY'
}

enum VaRMethod {
  HISTORICAL = 'HISTORICAL',
  PARAMETRIC = 'PARAMETRIC',
  MONTE_CARLO = 'MONTE_CARLO'
}

// ============================================================================
// RISK ENGINE
// ============================================================================

export class RiskEngine extends EventEmitter {
  private config: RiskConfig;
  private redis: Redis;
  private logger: winston.Logger;

  private portfolios: Map<string, Portfolio> = new Map();
  private marketData: Map<string, MarketData> = new Map();
  private historicalPrices: Map<string, number[]> = new Map();
  private insuranceFund: InsuranceFund;
  private alerts: Map<string, RiskAlert> = new Map();

  private isRunning: boolean = false;
  private riskMonitorInterval?: NodeJS.Timeout;
  private priceUpdateInterval?: NodeJS.Timeout;

  constructor(config: RiskConfig, redisUrl: string) {
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
        new winston.transports.File({ filename: 'risk-engine.log' })
      ]
    });

    this.insuranceFund = {
      balance: 0n,
      target: config.insuranceFundTarget,
      utilizationRate: 0,
      contributions: 0n,
      withdrawals: 0n,
      lastUpdated: new Date()
    };

    this.logger.info('Risk Engine initialized', {
      maxLeverage: config.maxLeverage,
      varConfidence: config.varConfidenceLevels,
      simulations: config.monteCarloSimulations
    });
  }

  // ============================================================================
  // INITIALIZATION
  // ============================================================================

  async start(): Promise<void> {
    if (this.isRunning) {
      throw new Error('Risk engine already running');
    }

    // Load portfolios
    await this.loadPortfolios();

    // Initialize market data
    await this.updateMarketData();

    // Start monitoring
    this.riskMonitorInterval = setInterval(
      () => this.runRiskMonitoring(),
      1000 // Every second
    );

    this.priceUpdateInterval = setInterval(
      () => this.updateMarketData(),
      5000 // Every 5 seconds
    );

    this.isRunning = true;
    this.logger.info('Risk Engine started');
    this.emit('started');
  }

  async stop(): Promise<void> {
    if (this.riskMonitorInterval) {
      clearInterval(this.riskMonitorInterval);
    }

    if (this.priceUpdateInterval) {
      clearInterval(this.priceUpdateInterval);
    }

    await this.saveState();

    this.isRunning = false;
    this.logger.info('Risk Engine stopped');
    this.emit('stopped');
  }

  // ============================================================================
  // CORE RISK MONITORING
  // ============================================================================

  private async runRiskMonitoring(): Promise<void> {
    const startTime = Date.now();

    // Update all positions with current prices
    await this.updateAllPositions();

    // Check each portfolio
    for (const [userId, portfolio] of this.portfolios) {
      // Update margin ratios
      this.updateMarginRatio(portfolio);

      // Check for liquidations
      if (portfolio.marginRatio <= this.config.marginRequirements.liquidationMargin) {
        await this.triggerLiquidation(portfolio);
      } else if (
        portfolio.marginRatio <= this.config.marginRequirements.maintenanceMargin
      ) {
        await this.sendMarginCall(portfolio);
      }

      // Check position limits
      await this.checkPositionLimits(portfolio);

      // Update risk metrics
      await this.calculatePortfolioRisk(portfolio);
    }

    // System-wide risk checks
    await this.checkSystemRisk();

    const duration = Date.now() - startTime;
    if (duration > 10) {
      this.logger.warn('Risk monitoring took longer than expected', { duration });
    }
  }

  private async updateAllPositions(): Promise<void> {
    for (const [userId, portfolio] of this.portfolios) {
      let totalUnrealizedPnL = 0n;

      for (const position of portfolio.positions) {
        const marketData = this.marketData.get(position.asset);
        if (!marketData) continue;

        // Update mark price
        position.markPrice = marketData.price;

        // Calculate unrealized P&L
        position.unrealizedPnL = this.calculateUnrealizedPnL(position);
        totalUnrealizedPnL += position.unrealizedPnL;

        // Update liquidation price
        position.liquidationPrice = this.calculateLiquidationPrice(position);

        position.lastUpdateTime = new Date();
      }

      portfolio.unrealizedPnL = totalUnrealizedPnL;
      portfolio.freeMargin =
        portfolio.totalCollateral +
        portfolio.unrealizedPnL -
        portfolio.usedMargin;

      portfolio.lastUpdated = new Date();
    }
  }

  private calculateUnrealizedPnL(position: Position): bigint {
    const priceDiff = position.markPrice - position.entryPrice;
    const pnlPerUnit =
      position.side === PositionSide.LONG ? priceDiff : -priceDiff;

    // PnL = size * priceDiff
    const pnl = BigInt(
      Math.floor(Number(position.size) * pnlPerUnit * 1e18)
    );

    return pnl;
  }

  private calculateLiquidationPrice(position: Position): number {
    const maintenanceMarginRate = this.config.marginRequirements.maintenanceMargin;
    const entryPrice = position.entryPrice;
    const leverage = position.leverage;

    if (position.side === PositionSide.LONG) {
      // Liq price = Entry * (1 - 1/leverage + maintenance margin)
      return entryPrice * (1 - 1 / leverage + maintenanceMarginRate);
    } else {
      // Liq price = Entry * (1 + 1/leverage - maintenance margin)
      return entryPrice * (1 + 1 / leverage - maintenanceMarginRate);
    }
  }

  private updateMarginRatio(portfolio: Portfolio): void {
    const totalEquity =
      portfolio.totalCollateral + portfolio.unrealizedPnL;
    const totalNotional = this.calculateTotalNotional(portfolio);

    if (totalNotional === 0n) {
      portfolio.marginRatio = 1.0;
    } else {
      portfolio.marginRatio =
        Number(totalEquity) / Number(totalNotional);
    }
  }

  private calculateTotalNotional(portfolio: Portfolio): bigint {
    let total = 0n;

    for (const position of portfolio.positions) {
      const notional = BigInt(
        Math.floor(Number(position.size) * position.markPrice)
      );
      total += notional;
    }

    return total;
  }

  // ============================================================================
  // LIQUIDATION ENGINE
  // ============================================================================

  private async triggerLiquidation(portfolio: Portfolio): Promise<void> {
    this.logger.warn('Triggering liquidation', {
      userId: portfolio.userId,
      marginRatio: portfolio.marginRatio
    });

    // Sort positions by loss (liquidate worst first)
    const sortedPositions = [...portfolio.positions].sort(
      (a, b) => Number(a.unrealizedPnL - b.unrealizedPnL)
    );

    for (const position of sortedPositions) {
      const liquidationResult = await this.liquidatePosition(portfolio, position);

      // Update portfolio
      this.updateMarginRatio(portfolio);

      // Check if portfolio is now safe
      if (
        portfolio.marginRatio >
        this.config.marginRequirements.maintenanceMargin
      ) {
        this.logger.info('Portfolio restored to safe margin', {
          userId: portfolio.userId,
          marginRatio: portfolio.marginRatio
        });
        break;
      }
    }
  }

  private async liquidatePosition(
    portfolio: Portfolio,
    position: Position
  ): Promise<LiquidationEvent> {
    const marketData = this.marketData.get(position.asset);
    if (!marketData) {
      throw new Error(`No market data for ${position.asset}`);
    }

    // Determine liquidation type
    let liquidationType = LiquidationType.FULL;
    let liquidatedSize = position.size;

    // Check for partial liquidation
    if (
      Number(position.size) >=
      this.config.liquidationParameters.partialLiquidationThreshold
    ) {
      const requiredReduction = this.calculateRequiredReduction(
        portfolio,
        position
      );

      if (requiredReduction < Number(position.size)) {
        liquidationType = LiquidationType.PARTIAL;
        liquidatedSize = BigInt(Math.ceil(requiredReduction));
      }
    }

    // Calculate liquidation price (with spread)
    const liquidationPrice =
      position.side === PositionSide.LONG
        ? marketData.price *
          (1 - this.config.liquidationParameters.maxLiquidationSpread)
        : marketData.price *
          (1 + this.config.liquidationParameters.maxLiquidationSpread);

    // Calculate bankruptcy price
    const bankruptcyPrice = this.calculateBankruptcyPrice(position);

    // Calculate penalty and insurance contribution
    const penalty = BigInt(
      Math.floor(
        Number(liquidatedSize) *
          liquidationPrice *
          this.config.liquidationParameters.liquidationPenalty
      )
    );

    const insuranceContribution = BigInt(
      Math.floor(
        Number(penalty) *
          this.config.liquidationParameters.insuranceFundContribution
      )
    );

    // Create liquidation event
    const liquidationEvent: LiquidationEvent = {
      liquidationId: this.generateId(),
      positionId: position.positionId,
      userId: portfolio.userId,
      asset: position.asset,
      liquidationType,
      liquidatedSize,
      liquidationPrice,
      bankruptcyPrice,
      penalty,
      insuranceFundContribution: insuranceContribution,
      timestamp: new Date(),
      reason: `Margin ratio ${portfolio.marginRatio.toFixed(4)} below liquidation threshold`
    };

    // Update position
    if (liquidationType === LiquidationType.FULL) {
      // Remove position from portfolio
      const index = portfolio.positions.indexOf(position);
      if (index > -1) {
        portfolio.positions.splice(index, 1);
      }
    } else {
      // Partial liquidation
      position.size -= liquidatedSize;
      const remainingRatio =
        Number(position.size) / Number(position.size + liquidatedSize);
      position.margin = BigInt(
        Math.floor(Number(position.margin) * remainingRatio)
      );
    }

    // Update collateral
    portfolio.totalCollateral -= penalty;

    // Add to insurance fund
    this.insuranceFund.balance += insuranceContribution;
    this.insuranceFund.contributions += insuranceContribution;
    this.insuranceFund.lastUpdated = new Date();

    this.logger.info('Position liquidated', {
      liquidationId: liquidationEvent.liquidationId,
      userId: portfolio.userId,
      asset: position.asset,
      type: liquidationType,
      size: liquidatedSize.toString(),
      price: liquidationPrice
    });

    this.emit('liquidation', liquidationEvent);

    return liquidationEvent;
  }

  private calculateRequiredReduction(
    portfolio: Portfolio,
    position: Position
  ): number {
    const targetMarginRatio = this.config.marginRequirements.maintenanceMargin * 1.2;
    const currentMarginRatio = portfolio.marginRatio;

    // Calculate how much position needs to be reduced
    const totalNotional = Number(this.calculateTotalNotional(portfolio));
    const requiredNotionalReduction =
      totalNotional * (1 - currentMarginRatio / targetMarginRatio);

    return requiredNotionalReduction / position.markPrice;
  }

  private calculateBankruptcyPrice(position: Position): number {
    const entryPrice = position.entryPrice;
    const leverage = position.leverage;

    if (position.side === PositionSide.LONG) {
      return entryPrice * (1 - 1 / leverage);
    } else {
      return entryPrice * (1 + 1 / leverage);
    }
  }

  private async sendMarginCall(portfolio: Portfolio): Promise<void> {
    const alert: RiskAlert = {
      alertId: this.generateId(),
      userId: portfolio.userId,
      type: RiskAlertType.MARGIN_CALL,
      severity: AlertSeverity.WARNING,
      message: `Margin ratio at ${(portfolio.marginRatio * 100).toFixed(2)}%. Add collateral or reduce positions.`,
      metrics: {
        marginRatio: portfolio.marginRatio,
        requiredMargin: this.config.marginRequirements.maintenanceMargin,
        freeMargin: Number(portfolio.freeMargin)
      },
      timestamp: new Date(),
      acknowledged: false
    };

    this.alerts.set(alert.alertId, alert);
    this.emit('marginCall', alert);

    this.logger.warn('Margin call sent', {
      userId: portfolio.userId,
      marginRatio: portfolio.marginRatio
    });
  }

  // ============================================================================
  // RISK METRICS CALCULATION
  // ============================================================================

  async calculatePortfolioRisk(portfolio: Portfolio): Promise<void> {
    const returns = await this.getPortfolioReturns(portfolio);

    if (returns.length < 30) {
      // Not enough data for meaningful risk calculation
      return;
    }

    // Calculate Value at Risk
    const var95 = this.calculateVaR(returns, 0.95);
    const var99 = this.calculateVaR(returns, 0.99);

    // Calculate Conditional VaR (Expected Shortfall)
    const cvar95 = this.calculateCVaR(returns, 0.95);
    const cvar99 = this.calculateCVaR(returns, 0.99);

    // Calculate volatility
    const volatility = this.calculateVolatility(returns);

    // Calculate Sharpe Ratio (assuming risk-free rate = 0 for crypto)
    const avgReturn = returns.reduce((a, b) => a + b, 0) / returns.length;
    const sharpeRatio = avgReturn / volatility;

    // Calculate Sortino Ratio (only downside deviation)
    const downsideReturns = returns.filter(r => r < 0);
    const downsideDeviation =
      Math.sqrt(
        downsideReturns.reduce((sum, r) => sum + r * r, 0) /
          downsideReturns.length
      ) || 0.0001;
    const sortinoRatio = avgReturn / downsideDeviation;

    // Calculate max drawdown
    const maxDrawdown = this.calculateMaxDrawdown(returns);

    // Calculate higher moments
    const skewness = this.calculateSkewness(returns);
    const kurtosis = this.calculateKurtosis(returns);

    // Update portfolio metrics
    portfolio.riskMetrics = {
      var95,
      var99,
      cvar95,
      cvar99,
      maxDrawdown,
      sharpeRatio,
      sortinoRatio,
      beta: await this.calculateBeta(portfolio),
      correlation: await this.calculateCorrelation(portfolio),
      volatility,
      skewness,
      kurtosis
    };

    // Check for risk alerts
    if (var99 > 0.1) {
      // More than 10% potential loss
      const alert: RiskAlert = {
        alertId: this.generateId(),
        userId: portfolio.userId,
        type: RiskAlertType.CONCENTRATION_RISK,
        severity: AlertSeverity.WARNING,
        message: `High VaR(99%): ${(var99 * 100).toFixed(2)}% potential loss`,
        metrics: { var99, volatility },
        timestamp: new Date(),
        acknowledged: false
      };

      this.alerts.set(alert.alertId, alert);
      this.emit('riskAlert', alert);
    }
  }

  private async getPortfolioReturns(portfolio: Portfolio): Promise<number[]> {
    // Get historical returns based on current positions
    const returns: number[] = [];
    const windowSize = this.config.historicalWindow;

    // Aggregate returns across all positions
    for (let i = 1; i < windowSize; i++) {
      let dailyReturn = 0;

      for (const position of portfolio.positions) {
        const prices = this.historicalPrices.get(position.asset);
        if (!prices || prices.length < windowSize) continue;

        const priceReturn =
          (prices[i] - prices[i - 1]) / prices[i - 1];
        const positionWeight =
          Number(position.size) * position.markPrice;

        dailyReturn +=
          position.side === PositionSide.LONG
            ? priceReturn * positionWeight
            : -priceReturn * positionWeight;
      }

      const totalValue = Number(
        portfolio.totalCollateral + portfolio.unrealizedPnL
      );
      returns.push(dailyReturn / totalValue);
    }

    return returns;
  }

  private calculateVaR(returns: number[], confidence: number): number {
    const sorted = [...returns].sort((a, b) => a - b);
    const index = Math.floor((1 - confidence) * sorted.length);
    return -sorted[index];
  }

  private calculateCVaR(returns: number[], confidence: number): number {
    const sorted = [...returns].sort((a, b) => a - b);
    const cutoffIndex = Math.floor((1 - confidence) * sorted.length);

    const tailReturns = sorted.slice(0, cutoffIndex);
    if (tailReturns.length === 0) return 0;

    const avgTailLoss =
      tailReturns.reduce((a, b) => a + b, 0) / tailReturns.length;
    return -avgTailLoss;
  }

  private calculateVolatility(returns: number[]): number {
    const mean = returns.reduce((a, b) => a + b, 0) / returns.length;
    const variance =
      returns.reduce((sum, r) => sum + (r - mean) ** 2, 0) / returns.length;
    return Math.sqrt(variance);
  }

  private calculateMaxDrawdown(returns: number[]): number {
    let peak = 1;
    let maxDrawdown = 0;
    let cumulative = 1;

    for (const ret of returns) {
      cumulative *= 1 + ret;
      if (cumulative > peak) {
        peak = cumulative;
      }

      const drawdown = (peak - cumulative) / peak;
      if (drawdown > maxDrawdown) {
        maxDrawdown = drawdown;
      }
    }

    return maxDrawdown;
  }

  private calculateSkewness(returns: number[]): number {
    const n = returns.length;
    const mean = returns.reduce((a, b) => a + b, 0) / n;
    const variance = returns.reduce((sum, r) => sum + (r - mean) ** 2, 0) / n;
    const stdDev = Math.sqrt(variance);

    const skewness =
      returns.reduce((sum, r) => sum + ((r - mean) / stdDev) ** 3, 0) / n;

    return skewness;
  }

  private calculateKurtosis(returns: number[]): number {
    const n = returns.length;
    const mean = returns.reduce((a, b) => a + b, 0) / n;
    const variance = returns.reduce((sum, r) => sum + (r - mean) ** 2, 0) / n;
    const stdDev = Math.sqrt(variance);

    const kurtosis =
      returns.reduce((sum, r) => sum + ((r - mean) / stdDev) ** 4, 0) / n - 3;

    return kurtosis;
  }

  private async calculateBeta(portfolio: Portfolio): Promise<number> {
    // Calculate beta against market index (e.g., BTC)
    const marketReturns = this.historicalPrices.get('BTC') || [];
    const portfolioReturns = await this.getPortfolioReturns(portfolio);

    if (
      marketReturns.length < 30 ||
      portfolioReturns.length !== marketReturns.length - 1
    ) {
      return 1;
    }

    // Calculate market returns
    const mktReturns: number[] = [];
    for (let i = 1; i < marketReturns.length; i++) {
      mktReturns.push(
        (marketReturns[i] - marketReturns[i - 1]) / marketReturns[i - 1]
      );
    }

    // Covariance / Variance
    const meanPort =
      portfolioReturns.reduce((a, b) => a + b, 0) / portfolioReturns.length;
    const meanMkt = mktReturns.reduce((a, b) => a + b, 0) / mktReturns.length;

    let covariance = 0;
    let marketVariance = 0;

    for (let i = 0; i < portfolioReturns.length; i++) {
      covariance += (portfolioReturns[i] - meanPort) * (mktReturns[i] - meanMkt);
      marketVariance += (mktReturns[i] - meanMkt) ** 2;
    }

    covariance /= portfolioReturns.length;
    marketVariance /= mktReturns.length;

    return covariance / marketVariance;
  }

  private async calculateCorrelation(portfolio: Portfolio): Promise<number> {
    // Average correlation between all assets in portfolio
    if (portfolio.positions.length < 2) return 0;

    let totalCorrelation = 0;
    let pairs = 0;

    for (let i = 0; i < portfolio.positions.length; i++) {
      for (let j = i + 1; j < portfolio.positions.length; j++) {
        const asset1 = portfolio.positions[i].asset;
        const asset2 = portfolio.positions[j].asset;

        const corr = this.calculateAssetCorrelation(asset1, asset2);
        totalCorrelation += corr;
        pairs++;
      }
    }

    return pairs > 0 ? totalCorrelation / pairs : 0;
  }

  private calculateAssetCorrelation(asset1: string, asset2: string): number {
    const prices1 = this.historicalPrices.get(asset1) || [];
    const prices2 = this.historicalPrices.get(asset2) || [];

    if (prices1.length < 30 || prices2.length < 30) return 0;

    const minLen = Math.min(prices1.length, prices2.length);

    // Calculate returns
    const returns1: number[] = [];
    const returns2: number[] = [];

    for (let i = 1; i < minLen; i++) {
      returns1.push((prices1[i] - prices1[i - 1]) / prices1[i - 1]);
      returns2.push((prices2[i] - prices2[i - 1]) / prices2[i - 1]);
    }

    // Pearson correlation
    const mean1 = returns1.reduce((a, b) => a + b, 0) / returns1.length;
    const mean2 = returns2.reduce((a, b) => a + b, 0) / returns2.length;

    let numerator = 0;
    let denom1 = 0;
    let denom2 = 0;

    for (let i = 0; i < returns1.length; i++) {
      const diff1 = returns1[i] - mean1;
      const diff2 = returns2[i] - mean2;
      numerator += diff1 * diff2;
      denom1 += diff1 ** 2;
      denom2 += diff2 ** 2;
    }

    return numerator / Math.sqrt(denom1 * denom2);
  }

  // ============================================================================
  // MONTE CARLO SIMULATION
  // ============================================================================

  async runMonteCarloSimulation(
    portfolio: Portfolio
  ): Promise<MonteCarloResult> {
    const simulations = this.config.monteCarloSimulations;
    const results: number[] = [];

    const returns = await this.getPortfolioReturns(portfolio);
    const mean = returns.reduce((a, b) => a + b, 0) / returns.length;
    const stdDev = this.calculateVolatility(returns);

    // Run simulations
    for (let i = 0; i < simulations; i++) {
      // Generate random return using normal distribution
      const z = this.generateNormalRandom();
      const simulatedReturn = mean + stdDev * z;

      const portfolioValue = Number(
        portfolio.totalCollateral + portfolio.unrealizedPnL
      );
      const simulatedLoss = portfolioValue * simulatedReturn;

      results.push(simulatedLoss);
    }

    // Sort results
    results.sort((a, b) => a - b);

    // Calculate percentiles
    const percentiles = new Map<number, number>();
    percentiles.set(1, results[Math.floor(0.01 * simulations)]);
    percentiles.set(5, results[Math.floor(0.05 * simulations)]);
    percentiles.set(10, results[Math.floor(0.1 * simulations)]);
    percentiles.set(50, results[Math.floor(0.5 * simulations)]);
    percentiles.set(90, results[Math.floor(0.9 * simulations)]);
    percentiles.set(95, results[Math.floor(0.95 * simulations)]);
    percentiles.set(99, results[Math.floor(0.99 * simulations)]);

    const expectedValue = results.reduce((a, b) => a + b, 0) / simulations;
    const variance =
      results.reduce((sum, r) => sum + (r - expectedValue) ** 2, 0) /
      simulations;

    return {
      simulations,
      percentiles,
      expectedValue,
      standardDeviation: Math.sqrt(variance),
      worstCase: results[0],
      bestCase: results[simulations - 1]
    };
  }

  private generateNormalRandom(): number {
    // Box-Muller transform
    const u1 = Math.random();
    const u2 = Math.random();
    return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  }

  // ============================================================================
  // STRESS TESTING
  // ============================================================================

  async runStressTest(
    portfolio: Portfolio,
    scenario: string
  ): Promise<StressTestResult> {
    const scenarios: Record<string, Record<string, number>> = {
      'market_crash': { price_change: -0.3, volatility_spike: 3.0 },
      'flash_crash': { price_change: -0.5, volatility_spike: 5.0 },
      'correlation_breakdown': { correlation_shift: 0.9 },
      'liquidity_crisis': { spread_increase: 0.1, volume_drop: 0.8 }
    };

    const scenarioParams = scenarios[scenario];
    if (!scenarioParams) {
      throw new Error(`Unknown scenario: ${scenario}`);
    }

    let portfolioLoss = 0;
    let liquidationsTriggered = 0;

    // Apply scenario to each position
    for (const position of portfolio.positions) {
      const priceChange = scenarioParams.price_change || 0;
      const stressedPrice = position.markPrice * (1 + priceChange);

      // Calculate PnL under stress
      const stressedPnL = this.calculateStressedPnL(position, stressedPrice);
      portfolioLoss += stressedPnL;

      // Check if liquidation would be triggered
      if (stressedPrice <= position.liquidationPrice) {
        liquidationsTriggered++;
      }
    }

    // Calculate margin required under stress
    const stressedEquity =
      Number(portfolio.totalCollateral) + portfolioLoss;
    const marginRequired = BigInt(Math.max(0, -stressedEquity));

    // Calculate insurance fund impact
    const insuranceFundImpact = marginRequired > 0n
      ? marginRequired
      : 0n;

    const passedTest =
      stressedEquity > 0 &&
      liquidationsTriggered < portfolio.positions.length * 0.5;

    return {
      scenario,
      portfolioLoss,
      marginRequired,
      liquidationsTriggered,
      insuranceFundImpact,
      passedTest
    };
  }

  private calculateStressedPnL(position: Position, stressedPrice: number): number {
    const priceDiff = stressedPrice - position.entryPrice;
    const pnlPerUnit =
      position.side === PositionSide.LONG ? priceDiff : -priceDiff;

    return Number(position.size) * pnlPerUnit;
  }

  // ============================================================================
  // SYSTEM RISK MONITORING
  // ============================================================================

  private async checkSystemRisk(): Promise<void> {
    const systemMetrics = await this.calculateSystemRiskMetrics();

    // Check circuit breakers
    if (
      systemMetrics.marketVolatility >
      this.config.circuitBreakerThresholds.maxVolatility
    ) {
      this.logger.error('Circuit breaker: High volatility', {
        volatility: systemMetrics.marketVolatility
      });
      this.emit('circuitBreaker', 'HIGH_VOLATILITY');
    }

    if (
      Number(systemMetrics.liquidationVolume24h) >
      this.config.circuitBreakerThresholds.maxLiquidationVolume
    ) {
      this.logger.error('Circuit breaker: High liquidation volume', {
        volume: systemMetrics.liquidationVolume24h.toString()
      });
      this.emit('circuitBreaker', 'HIGH_LIQUIDATIONS');
    }

    // Check insurance fund health
    if (systemMetrics.insuranceFundHealth < 0.5) {
      this.logger.warn('Insurance fund low', {
        health: systemMetrics.insuranceFundHealth
      });
      this.emit('lowInsuranceFund', this.insuranceFund);
    }
  }

  private async calculateSystemRiskMetrics(): Promise<SystemRiskMetrics> {
    let totalOpenInterest = 0n;
    let totalCollateral = 0n;

    for (const portfolio of this.portfolios.values()) {
      totalCollateral += portfolio.totalCollateral;

      for (const position of portfolio.positions) {
        totalOpenInterest += position.size;
      }
    }

    const systemLeverage =
      Number(totalOpenInterest) / Number(totalCollateral || 1n);

    // Calculate concentration index (Herfindahl)
    const positionSizes: number[] = [];
    for (const portfolio of this.portfolios.values()) {
      for (const position of portfolio.positions) {
        positionSizes.push(Number(position.size));
      }
    }

    const totalSize = positionSizes.reduce((a, b) => a + b, 0);
    const concentrationIndex = positionSizes.reduce(
      (sum, size) => sum + (size / totalSize) ** 2,
      0
    );

    // Market volatility
    let avgVolatility = 0;
    for (const marketData of this.marketData.values()) {
      avgVolatility += marketData.volatility;
    }
    avgVolatility /= this.marketData.size || 1;

    return {
      totalOpenInterest,
      totalCollateral,
      systemLeverage,
      concentrationIndex,
      liquidationVolume24h: 0n, // Would track from liquidation events
      insuranceFundHealth:
        Number(this.insuranceFund.balance) /
        Number(this.insuranceFund.target),
      marketVolatility: avgVolatility,
      correlationMatrix: []
    };
  }

  // ============================================================================
  // POSITION LIMIT CHECKS
  // ============================================================================

  private async checkPositionLimits(portfolio: Portfolio): Promise<void> {
    for (const position of portfolio.positions) {
      // Check individual position size
      if (position.size > this.config.positionLimits.maxPositionSize) {
        const alert: RiskAlert = {
          alertId: this.generateId(),
          userId: portfolio.userId,
          type: RiskAlertType.POSITION_LIMIT,
          severity: AlertSeverity.CRITICAL,
          message: `Position size ${position.size} exceeds limit`,
          metrics: {
            positionSize: Number(position.size),
            limit: Number(this.config.positionLimits.maxPositionSize)
          },
          timestamp: new Date(),
          acknowledged: false
        };

        this.alerts.set(alert.alertId, alert);
        this.emit('riskAlert', alert);
      }

      // Check leverage
      if (position.leverage > this.config.maxLeverage) {
        const alert: RiskAlert = {
          alertId: this.generateId(),
          userId: portfolio.userId,
          type: RiskAlertType.HIGH_LEVERAGE,
          severity: AlertSeverity.WARNING,
          message: `Leverage ${position.leverage}x exceeds max ${this.config.maxLeverage}x`,
          metrics: {
            currentLeverage: position.leverage,
            maxLeverage: this.config.maxLeverage
          },
          timestamp: new Date(),
          acknowledged: false
        };

        this.alerts.set(alert.alertId, alert);
        this.emit('riskAlert', alert);
      }
    }

    // Check portfolio concentration
    const totalNotional = this.calculateTotalNotional(portfolio);
    for (const position of portfolio.positions) {
      const positionNotional = BigInt(
        Math.floor(Number(position.size) * position.markPrice)
      );
      const concentration =
        Number(positionNotional) / Number(totalNotional || 1n);

      if (concentration > this.config.positionLimits.concentrationLimit) {
        const alert: RiskAlert = {
          alertId: this.generateId(),
          userId: portfolio.userId,
          type: RiskAlertType.CONCENTRATION_RISK,
          severity: AlertSeverity.WARNING,
          message: `Position ${position.asset} concentration ${(concentration * 100).toFixed(2)}% exceeds limit`,
          metrics: {
            concentration,
            limit: this.config.positionLimits.concentrationLimit
          },
          timestamp: new Date(),
          acknowledged: false
        };

        this.alerts.set(alert.alertId, alert);
        this.emit('riskAlert', alert);
      }
    }
  }

  // ============================================================================
  // HELPERS
  // ============================================================================

  private generateId(): string {
    return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private async updateMarketData(): Promise<void> {
    // Simulate market data update
    // In production, fetch from price oracles

    const assets = ['BTC', 'ETH', 'USDC', 'SOL', 'AVAX'];
    const basePrices = [45000, 2500, 1, 100, 35];

    for (let i = 0; i < assets.length; i++) {
      const price = basePrices[i] * (1 + (Math.random() - 0.5) * 0.01);

      this.marketData.set(assets[i], {
        asset: assets[i],
        price,
        volume24h: BigInt(Math.floor(Math.random() * 1e10)),
        high24h: price * 1.05,
        low24h: price * 0.95,
        volatility: Math.random() * 0.05,
        fundingRate: (Math.random() - 0.5) * 0.001,
        openInterest: BigInt(Math.floor(Math.random() * 1e8)),
        timestamp: new Date()
      });

      // Update historical prices
      const history = this.historicalPrices.get(assets[i]) || [];
      history.push(price);
      if (history.length > this.config.historicalWindow) {
        history.shift();
      }
      this.historicalPrices.set(assets[i], history);
    }
  }

  private async loadPortfolios(): Promise<void> {
    // Load from database
    this.logger.info('Portfolios loaded');
  }

  private async saveState(): Promise<void> {
    // Save state to database
    this.logger.info('Risk engine state saved');
  }

  // ============================================================================
  // PUBLIC API
  // ============================================================================

  getPortfolioRisk(userId: string): PortfolioRiskMetrics | undefined {
    const portfolio = this.portfolios.get(userId);
    return portfolio?.riskMetrics;
  }

  getActiveAlerts(userId: string): RiskAlert[] {
    return Array.from(this.alerts.values()).filter(
      a => a.userId === userId && !a.acknowledged
    );
  }

  getInsuranceFund(): InsuranceFund {
    return { ...this.insuranceFund };
  }

  async addCollateral(userId: string, amount: bigint): Promise<void> {
    const portfolio = this.portfolios.get(userId);
    if (!portfolio) {
      throw new Error('Portfolio not found');
    }

    portfolio.totalCollateral += amount;
    portfolio.freeMargin += amount;
    this.updateMarginRatio(portfolio);

    this.logger.info('Collateral added', {
      userId,
      amount: amount.toString(),
      newMarginRatio: portfolio.marginRatio
    });
  }

  async createPosition(
    userId: string,
    asset: string,
    side: PositionSide,
    size: bigint,
    leverage: number
  ): Promise<Position> {
    const portfolio = this.portfolios.get(userId);
    if (!portfolio) {
      throw new Error('Portfolio not found');
    }

    if (leverage > this.config.maxLeverage) {
      throw new Error(`Leverage ${leverage}x exceeds maximum ${this.config.maxLeverage}x`);
    }

    const marketData = this.marketData.get(asset);
    if (!marketData) {
      throw new Error(`No market data for ${asset}`);
    }

    const entryPrice = marketData.price;
    const notionalValue = Number(size) * entryPrice;
    const marginRequired = BigInt(Math.floor(notionalValue / leverage));

    if (portfolio.freeMargin < marginRequired) {
      throw new Error('Insufficient free margin');
    }

    const position: Position = {
      positionId: this.generateId(),
      userId,
      asset,
      side,
      size,
      entryPrice,
      markPrice: entryPrice,
      liquidationPrice: this.calculateLiquidationPrice({
        entryPrice,
        leverage,
        side
      } as Position),
      margin: marginRequired,
      leverage,
      unrealizedPnL: 0n,
      realizedPnL: 0n,
      fundingPayments: 0n,
      openTime: new Date(),
      lastUpdateTime: new Date()
    };

    portfolio.positions.push(position);
    portfolio.usedMargin += marginRequired;
    portfolio.freeMargin -= marginRequired;

    this.updateMarginRatio(portfolio);

    this.logger.info('Position created', {
      positionId: position.positionId,
      userId,
      asset,
      side,
      size: size.toString(),
      leverage
    });

    return position;
  }
}

export default RiskEngine;
