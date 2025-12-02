import { EventEmitter } from 'events';
import * as crypto from 'crypto';

/**
 * COMPREHENSIVE RISK ENGINE
 *
 * HYPOTHESIS: A sophisticated risk management engine with VaR calculations,
 * stress testing, and real-time exposure monitoring will prevent systemic
 * risk events with >99.9% accuracy.
 *
 * SUCCESS METRICS:
 * - Risk prediction accuracy: >99.9%
 * - False alarm rate: <0.1%
 * - Stress test coverage: 100% of tail scenarios
 * - Response time: <1ms for risk calculations
 * - Capital efficiency: >90% utilization with safety
 *
 * SECURITY CONSIDERATIONS:
 * - Multi-factor risk assessment
 * - Correlation risk modeling
 * - Black swan event protection
 * - Counterparty risk management
 * - Liquidity risk monitoring
 */

// Risk category
enum RiskCategory {
  MARKET = 'market',
  LIQUIDITY = 'liquidity',
  CREDIT = 'credit',
  OPERATIONAL = 'operational',
  CONCENTRATION = 'concentration',
  SYSTEMIC = 'systemic'
}

// Risk level
enum RiskLevel {
  MINIMAL = 'minimal',
  LOW = 'low',
  MODERATE = 'moderate',
  HIGH = 'high',
  CRITICAL = 'critical'
}

// VaR method
enum VaRMethod {
  HISTORICAL = 'historical',
  PARAMETRIC = 'parametric',
  MONTE_CARLO = 'monte_carlo'
}

// Position for risk
interface RiskPosition {
  positionId: string;
  userId: string;
  asset: string;
  size: bigint;
  notionalValue: bigint;
  leverage: number;
  unrealizedPnL: bigint;
  volatility: number;
  liquidityScore: number;
}

// Portfolio risk
interface PortfolioRisk {
  userId: string;
  totalNotional: bigint;
  totalUnrealizedPnL: bigint;
  varDaily: bigint;
  varWeekly: bigint;
  expectedShortfall: bigint;
  maxDrawdown: bigint;
  sharpeRatio: number;
  correlationRisk: number;
  concentrationRisk: number;
  liquidityRisk: number;
  overallRiskLevel: RiskLevel;
  lastUpdated: Date;
}

// Market risk metrics
interface MarketRiskMetrics {
  asset: string;
  currentPrice: bigint;
  volatility24h: number;
  volatility7d: number;
  volatility30d: number;
  maxDrawdown: number;
  liquidityDepth: bigint;
  bidAskSpread: number;
  correlationMatrix: Map<string, number>;
  riskScore: number;
}

// Stress test scenario
interface StressScenario {
  id: string;
  name: string;
  description: string;
  priceShocks: Map<string, number>; // asset -> percentage change
  volatilityMultiplier: number;
  liquidityReduction: number;
  correlationShock: number;
}

// Stress test result
interface StressTestResult {
  scenarioId: string;
  portfolioLoss: bigint;
  lossPercentage: number;
  positionsAtRisk: string[];
  liquidationsTriggered: number;
  insuranceFundImpact: bigint;
  systemSolvency: boolean;
}

// Risk alert
interface RiskAlert {
  id: string;
  category: RiskCategory;
  level: RiskLevel;
  message: string;
  affectedEntities: string[];
  metrics: any;
  timestamp: Date;
  resolved: boolean;
}

// Risk limits
interface RiskLimits {
  maxVaRPerUser: bigint;
  maxConcentrationPerAsset: number; // percentage
  maxLeverageSystem: number;
  maxCorrelationExposure: number;
  maxLiquidityRisk: number;
  minLiquidityScore: number;
}

// Historical return
interface HistoricalReturn {
  asset: string;
  returns: number[];
  timestamps: Date[];
}

// Monte Carlo path
interface MCPath {
  asset: string;
  pricePath: bigint[];
  finalPrice: bigint;
}

export class RiskEngine extends EventEmitter {
  private positions: Map<string, RiskPosition[]> = new Map(); // userId -> positions
  private portfolioRisks: Map<string, PortfolioRisk> = new Map();
  private marketRisks: Map<string, MarketRiskMetrics> = new Map();
  private historicalReturns: Map<string, HistoricalReturn> = new Map();
  private stressScenarios: Map<string, StressScenario> = new Map();
  private alerts: Map<string, RiskAlert> = new Map();
  private riskLimits: RiskLimits;

  // Configuration
  private varConfidenceLevel: number = 0.99; // 99% confidence
  private varHorizon: number = 1; // 1 day
  private monteCarloSimulations: number = 10000;
  private historicalWindowDays: number = 252; // 1 trading year

  constructor() {
    super();
    this.riskLimits = this.initializeRiskLimits();
    this.initializeStressScenarios();
    this.startRiskMonitoring();
  }

  private initializeRiskLimits(): RiskLimits {
    return {
      maxVaRPerUser: 1000000n * 10n ** 18n, // $1M
      maxConcentrationPerAsset: 30, // 30%
      maxLeverageSystem: 50,
      maxCorrelationExposure: 0.8,
      maxLiquidityRisk: 70, // score out of 100
      minLiquidityScore: 30
    };
  }

  private initializeStressScenarios(): void {
    // Market crash scenario
    const crashScenario: StressScenario = {
      id: 'crash_2020',
      name: 'Market Crash',
      description: 'March 2020 style crash',
      priceShocks: new Map([
        ['BTC', -40],
        ['ETH', -50],
        ['default', -30]
      ]),
      volatilityMultiplier: 3.0,
      liquidityReduction: 0.7,
      correlationShock: 0.95
    };

    // Flash crash scenario
    const flashCrash: StressScenario = {
      id: 'flash_crash',
      name: 'Flash Crash',
      description: 'Rapid market dislocation',
      priceShocks: new Map([
        ['BTC', -25],
        ['ETH', -35],
        ['default', -20]
      ]),
      volatilityMultiplier: 5.0,
      liquidityReduction: 0.9,
      correlationShock: 0.99
    };

    // Liquidity crisis
    const liquidityCrisis: StressScenario = {
      id: 'liquidity_crisis',
      name: 'Liquidity Crisis',
      description: 'Severe liquidity crunch',
      priceShocks: new Map([
        ['BTC', -15],
        ['ETH', -20],
        ['default', -10]
      ]),
      volatilityMultiplier: 2.0,
      liquidityReduction: 0.95,
      correlationShock: 0.85
    };

    this.stressScenarios.set(crashScenario.id, crashScenario);
    this.stressScenarios.set(flashCrash.id, flashCrash);
    this.stressScenarios.set(liquidityCrisis.id, liquidityCrisis);
  }

  /**
   * Add position for risk monitoring
   */
  addPosition(position: RiskPosition): void {
    if (!this.positions.has(position.userId)) {
      this.positions.set(position.userId, []);
    }
    this.positions.get(position.userId)!.push(position);

    this.updatePortfolioRisk(position.userId);
    this.emit('positionAdded', position);
  }

  /**
   * Update position
   */
  updatePosition(positionId: string, updates: Partial<RiskPosition>): void {
    for (const [userId, positions] of this.positions) {
      const pos = positions.find(p => p.positionId === positionId);
      if (pos) {
        Object.assign(pos, updates);
        this.updatePortfolioRisk(userId);
        break;
      }
    }
  }

  /**
   * Remove position
   */
  removePosition(positionId: string): void {
    for (const [userId, positions] of this.positions) {
      const index = positions.findIndex(p => p.positionId === positionId);
      if (index !== -1) {
        positions.splice(index, 1);
        this.updatePortfolioRisk(userId);
        break;
      }
    }
  }

  /**
   * Update market risk data
   */
  updateMarketRisk(metrics: MarketRiskMetrics): void {
    this.marketRisks.set(metrics.asset, metrics);
    this.emit('marketRiskUpdated', metrics);

    // Check for market risk alerts
    if (metrics.volatility24h > 50) {
      this.createAlert(
        RiskCategory.MARKET,
        RiskLevel.HIGH,
        `High volatility detected for ${metrics.asset}: ${metrics.volatility24h}%`,
        [metrics.asset],
        metrics
      );
    }
  }

  /**
   * Add historical returns for VaR calculation
   */
  addHistoricalReturns(asset: string, returns: number[], timestamps: Date[]): void {
    this.historicalReturns.set(asset, { asset, returns, timestamps });
  }

  /**
   * Calculate Value at Risk (VaR)
   */
  calculateVaR(
    userId: string,
    method: VaRMethod = VaRMethod.HISTORICAL,
    confidenceLevel: number = this.varConfidenceLevel,
    horizon: number = this.varHorizon
  ): bigint {
    const positions = this.positions.get(userId);
    if (!positions || positions.length === 0) return 0n;

    switch (method) {
      case VaRMethod.HISTORICAL:
        return this.calculateHistoricalVaR(positions, confidenceLevel, horizon);
      case VaRMethod.PARAMETRIC:
        return this.calculateParametricVaR(positions, confidenceLevel, horizon);
      case VaRMethod.MONTE_CARLO:
        return this.calculateMonteCarloVaR(positions, confidenceLevel, horizon);
      default:
        return this.calculateHistoricalVaR(positions, confidenceLevel, horizon);
    }
  }

  /**
   * Calculate Expected Shortfall (CVaR)
   */
  calculateExpectedShortfall(
    userId: string,
    confidenceLevel: number = this.varConfidenceLevel
  ): bigint {
    const positions = this.positions.get(userId);
    if (!positions || positions.length === 0) return 0n;

    // Get historical portfolio returns
    const portfolioReturns = this.getPortfolioReturns(positions);
    if (portfolioReturns.length === 0) return 0n;

    // Sort returns
    const sortedReturns = [...portfolioReturns].sort((a, b) => a - b);

    // Find VaR cutoff
    const cutoffIndex = Math.floor(sortedReturns.length * (1 - confidenceLevel));

    // Calculate average of returns worse than VaR
    let sumTailReturns = 0;
    for (let i = 0; i < cutoffIndex; i++) {
      sumTailReturns += sortedReturns[i];
    }

    const avgTailReturn = cutoffIndex > 0 ? sumTailReturns / cutoffIndex : 0;

    // Convert to monetary value
    const totalNotional = positions.reduce((sum, p) => sum + p.notionalValue, 0n);
    return BigInt(Math.floor(Number(totalNotional) * Math.abs(avgTailReturn)));
  }

  /**
   * Run stress test
   */
  runStressTest(userId: string, scenarioId: string): StressTestResult | null {
    const scenario = this.stressScenarios.get(scenarioId);
    if (!scenario) return null;

    const positions = this.positions.get(userId);
    if (!positions || positions.length === 0) {
      return {
        scenarioId,
        portfolioLoss: 0n,
        lossPercentage: 0,
        positionsAtRisk: [],
        liquidationsTriggered: 0,
        insuranceFundImpact: 0n,
        systemSolvency: true
      };
    }

    let totalLoss = 0n;
    const positionsAtRisk: string[] = [];
    let liquidations = 0;

    for (const position of positions) {
      // Get price shock for this asset
      const priceShock = scenario.priceShocks.get(position.asset) ||
                         scenario.priceShocks.get('default') || 0;

      // Calculate loss
      const lossFraction = BigInt(Math.abs(priceShock) * 100);
      const positionLoss = (position.notionalValue * lossFraction) / 10000n;

      totalLoss += positionLoss;

      // Check if liquidation would trigger
      const adjustedPnL = position.unrealizedPnL - positionLoss;
      const marginUsed = position.notionalValue / BigInt(position.leverage);

      if (adjustedPnL < -(marginUsed * 80n / 100n)) {
        positionsAtRisk.push(position.positionId);
        liquidations++;
      }
    }

    const totalNotional = positions.reduce((sum, p) => sum + p.notionalValue, 0n);
    const lossPercentage = totalNotional > 0n
      ? Number((totalLoss * 10000n) / totalNotional) / 100
      : 0;

    // Insurance fund impact (simplified)
    const insuranceFundImpact = liquidations > 0
      ? (totalLoss * BigInt(liquidations)) / BigInt(positions.length * 10)
      : 0n;

    const systemSolvency = lossPercentage < 50;

    this.emit('stressTestCompleted', {
      userId,
      scenarioId,
      totalLoss,
      lossPercentage
    });

    return {
      scenarioId,
      portfolioLoss: totalLoss,
      lossPercentage,
      positionsAtRisk,
      liquidationsTriggered: liquidations,
      insuranceFundImpact,
      systemSolvency
    };
  }

  /**
   * Calculate concentration risk
   */
  calculateConcentrationRisk(userId: string): number {
    const positions = this.positions.get(userId);
    if (!positions || positions.length === 0) return 0;

    const totalNotional = positions.reduce((sum, p) => sum + p.notionalValue, 0n);
    if (totalNotional === 0n) return 0;

    // Group by asset
    const assetExposure = new Map<string, bigint>();
    for (const pos of positions) {
      const current = assetExposure.get(pos.asset) || 0n;
      assetExposure.set(pos.asset, current + pos.notionalValue);
    }

    // Find max concentration
    let maxConcentration = 0;
    for (const [, exposure] of assetExposure) {
      const concentration = Number((exposure * 10000n) / totalNotional) / 100;
      if (concentration > maxConcentration) {
        maxConcentration = concentration;
      }
    }

    return maxConcentration;
  }

  /**
   * Calculate liquidity risk
   */
  calculateLiquidityRisk(userId: string): number {
    const positions = this.positions.get(userId);
    if (!positions || positions.length === 0) return 0;

    let totalWeightedLiquidity = 0;
    let totalWeight = 0;

    for (const pos of positions) {
      const marketRisk = this.marketRisks.get(pos.asset);
      if (marketRisk) {
        const weight = Number(pos.notionalValue);
        totalWeightedLiquidity += pos.liquidityScore * weight;
        totalWeight += weight;
      }
    }

    if (totalWeight === 0) return 0;

    // Lower score = higher risk
    const avgLiquidity = totalWeightedLiquidity / totalWeight;
    return 100 - avgLiquidity; // Convert to risk score
  }

  /**
   * Calculate correlation risk
   */
  calculateCorrelationRisk(userId: string): number {
    const positions = this.positions.get(userId);
    if (!positions || positions.length < 2) return 0;

    // Get unique assets
    const assets = [...new Set(positions.map(p => p.asset))];
    if (assets.length < 2) return 0;

    // Calculate average correlation
    let totalCorrelation = 0;
    let pairCount = 0;

    for (let i = 0; i < assets.length; i++) {
      const marketRisk1 = this.marketRisks.get(assets[i]);
      if (!marketRisk1) continue;

      for (let j = i + 1; j < assets.length; j++) {
        const correlation = marketRisk1.correlationMatrix.get(assets[j]) || 0;
        totalCorrelation += Math.abs(correlation);
        pairCount++;
      }
    }

    return pairCount > 0 ? totalCorrelation / pairCount : 0;
  }

  /**
   * Check risk limits
   */
  checkRiskLimits(userId: string): { passed: boolean; violations: string[] } {
    const violations: string[] = [];
    const portfolioRisk = this.portfolioRisks.get(userId);

    if (!portfolioRisk) {
      return { passed: true, violations: [] };
    }

    // Check VaR limit
    if (portfolioRisk.varDaily > this.riskLimits.maxVaRPerUser) {
      violations.push(`VaR exceeds limit: ${portfolioRisk.varDaily} > ${this.riskLimits.maxVaRPerUser}`);
    }

    // Check concentration limit
    if (portfolioRisk.concentrationRisk > this.riskLimits.maxConcentrationPerAsset) {
      violations.push(`Concentration risk too high: ${portfolioRisk.concentrationRisk}%`);
    }

    // Check correlation exposure
    if (portfolioRisk.correlationRisk > this.riskLimits.maxCorrelationExposure) {
      violations.push(`Correlation exposure too high: ${portfolioRisk.correlationRisk}`);
    }

    // Check liquidity risk
    if (portfolioRisk.liquidityRisk > this.riskLimits.maxLiquidityRisk) {
      violations.push(`Liquidity risk too high: ${portfolioRisk.liquidityRisk}`);
    }

    if (violations.length > 0) {
      this.createAlert(
        RiskCategory.SYSTEMIC,
        RiskLevel.HIGH,
        `Risk limit violations for user ${userId}`,
        [userId],
        { violations }
      );
    }

    return {
      passed: violations.length === 0,
      violations
    };
  }

  /**
   * Get system-wide risk metrics
   */
  getSystemRiskMetrics(): {
    totalVaR: bigint;
    totalExposure: bigint;
    averageLeverage: number;
    systemLiquidityRisk: number;
    concentrationByAsset: Map<string, number>;
    openAlerts: number;
  } {
    let totalVaR = 0n;
    let totalExposure = 0n;
    let totalLeverage = 0;
    let positionCount = 0;

    const assetExposure = new Map<string, bigint>();

    for (const [userId, risk] of this.portfolioRisks) {
      totalVaR += risk.varDaily;
      totalExposure += risk.totalNotional;

      const positions = this.positions.get(userId);
      if (positions) {
        for (const pos of positions) {
          totalLeverage += pos.leverage;
          positionCount++;

          const current = assetExposure.get(pos.asset) || 0n;
          assetExposure.set(pos.asset, current + pos.notionalValue);
        }
      }
    }

    // Calculate concentration by asset
    const concentrationByAsset = new Map<string, number>();
    for (const [asset, exposure] of assetExposure) {
      if (totalExposure > 0n) {
        const concentration = Number((exposure * 10000n) / totalExposure) / 100;
        concentrationByAsset.set(asset, concentration);
      }
    }

    // System liquidity risk
    let systemLiquidityRisk = 0;
    let riskCount = 0;
    for (const risk of this.portfolioRisks.values()) {
      systemLiquidityRisk += risk.liquidityRisk;
      riskCount++;
    }

    const openAlerts = Array.from(this.alerts.values())
      .filter(a => !a.resolved).length;

    return {
      totalVaR,
      totalExposure,
      averageLeverage: positionCount > 0 ? totalLeverage / positionCount : 0,
      systemLiquidityRisk: riskCount > 0 ? systemLiquidityRisk / riskCount : 0,
      concentrationByAsset,
      openAlerts
    };
  }

  /**
   * Get portfolio risk profile
   */
  getPortfolioRisk(userId: string): PortfolioRisk | undefined {
    return this.portfolioRisks.get(userId);
  }

  /**
   * Create risk alert
   */
  createAlert(
    category: RiskCategory,
    level: RiskLevel,
    message: string,
    affectedEntities: string[],
    metrics: any
  ): void {
    const alert: RiskAlert = {
      id: crypto.randomBytes(16).toString('hex'),
      category,
      level,
      message,
      affectedEntities,
      metrics,
      timestamp: new Date(),
      resolved: false
    };

    this.alerts.set(alert.id, alert);
    this.emit('riskAlert', alert);

    if (level === RiskLevel.CRITICAL) {
      this.emit('criticalRiskAlert', alert);
    }
  }

  /**
   * Resolve alert
   */
  resolveAlert(alertId: string): void {
    const alert = this.alerts.get(alertId);
    if (alert) {
      alert.resolved = true;
      this.emit('alertResolved', alert);
    }
  }

  private updatePortfolioRisk(userId: string): void {
    const positions = this.positions.get(userId);
    if (!positions || positions.length === 0) {
      this.portfolioRisks.delete(userId);
      return;
    }

    const totalNotional = positions.reduce((sum, p) => sum + p.notionalValue, 0n);
    const totalPnL = positions.reduce((sum, p) => sum + p.unrealizedPnL, 0n);

    const varDaily = this.calculateVaR(userId, VaRMethod.HISTORICAL, 0.99, 1);
    const varWeekly = this.calculateVaR(userId, VaRMethod.HISTORICAL, 0.99, 7);
    const expectedShortfall = this.calculateExpectedShortfall(userId);

    const concentrationRisk = this.calculateConcentrationRisk(userId);
    const liquidityRisk = this.calculateLiquidityRisk(userId);
    const correlationRisk = this.calculateCorrelationRisk(userId);

    // Calculate Sharpe ratio (simplified)
    const returns = this.getPortfolioReturns(positions);
    const avgReturn = returns.length > 0
      ? returns.reduce((a, b) => a + b, 0) / returns.length
      : 0;
    const stdDev = this.calculateStdDev(returns);
    const sharpeRatio = stdDev > 0 ? (avgReturn - 0.02 / 252) / stdDev : 0;

    // Calculate max drawdown
    const maxDrawdown = this.calculateMaxDrawdown(positions);

    // Determine overall risk level
    const overallRiskLevel = this.determineRiskLevel(
      Number(varDaily),
      concentrationRisk,
      liquidityRisk,
      correlationRisk
    );

    const portfolioRisk: PortfolioRisk = {
      userId,
      totalNotional,
      totalUnrealizedPnL: totalPnL,
      varDaily,
      varWeekly,
      expectedShortfall,
      maxDrawdown,
      sharpeRatio,
      correlationRisk,
      concentrationRisk,
      liquidityRisk,
      overallRiskLevel,
      lastUpdated: new Date()
    };

    this.portfolioRisks.set(userId, portfolioRisk);
    this.emit('portfolioRiskUpdated', portfolioRisk);

    // Check risk limits
    this.checkRiskLimits(userId);
  }

  private calculateHistoricalVaR(
    positions: RiskPosition[],
    confidenceLevel: number,
    horizon: number
  ): bigint {
    const portfolioReturns = this.getPortfolioReturns(positions);
    if (portfolioReturns.length === 0) return 0n;

    // Scale returns for horizon
    const scaledReturns = portfolioReturns.map(r => r * Math.sqrt(horizon));

    // Sort returns
    const sortedReturns = [...scaledReturns].sort((a, b) => a - b);

    // Find VaR at confidence level
    const varIndex = Math.floor(sortedReturns.length * (1 - confidenceLevel));
    const varReturn = sortedReturns[varIndex];

    // Convert to monetary value
    const totalNotional = positions.reduce((sum, p) => sum + p.notionalValue, 0n);
    return BigInt(Math.floor(Number(totalNotional) * Math.abs(varReturn)));
  }

  private calculateParametricVaR(
    positions: RiskPosition[],
    confidenceLevel: number,
    horizon: number
  ): bigint {
    const portfolioReturns = this.getPortfolioReturns(positions);
    if (portfolioReturns.length === 0) return 0n;

    const mean = portfolioReturns.reduce((a, b) => a + b, 0) / portfolioReturns.length;
    const stdDev = this.calculateStdDev(portfolioReturns);

    // Z-score for confidence level (e.g., 2.33 for 99%)
    const zScore = this.getZScore(confidenceLevel);

    // VaR = portfolio value * (z * stdDev * sqrt(horizon) - mean * horizon)
    const varReturn = (zScore * stdDev * Math.sqrt(horizon) - mean * horizon);

    const totalNotional = positions.reduce((sum, p) => sum + p.notionalValue, 0n);
    return BigInt(Math.floor(Number(totalNotional) * Math.abs(varReturn)));
  }

  private calculateMonteCarloVaR(
    positions: RiskPosition[],
    confidenceLevel: number,
    horizon: number
  ): bigint {
    const simulatedPnLs: number[] = [];

    for (let sim = 0; sim < this.monteCarloSimulations; sim++) {
      let portfolioPnL = 0;

      for (const position of positions) {
        const marketRisk = this.marketRisks.get(position.asset);
        if (!marketRisk) continue;

        // Simulate price path using GBM
        const drift = 0; // Assume 0 drift for VaR
        const volatility = marketRisk.volatility24h / 100 / Math.sqrt(252);

        // Generate random return
        const z = this.boxMullerTransform();
        const simulatedReturn = drift * horizon / 252 + volatility * Math.sqrt(horizon / 252) * z;

        portfolioPnL += Number(position.notionalValue) * simulatedReturn;
      }

      simulatedPnLs.push(portfolioPnL);
    }

    // Sort PnLs
    const sortedPnLs = simulatedPnLs.sort((a, b) => a - b);

    // Find VaR at confidence level
    const varIndex = Math.floor(sortedPnLs.length * (1 - confidenceLevel));
    const varPnL = sortedPnLs[varIndex];

    return BigInt(Math.floor(Math.abs(varPnL)));
  }

  private getPortfolioReturns(positions: RiskPosition[]): number[] {
    // Get returns for each position and weight by notional
    const totalNotional = Number(positions.reduce((sum, p) => sum + p.notionalValue, 0n));
    if (totalNotional === 0) return [];

    // Get minimum length of historical returns
    let minLength = Infinity;
    for (const pos of positions) {
      const history = this.historicalReturns.get(pos.asset);
      if (history && history.returns.length < minLength) {
        minLength = history.returns.length;
      }
    }

    if (minLength === Infinity || minLength === 0) return [];

    // Calculate weighted portfolio returns
    const portfolioReturns: number[] = [];

    for (let i = 0; i < minLength; i++) {
      let dayReturn = 0;

      for (const pos of positions) {
        const history = this.historicalReturns.get(pos.asset);
        if (history) {
          const weight = Number(pos.notionalValue) / totalNotional;
          dayReturn += history.returns[i] * weight;
        }
      }

      portfolioReturns.push(dayReturn);
    }

    return portfolioReturns;
  }

  private calculateStdDev(values: number[]): number {
    if (values.length === 0) return 0;

    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const squaredDiffs = values.map(v => Math.pow(v - mean, 2));
    const avgSquaredDiff = squaredDiffs.reduce((a, b) => a + b, 0) / values.length;

    return Math.sqrt(avgSquaredDiff);
  }

  private calculateMaxDrawdown(positions: RiskPosition[]): bigint {
    // Simplified: use volatility as proxy
    const avgVolatility = positions.length > 0
      ? positions.reduce((sum, p) => sum + p.volatility, 0) / positions.length
      : 0;

    const totalNotional = positions.reduce((sum, p) => sum + p.notionalValue, 0n);

    // Estimate max drawdown as 3x volatility
    return BigInt(Math.floor(Number(totalNotional) * avgVolatility * 3 / 100));
  }

  private getZScore(confidenceLevel: number): number {
    // Approximate z-scores for common confidence levels
    if (confidenceLevel >= 0.99) return 2.33;
    if (confidenceLevel >= 0.95) return 1.65;
    if (confidenceLevel >= 0.90) return 1.28;
    return 1.0;
  }

  private boxMullerTransform(): number {
    // Generate standard normal random variable
    const u1 = Math.random();
    const u2 = Math.random();
    return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  }

  private determineRiskLevel(
    var_: number,
    concentration: number,
    liquidity: number,
    correlation: number
  ): RiskLevel {
    // Calculate weighted risk score
    const score = var_ * 0.3 + concentration * 0.25 + liquidity * 0.25 + correlation * 100 * 0.2;

    if (score > 80) return RiskLevel.CRITICAL;
    if (score > 60) return RiskLevel.HIGH;
    if (score > 40) return RiskLevel.MODERATE;
    if (score > 20) return RiskLevel.LOW;
    return RiskLevel.MINIMAL;
  }

  private startRiskMonitoring(): void {
    // Update all portfolio risks every minute
    setInterval(() => {
      for (const userId of this.positions.keys()) {
        this.updatePortfolioRisk(userId);
      }
    }, 60000);

    // Run stress tests every hour
    setInterval(() => {
      for (const userId of this.positions.keys()) {
        for (const scenarioId of this.stressScenarios.keys()) {
          this.runStressTest(userId, scenarioId);
        }
      }
    }, 3600000);

    // Clean old alerts
    setInterval(() => {
      const dayAgo = Date.now() - 24 * 60 * 60 * 1000;
      for (const [id, alert] of this.alerts) {
        if (alert.resolved && alert.timestamp.getTime() < dayAgo) {
          this.alerts.delete(id);
        }
      }
    }, 3600000);
  }
}

// Export types
export {
  RiskCategory,
  RiskLevel,
  VaRMethod,
  RiskPosition,
  PortfolioRisk,
  MarketRiskMetrics,
  StressScenario,
  StressTestResult,
  RiskAlert,
  RiskLimits,
  HistoricalReturn,
  MCPath
};
