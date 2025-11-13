/**
 * Prometheus Metrics Exporter
 *
 * Exposes metrics for:
 * - Block production rate
 * - Order processing latency (p50, p95, p99)
 * - MEV attacks (blocked vs attempted)
 * - Sequencer uptime
 * - Gas costs
 * - Active connections
 *
 * Metrics endpoint: /metrics
 */

import express from 'express';
import { Registry, Counter, Gauge, Histogram, collectDefaultMetrics } from 'prom-client';
import Redis from 'ioredis';
import { ethers } from 'ethers';

export class PrometheusExporter {
  private app: express.Application;
  private registry: Registry;
  private redis: Redis;
  private provider: ethers.Provider;

  // Metrics
  private blockProductionCounter: Counter;
  private orderSubmissionCounter: Counter;
  private orderProcessingDuration: Histogram;
  private tradeCounter: Counter;
  private mevAttackCounter: Counter;
  private mevBlockedCounter: Counter;
  private activeConnectionsGauge: Gauge;
  private orderbookDepthGauge: Gauge;
  private gasCostGauge: Gauge;
  private sequencerUptimeGauge: Gauge;
  private memoryUsageGauge: Gauge;
  private latencyHistogram: Histogram;

  constructor(redisUrl: string, providerUrl: string) {
    this.app = express();
    this.registry = new Registry();
    this.redis = new Redis(redisUrl);
    this.provider = new ethers.JsonRpcProvider(providerUrl);

    // Collect default metrics (CPU, memory, etc.)
    collectDefaultMetrics({ register: this.registry, prefix: 'dex_' });

    this.initializeMetrics();
    this.setupRoutes();
    this.startCollectors();
  }

  /**
   * Initialize Prometheus metrics
   */
  private initializeMetrics(): void {
    // Block production
    this.blockProductionCounter = new Counter({
      name: 'dex_blocks_produced_total',
      help: 'Total number of blocks produced',
      registers: [this.registry],
    });

    // Order metrics
    this.orderSubmissionCounter = new Counter({
      name: 'dex_orders_submitted_total',
      help: 'Total number of orders submitted',
      labelNames: ['pair', 'side', 'type'],
      registers: [this.registry],
    });

    this.orderProcessingDuration = new Histogram({
      name: 'dex_order_processing_duration_seconds',
      help: 'Order processing duration in seconds',
      labelNames: ['status'],
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5],
      registers: [this.registry],
    });

    // Trade metrics
    this.tradeCounter = new Counter({
      name: 'dex_trades_executed_total',
      help: 'Total number of trades executed',
      labelNames: ['pair'],
      registers: [this.registry],
    });

    // MEV metrics
    this.mevAttackCounter = new Counter({
      name: 'dex_mev_attacks_total',
      help: 'Total number of MEV attacks detected',
      labelNames: ['type', 'severity'],
      registers: [this.registry],
    });

    this.mevBlockedCounter = new Counter({
      name: 'dex_mev_attacks_blocked_total',
      help: 'Total number of MEV attacks blocked',
      labelNames: ['type'],
      registers: [this.registry],
    });

    // Connection metrics
    this.activeConnectionsGauge = new Gauge({
      name: 'dex_active_connections',
      help: 'Number of active WebSocket connections',
      registers: [this.registry],
    });

    // Orderbook metrics
    this.orderbookDepthGauge = new Gauge({
      name: 'dex_orderbook_depth',
      help: 'Total liquidity depth in orderbook',
      labelNames: ['pair', 'side'],
      registers: [this.registry],
    });

    // Gas metrics
    this.gasCostGauge = new Gauge({
      name: 'dex_gas_cost_gwei',
      help: 'Current gas cost in gwei',
      labelNames: ['operation'],
      registers: [this.registry],
    });

    // Sequencer metrics
    this.sequencerUptimeGauge = new Gauge({
      name: 'dex_sequencer_uptime_seconds',
      help: 'Sequencer uptime in seconds',
      registers: [this.registry],
    });

    // Memory metrics
    this.memoryUsageGauge = new Gauge({
      name: 'dex_memory_usage_bytes',
      help: 'Memory usage in bytes',
      labelNames: ['type'],
      registers: [this.registry],
    });

    // Latency metrics
    this.latencyHistogram = new Histogram({
      name: 'dex_latency_seconds',
      help: 'End-to-end latency in seconds',
      labelNames: ['operation'],
      buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10],
      registers: [this.registry],
    });
  }

  /**
   * Setup Express routes
   */
  private setupRoutes(): void {
    // Metrics endpoint
    this.app.get('/metrics', async (req, res) => {
      try {
        res.set('Content-Type', this.registry.contentType);
        res.end(await this.registry.metrics());
      } catch (error) {
        res.status(500).end((error as Error).message);
      }
    });

    // Health endpoint
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: Date.now(),
        uptime: process.uptime(),
      });
    });
  }

  /**
   * Start metric collectors
   */
  private startCollectors(): void {
    // Collect block production metrics
    this.collectBlockMetrics();

    // Collect MEV metrics
    this.collectMEVMetrics();

    // Collect connection metrics
    this.collectConnectionMetrics();

    // Collect gas metrics
    this.collectGasMetrics();

    // Collect memory metrics
    this.collectMemoryMetrics();

    console.log('📊 Metric collectors started');
  }

  /**
   * Collect block production metrics
   */
  private collectBlockMetrics(): void {
    setInterval(async () => {
      try {
        // Get current block number
        const blockNumber = await this.provider.getBlockNumber();
        this.blockProductionCounter.inc();

        // Calculate sequencer uptime
        const startTime = await this.redis.get('sequencer:start_time');
        if (startTime) {
          const uptime = (Date.now() - Number(startTime)) / 1000;
          this.sequencerUptimeGauge.set(uptime);
        }
      } catch (error) {
        console.error('Failed to collect block metrics:', error);
      }
    }, 5000); // Every 5 seconds
  }

  /**
   * Collect MEV metrics from Redis
   */
  private collectMEVMetrics(): void {
    // Subscribe to MEV alerts
    const subscriber = new Redis(this.redis.options);

    subscriber.subscribe('mev:alerts', (err) => {
      if (err) {
        console.error('Failed to subscribe to MEV alerts:', err);
      }
    });

    subscriber.on('message', (channel, message) => {
      if (channel === 'mev:alerts') {
        try {
          const alert = JSON.parse(message);

          this.mevAttackCounter.inc({
            type: alert.alertType,
            severity: alert.severity,
          });

          if (alert.blocked) {
            this.mevBlockedCounter.inc({ type: alert.alertType });
          }
        } catch (error) {
          console.error('Failed to parse MEV alert:', error);
        }
      }
    });
  }

  /**
   * Collect connection metrics from WebSocket feed
   */
  private collectConnectionMetrics(): void {
    const subscriber = new Redis(this.redis.options);

    subscriber.subscribe('websocket:health', (err) => {
      if (err) {
        console.error('Failed to subscribe to WebSocket health:', err);
      }
    });

    subscriber.on('message', (channel, message) => {
      if (channel === 'websocket:health') {
        try {
          const stats = JSON.parse(message);
          this.activeConnectionsGauge.set(stats.connectedClients);
        } catch (error) {
          console.error('Failed to parse WebSocket health:', error);
        }
      }
    });
  }

  /**
   * Collect gas metrics
   */
  private collectGasMetrics(): void {
    setInterval(async () => {
      try {
        const feeData = await this.provider.getFeeData();

        if (feeData.gasPrice) {
          const gasPriceGwei = Number(ethers.formatUnits(feeData.gasPrice, 'gwei'));
          this.gasCostGauge.set({ operation: 'base' }, gasPriceGwei);
        }

        if (feeData.maxFeePerGas) {
          const maxFeeGwei = Number(ethers.formatUnits(feeData.maxFeePerGas, 'gwei'));
          this.gasCostGauge.set({ operation: 'max' }, maxFeeGwei);
        }
      } catch (error) {
        console.error('Failed to collect gas metrics:', error);
      }
    }, 15000); // Every 15 seconds
  }

  /**
   * Collect memory metrics
   */
  private collectMemoryMetrics(): void {
    setInterval(() => {
      const memUsage = process.memoryUsage();

      this.memoryUsageGauge.set({ type: 'rss' }, memUsage.rss);
      this.memoryUsageGauge.set({ type: 'heap_total' }, memUsage.heapTotal);
      this.memoryUsageGauge.set({ type: 'heap_used' }, memUsage.heapUsed);
      this.memoryUsageGauge.set({ type: 'external' }, memUsage.external);
    }, 10000); // Every 10 seconds
  }

  /**
   * Record order submission
   */
  public recordOrderSubmission(pair: string, side: string, type: string): void {
    this.orderSubmissionCounter.inc({ pair, side, type });
  }

  /**
   * Record order processing duration
   */
  public recordOrderProcessing(durationSeconds: number, status: string): void {
    this.orderProcessingDuration.observe({ status }, durationSeconds);
  }

  /**
   * Record trade execution
   */
  public recordTrade(pair: string): void {
    this.tradeCounter.inc({ pair });
  }

  /**
   * Record latency
   */
  public recordLatency(operation: string, durationSeconds: number): void {
    this.latencyHistogram.observe({ operation }, durationSeconds);
  }

  /**
   * Update orderbook depth
   */
  public updateOrderbookDepth(pair: string, side: string, depth: number): void {
    this.orderbookDepthGauge.set({ pair, side }, depth);
  }

  /**
   * Start server
   */
  public listen(port: number): void {
    this.app.listen(port, () => {
      console.log(`📊 Prometheus exporter running on port ${port}`);
      console.log(`📈 Metrics: http://localhost:${port}/metrics`);
    });
  }

  /**
   * Get current metrics (for testing)
   */
  public async getMetrics(): Promise<string> {
    return await this.registry.metrics();
  }
}

/**
 * Start exporter
 */
export function startPrometheusExporter(): PrometheusExporter {
  const exporter = new PrometheusExporter(
    process.env.REDIS_URL || 'redis://localhost:6379',
    process.env.RPC_URL || 'http://localhost:8545'
  );

  const PORT = Number(process.env.METRICS_PORT) || 9090;
  exporter.listen(PORT);

  return exporter;
}

// Start if run directly
if (require.main === module) {
  startPrometheusExporter();
}
