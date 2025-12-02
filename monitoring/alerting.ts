/**
 * Alerting System
 *
 * Monitors critical metrics and sends alerts via:
 * - Slack
 * - PagerDuty
 * - Email
 *
 * Alert Conditions:
 * - Sequencer down
 * - High latency (p99 > 5s)
 * - MEV attack spike (>10 in 1 min)
 * - Low liquidity
 * - Memory leak
 * - Failed transactions spike
 */

import axios from 'axios';
import Redis from 'ioredis';
import { ethers } from 'ethers';

interface Alert {
  severity: 'info' | 'warning' | 'error' | 'critical';
  title: string;
  message: string;
  timestamp: number;
  metadata?: Record<string, any>;
}

interface AlertRule {
  name: string;
  condition: () => Promise<boolean>;
  severity: Alert['severity'];
  message: string;
  cooldown: number; // Seconds between alerts
  lastTriggered?: number;
}

export class AlertingSystem {
  private redis: Redis;
  private provider: ethers.Provider;
  private rules: AlertRule[] = [];

  // Configuration
  private slackWebhookUrl: string;
  private pagerDutyApiKey: string;
  private pagerDutyServiceKey: string;
  private emailRecipients: string[];

  // Metrics tracking
  private metrics = {
    mevAttacks: [] as number[], // Timestamps
    latencies: [] as number[],
    failedTxCount: 0,
    lastBlockTime: Date.now(),
  };

  constructor(
    redisUrl: string,
    providerUrl: string,
    config: {
      slackWebhook?: string;
      pagerDutyApiKey?: string;
      pagerDutyServiceKey?: string;
      emailRecipients?: string[];
    }
  ) {
    this.redis = new Redis(redisUrl);
    this.provider = new ethers.JsonRpcProvider(providerUrl);

    this.slackWebhookUrl = config.slackWebhook || '';
    this.pagerDutyApiKey = config.pagerDutyApiKey || '';
    this.pagerDutyServiceKey = config.pagerDutyServiceKey || '';
    this.emailRecipients = config.emailRecipients || [];

    this.setupRules();
    this.startMonitoring();
  }

  /**
   * Setup alert rules
   */
  private setupRules(): void {
    // Rule 1: Sequencer down
    this.rules.push({
      name: 'sequencer_down',
      condition: async () => {
        const lastBlock = await this.redis.get('sequencer:last_block');
        if (!lastBlock) return false;

        const timeSinceLastBlock = Date.now() - Number(lastBlock);
        return timeSinceLastBlock > 10000; // 10 seconds
      },
      severity: 'critical',
      message: '🚨 Sequencer appears to be down - no blocks produced in 10s',
      cooldown: 60, // 1 minute
    });

    // Rule 2: High latency
    this.rules.push({
      name: 'high_latency',
      condition: async () => {
        if (this.metrics.latencies.length < 100) return false;

        const sorted = [...this.metrics.latencies].sort((a, b) => a - b);
        const p99 = sorted[Math.floor(sorted.length * 0.99)];

        return p99 > 5000; // 5 seconds
      },
      severity: 'warning',
      message: '⚠️ High latency detected - p99 > 5s',
      cooldown: 300, // 5 minutes
    });

    // Rule 3: MEV attack spike
    this.rules.push({
      name: 'mev_spike',
      condition: async () => {
        const oneMinuteAgo = Date.now() - 60000;
        const recentAttacks = this.metrics.mevAttacks.filter(t => t > oneMinuteAgo);

        return recentAttacks.length > 10;
      },
      severity: 'error',
      message: '🛡️ MEV attack spike detected - >10 attacks in 1 minute',
      cooldown: 180, // 3 minutes
    });

    // Rule 4: Low liquidity
    this.rules.push({
      name: 'low_liquidity',
      condition: async () => {
        const liquidity = await this.redis.get('orderbook:total_liquidity');
        if (!liquidity) return false;

        return Number(liquidity) < 100000; // $100k threshold
      },
      severity: 'warning',
      message: '💧 Low liquidity warning - total liquidity < $100k',
      cooldown: 600, // 10 minutes
    });

    // Rule 5: Memory leak detection
    this.rules.push({
      name: 'memory_leak',
      condition: async () => {
        const memUsage = process.memoryUsage();
        const heapUsedMB = memUsage.heapUsed / 1024 / 1024;

        return heapUsedMB > 1024; // 1 GB
      },
      severity: 'error',
      message: '💾 Memory usage critical - heap > 1GB',
      cooldown: 300, // 5 minutes
    });

    // Rule 6: Failed transaction spike
    this.rules.push({
      name: 'failed_tx_spike',
      condition: async () => {
        return this.metrics.failedTxCount > 50;
      },
      severity: 'error',
      message: '❌ High transaction failure rate - >50 failures',
      cooldown: 180, // 3 minutes
    });

    // Rule 7: Gas price spike
    this.rules.push({
      name: 'gas_spike',
      condition: async () => {
        try {
          const feeData = await this.provider.getFeeData();
          if (!feeData.gasPrice) return false;

          const gasPriceGwei = Number(ethers.formatUnits(feeData.gasPrice, 'gwei'));
          return gasPriceGwei > 100; // 100 gwei
        } catch {
          return false;
        }
      },
      severity: 'warning',
      message: '⛽ Gas price spike - >100 gwei',
      cooldown: 600, // 10 minutes
    });

    console.log(`📋 Configured ${this.rules.length} alert rules`);
  }

  /**
   * Start monitoring
   */
  private startMonitoring(): void {
    // Check rules every 30 seconds
    setInterval(() => {
      this.checkRules();
    }, 30000);

    // Subscribe to MEV alerts
    const subscriber = new Redis(this.redis.options);

    subscriber.subscribe('mev:alerts', (err) => {
      if (err) {
        console.error('Failed to subscribe to MEV alerts:', err);
      }
    });

    subscriber.on('message', (channel, message) => {
      if (channel === 'mev:alerts') {
        this.metrics.mevAttacks.push(Date.now());

        // Clean old entries (keep 5 minutes)
        const fiveMinutesAgo = Date.now() - 300000;
        this.metrics.mevAttacks = this.metrics.mevAttacks.filter(t => t > fiveMinutesAgo);
      }
    });

    // Subscribe to latency metrics
    subscriber.subscribe('metrics:latency', (err) => {
      if (err) {
        console.error('Failed to subscribe to latency metrics:', err);
      }
    });

    subscriber.on('message', (channel, message) => {
      if (channel === 'metrics:latency') {
        try {
          const latency = JSON.parse(message).latency;
          this.metrics.latencies.push(latency);

          // Keep only last 1000 measurements
          if (this.metrics.latencies.length > 1000) {
            this.metrics.latencies.shift();
          }
        } catch (error) {
          console.error('Failed to parse latency metric:', error);
        }
      }
    });

    console.log('🔔 Alert monitoring started');
  }

  /**
   * Check all rules
   */
  private async checkRules(): Promise<void> {
    for (const rule of this.rules) {
      try {
        // Check cooldown
        if (rule.lastTriggered) {
          const timeSinceLastTrigger = (Date.now() - rule.lastTriggered) / 1000;
          if (timeSinceLastTrigger < rule.cooldown) {
            continue;
          }
        }

        // Check condition
        const shouldAlert = await rule.condition();

        if (shouldAlert) {
          await this.sendAlert({
            severity: rule.severity,
            title: rule.name,
            message: rule.message,
            timestamp: Date.now(),
            metadata: {
              rule: rule.name,
            },
          });

          rule.lastTriggered = Date.now();
        }
      } catch (error) {
        console.error(`Failed to check rule ${rule.name}:`, error);
      }
    }
  }

  /**
   * Send alert to all configured channels
   */
  private async sendAlert(alert: Alert): Promise<void> {
    console.log(`🚨 ALERT [${alert.severity}]: ${alert.message}`);

    // Send to Slack
    if (this.slackWebhookUrl) {
      await this.sendSlackAlert(alert);
    }

    // Send to PagerDuty (only for critical alerts)
    if (this.pagerDutyApiKey && alert.severity === 'critical') {
      await this.sendPagerDutyAlert(alert);
    }

    // Send email
    if (this.emailRecipients.length > 0) {
      await this.sendEmailAlert(alert);
    }

    // Store in Redis for dashboard
    await this.redis.lpush('alerts:history', JSON.stringify(alert));
    await this.redis.ltrim('alerts:history', 0, 999); // Keep last 1000
  }

  /**
   * Send Slack alert
   */
  private async sendSlackAlert(alert: Alert): Promise<void> {
    try {
      const color = {
        info: '#36a64f',
        warning: '#ff9800',
        error: '#f44336',
        critical: '#9c27b0',
      }[alert.severity];

      await axios.post(this.slackWebhookUrl, {
        attachments: [
          {
            color,
            title: `${this.getSeverityEmoji(alert.severity)} ${alert.title}`,
            text: alert.message,
            fields: [
              {
                title: 'Severity',
                value: alert.severity.toUpperCase(),
                short: true,
              },
              {
                title: 'Time',
                value: new Date(alert.timestamp).toISOString(),
                short: true,
              },
            ],
            footer: 'DEX Monitoring',
            ts: Math.floor(alert.timestamp / 1000),
          },
        ],
      });

      console.log('✅ Slack alert sent');
    } catch (error) {
      console.error('Failed to send Slack alert:', error);
    }
  }

  /**
   * Send PagerDuty alert
   */
  private async sendPagerDutyAlert(alert: Alert): Promise<void> {
    try {
      await axios.post(
        'https://events.pagerduty.com/v2/enqueue',
        {
          routing_key: this.pagerDutyServiceKey,
          event_action: 'trigger',
          payload: {
            summary: alert.message,
            severity: alert.severity,
            source: 'DEX Monitoring',
            timestamp: new Date(alert.timestamp).toISOString(),
            custom_details: alert.metadata,
          },
        },
        {
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );

      console.log('✅ PagerDuty alert sent');
    } catch (error) {
      console.error('Failed to send PagerDuty alert:', error);
    }
  }

  /**
   * Send email alert
   */
  private async sendEmailAlert(alert: Alert): Promise<void> {
    // Would integrate with SendGrid, AWS SES, etc.
    console.log(`📧 Email alert to ${this.emailRecipients.join(', ')}`);
  }

  /**
   * Get severity emoji
   */
  private getSeverityEmoji(severity: Alert['severity']): string {
    return {
      info: 'ℹ️',
      warning: '⚠️',
      error: '❌',
      critical: '🚨',
    }[severity];
  }

  /**
   * Trigger manual alert
   */
  public async triggerAlert(
    severity: Alert['severity'],
    title: string,
    message: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    await this.sendAlert({
      severity,
      title,
      message,
      timestamp: Date.now(),
      metadata,
    });
  }

  /**
   * Get alert history
   */
  public async getAlertHistory(limit: number = 100): Promise<Alert[]> {
    const alerts = await this.redis.lrange('alerts:history', 0, limit - 1);
    return alerts.map(a => JSON.parse(a));
  }

  /**
   * Record failed transaction
   */
  public recordFailedTransaction(): void {
    this.metrics.failedTxCount++;

    // Reset counter every minute
    setTimeout(() => {
      this.metrics.failedTxCount = Math.max(0, this.metrics.failedTxCount - 1);
    }, 60000);
  }

  /**
   * Health check
   */
  public getHealth(): object {
    return {
      activeRules: this.rules.length,
      recentMEVAttacks: this.metrics.mevAttacks.length,
      latencySamples: this.metrics.latencies.length,
      failedTxCount: this.metrics.failedTxCount,
    };
  }
}

/**
 * Start alerting system
 */
export function startAlertingSystem(): AlertingSystem {
  const alerting = new AlertingSystem(
    process.env.REDIS_URL || 'redis://localhost:6379',
    process.env.RPC_URL || 'http://localhost:8545',
    {
      slackWebhook: process.env.SLACK_WEBHOOK_URL,
      pagerDutyApiKey: process.env.PAGERDUTY_API_KEY,
      pagerDutyServiceKey: process.env.PAGERDUTY_SERVICE_KEY,
      emailRecipients: process.env.EMAIL_RECIPIENTS?.split(',') || [],
    }
  );

  console.log('🔔 Alerting system initialized');

  return alerting;
}

// Start if run directly
if (require.main === module) {
  startAlertingSystem();
}
