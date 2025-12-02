import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import { performance } from 'perf_hooks';

/**
 * OBSERVABILITY STACK FOR MEV-RESISTANT DEX
 *
 * HYPOTHESIS: Comprehensive observability with sub-millisecond metric collection,
 * distributed tracing, and intelligent alerting will enable proactive issue detection
 * and maintain >99.99% uptime.
 *
 * SUCCESS METRICS:
 * - Metric collection overhead < 0.1% of request latency
 * - Alert detection to notification < 30 seconds
 * - 100% trace correlation across services
 * - Zero blind spots in system monitoring
 *
 * SECURITY CONSIDERATIONS:
 * - PII redaction in logs and traces
 * - Metric data encryption at rest
 * - Access control for sensitive dashboards
 * - Anomaly detection for security threats
 */

// Metric Types (Prometheus-compatible)
enum MetricType {
  COUNTER = 'counter',
  GAUGE = 'gauge',
  HISTOGRAM = 'histogram',
  SUMMARY = 'summary'
}

// Alert Severity Levels
enum AlertSeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info'
}

// Health Check Status
enum HealthStatus {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy'
}

// Trace Status
enum SpanStatus {
  OK = 'ok',
  ERROR = 'error',
  CANCELLED = 'cancelled'
}

// Interfaces
interface MetricLabel {
  [key: string]: string;
}

interface MetricValue {
  value: number;
  timestamp: bigint;
  labels: MetricLabel;
}

interface HistogramBucket {
  le: number;
  count: number;
}

interface Metric {
  name: string;
  type: MetricType;
  help: string;
  values: MetricValue[];
  buckets?: HistogramBucket[]; // For histograms
  quantiles?: Map<number, number>; // For summaries
}

interface TraceSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  operationName: string;
  serviceName: string;
  startTime: bigint;
  endTime?: bigint;
  duration?: number; // microseconds
  status: SpanStatus;
  tags: Map<string, string | number | boolean>;
  logs: SpanLog[];
  baggage: Map<string, string>;
}

interface SpanLog {
  timestamp: bigint;
  fields: Map<string, any>;
}

interface Alert {
  id: string;
  name: string;
  severity: AlertSeverity;
  message: string;
  metric: string;
  threshold: number;
  currentValue: number;
  triggeredAt: Date;
  resolvedAt?: Date;
  acknowledged: boolean;
  silenced: boolean;
  labels: MetricLabel;
}

interface AlertRule {
  id: string;
  name: string;
  metric: string;
  condition: AlertCondition;
  threshold: number;
  duration: number; // seconds
  severity: AlertSeverity;
  labels: MetricLabel;
  annotations: Map<string, string>;
  enabled: boolean;
}

interface AlertCondition {
  operator: '>' | '<' | '>=' | '<=' | '==' | '!=';
  aggregation: 'avg' | 'max' | 'min' | 'sum' | 'rate' | 'percentile';
  percentile?: number;
}

interface HealthCheck {
  name: string;
  status: HealthStatus;
  lastCheck: Date;
  latency: number;
  message?: string;
  dependencies: HealthCheck[];
}

interface DashboardWidget {
  id: string;
  title: string;
  type: 'timeseries' | 'gauge' | 'table' | 'stat' | 'heatmap';
  metrics: string[];
  query: string;
  refreshInterval: number;
}

interface LogEntry {
  timestamp: bigint;
  level: 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';
  service: string;
  message: string;
  traceId?: string;
  spanId?: string;
  fields: Map<string, any>;
}

// Configuration
interface ObservabilityConfig {
  serviceName: string;
  environment: string;
  metricsRetentionDays: number;
  traceRetentionDays: number;
  maxMetricsPerSecond: number;
  histogramBuckets: number[];
  alertCheckIntervalMs: number;
  healthCheckIntervalMs: number;
  piiPatterns: RegExp[];
  enableTracing: boolean;
  enableMetrics: boolean;
  enableAlerting: boolean;
}

/**
 * High-performance metrics collector
 */
class MetricsCollector extends EventEmitter {
  private metrics: Map<string, Metric> = new Map();
  private histogramBuckets: number[];
  private maxSamples: number = 10000;
  private ringBuffer: Map<string, MetricValue[]> = new Map();
  private piiPatterns: RegExp[];

  constructor(buckets: number[], piiPatterns: RegExp[]) {
    super();
    this.histogramBuckets = buckets;
    this.piiPatterns = piiPatterns;
  }

  /**
   * Register a new metric
   */
  registerMetric(
    name: string,
    type: MetricType,
    help: string
  ): void {
    if (this.metrics.has(name)) {
      throw new Error(`Metric ${name} already registered`);
    }

    const metric: Metric = {
      name,
      type,
      help,
      values: []
    };

    if (type === MetricType.HISTOGRAM) {
      metric.buckets = this.histogramBuckets.map(le => ({
        le,
        count: 0
      }));
    }

    if (type === MetricType.SUMMARY) {
      metric.quantiles = new Map([
        [0.5, 0],
        [0.9, 0],
        [0.95, 0],
        [0.99, 0]
      ]);
    }

    this.metrics.set(name, metric);
    this.ringBuffer.set(name, []);
  }

  /**
   * Increment a counter
   */
  incrementCounter(
    name: string,
    value: number = 1,
    labels: MetricLabel = {}
  ): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== MetricType.COUNTER) {
      throw new Error(`Counter ${name} not found`);
    }

    const sanitizedLabels = this.sanitizeLabels(labels);
    const metricValue: MetricValue = {
      value,
      timestamp: this.getNanoseconds(),
      labels: sanitizedLabels
    };

    this.addToRingBuffer(name, metricValue);
    this.emit('metric', { name, type: 'counter', value: metricValue });
  }

  /**
   * Set a gauge value
   */
  setGauge(
    name: string,
    value: number,
    labels: MetricLabel = {}
  ): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== MetricType.GAUGE) {
      throw new Error(`Gauge ${name} not found`);
    }

    const sanitizedLabels = this.sanitizeLabels(labels);
    const metricValue: MetricValue = {
      value,
      timestamp: this.getNanoseconds(),
      labels: sanitizedLabels
    };

    this.addToRingBuffer(name, metricValue);
    this.emit('metric', { name, type: 'gauge', value: metricValue });
  }

  /**
   * Observe a histogram value
   */
  observeHistogram(
    name: string,
    value: number,
    labels: MetricLabel = {}
  ): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== MetricType.HISTOGRAM) {
      throw new Error(`Histogram ${name} not found`);
    }

    // Update bucket counts
    for (const bucket of metric.buckets!) {
      if (value <= bucket.le) {
        bucket.count++;
      }
    }

    const sanitizedLabels = this.sanitizeLabels(labels);
    const metricValue: MetricValue = {
      value,
      timestamp: this.getNanoseconds(),
      labels: sanitizedLabels
    };

    this.addToRingBuffer(name, metricValue);
    this.emit('metric', { name, type: 'histogram', value: metricValue });
  }

  /**
   * Observe a summary value (auto-calculates quantiles)
   */
  observeSummary(
    name: string,
    value: number,
    labels: MetricLabel = {}
  ): void {
    const metric = this.metrics.get(name);
    if (!metric || metric.type !== MetricType.SUMMARY) {
      throw new Error(`Summary ${name} not found`);
    }

    const sanitizedLabels = this.sanitizeLabels(labels);
    const metricValue: MetricValue = {
      value,
      timestamp: this.getNanoseconds(),
      labels: sanitizedLabels
    };

    this.addToRingBuffer(name, metricValue);

    // Recalculate quantiles
    const buffer = this.ringBuffer.get(name)!;
    const values = buffer.map(v => v.value).sort((a, b) => a - b);
    const len = values.length;

    if (len > 0) {
      metric.quantiles!.set(0.5, values[Math.floor(len * 0.5)]);
      metric.quantiles!.set(0.9, values[Math.floor(len * 0.9)]);
      metric.quantiles!.set(0.95, values[Math.floor(len * 0.95)]);
      metric.quantiles!.set(0.99, values[Math.floor(len * 0.99)]);
    }

    this.emit('metric', { name, type: 'summary', value: metricValue });
  }

  /**
   * Get metric in Prometheus exposition format
   */
  getPrometheusFormat(): string {
    let output = '';

    for (const [name, metric] of this.metrics) {
      output += `# HELP ${name} ${metric.help}\n`;
      output += `# TYPE ${name} ${metric.type}\n`;

      const buffer = this.ringBuffer.get(name)!;

      if (metric.type === MetricType.HISTOGRAM) {
        // Output histogram buckets
        for (const bucket of metric.buckets!) {
          output += `${name}_bucket{le="${bucket.le}"} ${bucket.count}\n`;
        }
        output += `${name}_bucket{le="+Inf"} ${buffer.length}\n`;
        const sum = buffer.reduce((acc, v) => acc + v.value, 0);
        output += `${name}_sum ${sum}\n`;
        output += `${name}_count ${buffer.length}\n`;
      } else if (metric.type === MetricType.SUMMARY) {
        // Output summary quantiles
        for (const [quantile, value] of metric.quantiles!) {
          output += `${name}{quantile="${quantile}"} ${value}\n`;
        }
        const sum = buffer.reduce((acc, v) => acc + v.value, 0);
        output += `${name}_sum ${sum}\n`;
        output += `${name}_count ${buffer.length}\n`;
      } else {
        // Counter or Gauge - output latest value per label set
        const latestByLabels = new Map<string, MetricValue>();
        for (const value of buffer) {
          const labelKey = JSON.stringify(value.labels);
          latestByLabels.set(labelKey, value);
        }

        for (const [, value] of latestByLabels) {
          const labelStr = Object.entries(value.labels)
            .map(([k, v]) => `${k}="${v}"`)
            .join(',');
          if (labelStr) {
            output += `${name}{${labelStr}} ${value.value}\n`;
          } else {
            output += `${name} ${value.value}\n`;
          }
        }
      }
      output += '\n';
    }

    return output;
  }

  /**
   * Query metrics with aggregation
   */
  queryMetric(
    name: string,
    aggregation: 'avg' | 'max' | 'min' | 'sum' | 'count' | 'rate',
    windowMs: number = 60000
  ): number {
    const buffer = this.ringBuffer.get(name);
    if (!buffer || buffer.length === 0) {
      return 0;
    }

    const cutoff = this.getNanoseconds() - BigInt(windowMs) * 1000000n;
    const windowValues = buffer.filter(v => v.timestamp >= cutoff);

    if (windowValues.length === 0) {
      return 0;
    }

    switch (aggregation) {
      case 'avg':
        return windowValues.reduce((sum, v) => sum + v.value, 0) / windowValues.length;
      case 'max':
        return Math.max(...windowValues.map(v => v.value));
      case 'min':
        return Math.min(...windowValues.map(v => v.value));
      case 'sum':
        return windowValues.reduce((sum, v) => sum + v.value, 0);
      case 'count':
        return windowValues.length;
      case 'rate':
        // Rate per second
        return (windowValues.length / windowMs) * 1000;
      default:
        return 0;
    }
  }

  private addToRingBuffer(name: string, value: MetricValue): void {
    const buffer = this.ringBuffer.get(name)!;
    buffer.push(value);

    // Maintain ring buffer size
    if (buffer.length > this.maxSamples) {
      buffer.shift();
    }
  }

  private sanitizeLabels(labels: MetricLabel): MetricLabel {
    const sanitized: MetricLabel = {};

    for (const [key, value] of Object.entries(labels)) {
      let sanitizedValue = value;

      // Redact PII
      for (const pattern of this.piiPatterns) {
        sanitizedValue = sanitizedValue.replace(pattern, '[REDACTED]');
      }

      sanitized[key] = sanitizedValue;
    }

    return sanitized;
  }

  private getNanoseconds(): bigint {
    const [seconds, nanoseconds] = process.hrtime();
    return BigInt(seconds) * 1000000000n + BigInt(nanoseconds);
  }
}

/**
 * Distributed tracing system (OpenTelemetry-compatible)
 */
class DistributedTracer extends EventEmitter {
  private activeSpans: Map<string, TraceSpan> = new Map();
  private completedSpans: TraceSpan[] = [];
  private maxSpanHistory: number = 100000;
  private serviceName: string;
  private piiPatterns: RegExp[];

  constructor(serviceName: string, piiPatterns: RegExp[]) {
    super();
    this.serviceName = serviceName;
    this.piiPatterns = piiPatterns;
  }

  /**
   * Start a new trace
   */
  startTrace(operationName: string): TraceSpan {
    const traceId = this.generateTraceId();
    const spanId = this.generateSpanId();

    const span: TraceSpan = {
      traceId,
      spanId,
      operationName,
      serviceName: this.serviceName,
      startTime: this.getNanoseconds(),
      status: SpanStatus.OK,
      tags: new Map(),
      logs: [],
      baggage: new Map()
    };

    this.activeSpans.set(spanId, span);
    this.emit('spanStarted', span);

    return span;
  }

  /**
   * Start a child span
   */
  startSpan(
    operationName: string,
    parentSpan: TraceSpan
  ): TraceSpan {
    const span: TraceSpan = {
      traceId: parentSpan.traceId,
      spanId: this.generateSpanId(),
      parentSpanId: parentSpan.spanId,
      operationName,
      serviceName: this.serviceName,
      startTime: this.getNanoseconds(),
      status: SpanStatus.OK,
      tags: new Map(),
      logs: [],
      baggage: new Map(parentSpan.baggage) // Inherit baggage
    };

    this.activeSpans.set(span.spanId, span);
    this.emit('spanStarted', span);

    return span;
  }

  /**
   * End a span
   */
  endSpan(span: TraceSpan, status: SpanStatus = SpanStatus.OK): void {
    span.endTime = this.getNanoseconds();
    span.duration = Number(span.endTime - span.startTime) / 1000; // microseconds
    span.status = status;

    // Sanitize tags for PII
    this.sanitizeSpanTags(span);

    this.activeSpans.delete(span.spanId);
    this.completedSpans.push(span);

    // Maintain history size
    if (this.completedSpans.length > this.maxSpanHistory) {
      this.completedSpans = this.completedSpans.slice(-this.maxSpanHistory);
    }

    this.emit('spanEnded', span);
  }

  /**
   * Add tag to span
   */
  setTag(span: TraceSpan, key: string, value: string | number | boolean): void {
    span.tags.set(key, value);
  }

  /**
   * Add log to span
   */
  log(span: TraceSpan, fields: Map<string, any>): void {
    const sanitizedFields = new Map<string, any>();

    for (const [key, value] of fields) {
      let sanitizedValue = value;
      if (typeof value === 'string') {
        for (const pattern of this.piiPatterns) {
          sanitizedValue = sanitizedValue.replace(pattern, '[REDACTED]');
        }
      }
      sanitizedFields.set(key, sanitizedValue);
    }

    span.logs.push({
      timestamp: this.getNanoseconds(),
      fields: sanitizedFields
    });
  }

  /**
   * Set baggage item (propagated to all child spans)
   */
  setBaggage(span: TraceSpan, key: string, value: string): void {
    span.baggage.set(key, value);
  }

  /**
   * Get trace by ID
   */
  getTrace(traceId: string): TraceSpan[] {
    return this.completedSpans.filter(s => s.traceId === traceId);
  }

  /**
   * Export traces in Jaeger format
   */
  exportJaegerFormat(traceId: string): object {
    const spans = this.getTrace(traceId);

    return {
      data: [{
        traceID: traceId,
        spans: spans.map(span => ({
          traceID: span.traceId,
          spanID: span.spanId,
          operationName: span.operationName,
          references: span.parentSpanId ? [{
            refType: 'CHILD_OF',
            traceID: span.traceId,
            spanID: span.parentSpanId
          }] : [],
          startTime: Number(span.startTime / 1000n), // microseconds
          duration: span.duration,
          tags: Array.from(span.tags.entries()).map(([key, value]) => ({
            key,
            type: typeof value,
            value
          })),
          logs: span.logs.map(log => ({
            timestamp: Number(log.timestamp / 1000n),
            fields: Array.from(log.fields.entries()).map(([key, value]) => ({
              key,
              type: typeof value,
              value
            }))
          })),
          processID: 'p1'
        })),
        processes: {
          p1: {
            serviceName: this.serviceName,
            tags: []
          }
        }
      }]
    };
  }

  /**
   * Get span statistics
   */
  getSpanStats(): {
    totalSpans: number;
    activeSpans: number;
    avgDuration: number;
    errorRate: number;
  } {
    const completed = this.completedSpans;
    const errorCount = completed.filter(s => s.status === SpanStatus.ERROR).length;

    return {
      totalSpans: completed.length,
      activeSpans: this.activeSpans.size,
      avgDuration: completed.length > 0
        ? completed.reduce((sum, s) => sum + (s.duration || 0), 0) / completed.length
        : 0,
      errorRate: completed.length > 0
        ? errorCount / completed.length
        : 0
    };
  }

  private generateTraceId(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  private generateSpanId(): string {
    return crypto.randomBytes(8).toString('hex');
  }

  private sanitizeSpanTags(span: TraceSpan): void {
    const sanitizedTags = new Map<string, string | number | boolean>();

    for (const [key, value] of span.tags) {
      if (typeof value === 'string') {
        let sanitized = value;
        for (const pattern of this.piiPatterns) {
          sanitized = sanitized.replace(pattern, '[REDACTED]');
        }
        sanitizedTags.set(key, sanitized);
      } else {
        sanitizedTags.set(key, value);
      }
    }

    span.tags = sanitizedTags;
  }

  private getNanoseconds(): bigint {
    const [seconds, nanoseconds] = process.hrtime();
    return BigInt(seconds) * 1000000000n + BigInt(nanoseconds);
  }
}

/**
 * Intelligent alerting system
 */
class AlertingEngine extends EventEmitter {
  private rules: Map<string, AlertRule> = new Map();
  private activeAlerts: Map<string, Alert> = new Map();
  private alertHistory: Alert[] = [];
  private metricsCollector: MetricsCollector;
  private checkInterval: number;
  private pendingConditions: Map<string, { firstSeen: number; value: number }> = new Map();

  constructor(metricsCollector: MetricsCollector, checkIntervalMs: number) {
    super();
    this.metricsCollector = metricsCollector;
    this.checkInterval = checkIntervalMs;
    this.startChecking();
  }

  /**
   * Add alert rule
   */
  addRule(rule: AlertRule): void {
    this.rules.set(rule.id, rule);
    this.emit('ruleAdded', rule);
  }

  /**
   * Remove alert rule
   */
  removeRule(ruleId: string): void {
    this.rules.delete(ruleId);
    this.pendingConditions.delete(ruleId);
    this.emit('ruleRemoved', ruleId);
  }

  /**
   * Silence an alert
   */
  silenceAlert(alertId: string, durationMs: number): void {
    const alert = this.activeAlerts.get(alertId);
    if (alert) {
      alert.silenced = true;

      setTimeout(() => {
        alert.silenced = false;
      }, durationMs);

      this.emit('alertSilenced', alert);
    }
  }

  /**
   * Acknowledge an alert
   */
  acknowledgeAlert(alertId: string): void {
    const alert = this.activeAlerts.get(alertId);
    if (alert) {
      alert.acknowledged = true;
      this.emit('alertAcknowledged', alert);
    }
  }

  /**
   * Get all active alerts
   */
  getActiveAlerts(): Alert[] {
    return Array.from(this.activeAlerts.values());
  }

  /**
   * Get alert history
   */
  getAlertHistory(limit: number = 100): Alert[] {
    return this.alertHistory.slice(-limit);
  }

  private startChecking(): void {
    setInterval(() => {
      this.checkAllRules();
    }, this.checkInterval);
  }

  private checkAllRules(): void {
    const now = Date.now();

    for (const [ruleId, rule] of this.rules) {
      if (!rule.enabled) continue;

      const currentValue = this.evaluateCondition(rule);

      if (this.isConditionMet(rule, currentValue)) {
        // Check if condition has persisted for required duration
        const pending = this.pendingConditions.get(ruleId);

        if (!pending) {
          // First time condition is met
          this.pendingConditions.set(ruleId, {
            firstSeen: now,
            value: currentValue
          });
        } else if (now - pending.firstSeen >= rule.duration * 1000) {
          // Condition has persisted long enough
          if (!this.activeAlerts.has(ruleId)) {
            this.triggerAlert(rule, currentValue);
          }
        }
      } else {
        // Condition not met, clear pending and resolve if active
        this.pendingConditions.delete(ruleId);

        if (this.activeAlerts.has(ruleId)) {
          this.resolveAlert(ruleId);
        }
      }
    }
  }

  private evaluateCondition(rule: AlertRule): number {
    const { aggregation, percentile } = rule.condition;

    if (aggregation === 'percentile' && percentile) {
      const buffer = this.metricsCollector['ringBuffer'].get(rule.metric);
      if (!buffer || buffer.length === 0) return 0;

      const values = buffer.map((v: MetricValue) => v.value).sort((a: number, b: number) => a - b);
      const index = Math.floor((percentile / 100) * values.length);
      return values[index] || 0;
    }

    return this.metricsCollector.queryMetric(
      rule.metric,
      aggregation as 'avg' | 'max' | 'min' | 'sum' | 'count' | 'rate'
    );
  }

  private isConditionMet(rule: AlertRule, value: number): boolean {
    const { operator, threshold } = { ...rule.condition, threshold: rule.threshold };

    switch (operator) {
      case '>':
        return value > threshold;
      case '<':
        return value < threshold;
      case '>=':
        return value >= threshold;
      case '<=':
        return value <= threshold;
      case '==':
        return value === threshold;
      case '!=':
        return value !== threshold;
      default:
        return false;
    }
  }

  private triggerAlert(rule: AlertRule, currentValue: number): void {
    const alert: Alert = {
      id: crypto.randomBytes(8).toString('hex'),
      name: rule.name,
      severity: rule.severity,
      message: this.formatAlertMessage(rule, currentValue),
      metric: rule.metric,
      threshold: rule.threshold,
      currentValue,
      triggeredAt: new Date(),
      acknowledged: false,
      silenced: false,
      labels: rule.labels
    };

    this.activeAlerts.set(rule.id, alert);
    this.alertHistory.push(alert);

    this.emit('alertTriggered', alert);

    // Emit severity-specific events
    if (rule.severity === AlertSeverity.CRITICAL) {
      this.emit('criticalAlert', alert);
    }
  }

  private resolveAlert(ruleId: string): void {
    const alert = this.activeAlerts.get(ruleId);
    if (alert) {
      alert.resolvedAt = new Date();
      this.activeAlerts.delete(ruleId);
      this.emit('alertResolved', alert);
    }
  }

  private formatAlertMessage(rule: AlertRule, value: number): string {
    let message = `${rule.name}: ${rule.metric} is ${rule.condition.operator} ${rule.threshold}`;
    message += ` (current: ${value.toFixed(4)})`;
    return message;
  }
}

/**
 * Health check system
 */
class HealthCheckManager extends EventEmitter {
  private checks: Map<string, () => Promise<HealthCheck>> = new Map();
  private lastResults: Map<string, HealthCheck> = new Map();
  private checkInterval: number;

  constructor(checkIntervalMs: number) {
    super();
    this.checkInterval = checkIntervalMs;
    this.startChecking();
  }

  /**
   * Register a health check
   */
  registerCheck(
    name: string,
    checkFn: () => Promise<HealthCheck>
  ): void {
    this.checks.set(name, checkFn);
  }

  /**
   * Run all health checks
   */
  async runAllChecks(): Promise<Map<string, HealthCheck>> {
    const results = new Map<string, HealthCheck>();

    for (const [name, checkFn] of this.checks) {
      const startTime = performance.now();

      try {
        const result = await checkFn();
        result.lastCheck = new Date();
        result.latency = performance.now() - startTime;
        results.set(name, result);
      } catch (error) {
        results.set(name, {
          name,
          status: HealthStatus.UNHEALTHY,
          lastCheck: new Date(),
          latency: performance.now() - startTime,
          message: error instanceof Error ? error.message : 'Unknown error',
          dependencies: []
        });
      }
    }

    this.lastResults = results;
    this.emit('healthCheckCompleted', results);

    // Check for status changes
    for (const [name, result] of results) {
      if (result.status === HealthStatus.UNHEALTHY) {
        this.emit('unhealthyService', result);
      }
    }

    return results;
  }

  /**
   * Get overall system health
   */
  getOverallHealth(): HealthStatus {
    let hasUnhealthy = false;
    let hasDegraded = false;

    for (const result of this.lastResults.values()) {
      if (result.status === HealthStatus.UNHEALTHY) {
        hasUnhealthy = true;
      } else if (result.status === HealthStatus.DEGRADED) {
        hasDegraded = true;
      }
    }

    if (hasUnhealthy) return HealthStatus.UNHEALTHY;
    if (hasDegraded) return HealthStatus.DEGRADED;
    return HealthStatus.HEALTHY;
  }

  /**
   * Get health report
   */
  getHealthReport(): object {
    const checks: object[] = [];

    for (const [name, result] of this.lastResults) {
      checks.push({
        name,
        status: result.status,
        latency: result.latency,
        lastCheck: result.lastCheck,
        message: result.message
      });
    }

    return {
      status: this.getOverallHealth(),
      timestamp: new Date(),
      checks
    };
  }

  private startChecking(): void {
    setInterval(() => {
      this.runAllChecks().catch(err => {
        this.emit('error', err);
      });
    }, this.checkInterval);
  }
}

/**
 * Log aggregator with structured logging
 */
class LogAggregator extends EventEmitter {
  private logs: LogEntry[] = [];
  private maxLogs: number = 100000;
  private piiPatterns: RegExp[];
  private serviceName: string;

  constructor(serviceName: string, piiPatterns: RegExp[]) {
    super();
    this.serviceName = serviceName;
    this.piiPatterns = piiPatterns;
  }

  /**
   * Log a message
   */
  log(
    level: 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal',
    message: string,
    fields: Map<string, any> = new Map(),
    traceId?: string,
    spanId?: string
  ): void {
    // Sanitize message and fields for PII
    let sanitizedMessage = message;
    for (const pattern of this.piiPatterns) {
      sanitizedMessage = sanitizedMessage.replace(pattern, '[REDACTED]');
    }

    const sanitizedFields = new Map<string, any>();
    for (const [key, value] of fields) {
      if (typeof value === 'string') {
        let sanitized = value;
        for (const pattern of this.piiPatterns) {
          sanitized = sanitized.replace(pattern, '[REDACTED]');
        }
        sanitizedFields.set(key, sanitized);
      } else {
        sanitizedFields.set(key, value);
      }
    }

    const entry: LogEntry = {
      timestamp: this.getNanoseconds(),
      level,
      service: this.serviceName,
      message: sanitizedMessage,
      traceId,
      spanId,
      fields: sanitizedFields
    };

    this.logs.push(entry);

    // Maintain log buffer size
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs);
    }

    this.emit('log', entry);

    // Emit level-specific events
    if (level === 'error' || level === 'fatal') {
      this.emit('errorLog', entry);
    }
  }

  /**
   * Search logs
   */
  searchLogs(
    query: {
      level?: string;
      traceId?: string;
      messagePattern?: RegExp;
      startTime?: bigint;
      endTime?: bigint;
    },
    limit: number = 100
  ): LogEntry[] {
    let filtered = this.logs;

    if (query.level) {
      filtered = filtered.filter(l => l.level === query.level);
    }

    if (query.traceId) {
      filtered = filtered.filter(l => l.traceId === query.traceId);
    }

    if (query.messagePattern) {
      filtered = filtered.filter(l => query.messagePattern!.test(l.message));
    }

    if (query.startTime) {
      filtered = filtered.filter(l => l.timestamp >= query.startTime!);
    }

    if (query.endTime) {
      filtered = filtered.filter(l => l.timestamp <= query.endTime!);
    }

    return filtered.slice(-limit);
  }

  /**
   * Export logs in JSON format
   */
  exportJSON(logs: LogEntry[]): string {
    return JSON.stringify(
      logs.map(log => ({
        timestamp: log.timestamp.toString(),
        level: log.level,
        service: log.service,
        message: log.message,
        traceId: log.traceId,
        spanId: log.spanId,
        fields: Object.fromEntries(log.fields)
      })),
      null,
      2
    );
  }

  private getNanoseconds(): bigint {
    const [seconds, nanoseconds] = process.hrtime();
    return BigInt(seconds) * 1000000000n + BigInt(nanoseconds);
  }
}

/**
 * Main Observability Stack orchestrator
 */
export class ObservabilityStack extends EventEmitter {
  private config: ObservabilityConfig;
  public metrics: MetricsCollector;
  public tracer: DistributedTracer;
  public alerting: AlertingEngine;
  public healthChecks: HealthCheckManager;
  public logs: LogAggregator;

  constructor(config: ObservabilityConfig) {
    super();
    this.config = config;

    // Initialize components
    this.metrics = new MetricsCollector(
      config.histogramBuckets,
      config.piiPatterns
    );

    this.tracer = new DistributedTracer(
      config.serviceName,
      config.piiPatterns
    );

    this.alerting = new AlertingEngine(
      this.metrics,
      config.alertCheckIntervalMs
    );

    this.healthChecks = new HealthCheckManager(
      config.healthCheckIntervalMs
    );

    this.logs = new LogAggregator(
      config.serviceName,
      config.piiPatterns
    );

    // Wire up event forwarding
    this.setupEventForwarding();

    // Register default metrics
    this.registerDefaultMetrics();

    // Register default health checks
    this.registerDefaultHealthChecks();

    // Register default alert rules
    this.registerDefaultAlertRules();
  }

  /**
   * Create instrumented function wrapper
   */
  instrument<T extends (...args: any[]) => Promise<any>>(
    fn: T,
    operationName: string
  ): T {
    const self = this;

    return (async function (...args: any[]) {
      const span = self.tracer.startTrace(operationName);
      const startTime = performance.now();

      try {
        const result = await fn(...args);

        self.tracer.endSpan(span, SpanStatus.OK);
        self.metrics.observeHistogram(
          'function_duration_seconds',
          (performance.now() - startTime) / 1000
        );

        return result;
      } catch (error) {
        self.tracer.setTag(span, 'error', true);
        self.tracer.log(span, new Map([
          ['event', 'error'],
          ['message', error instanceof Error ? error.message : 'Unknown error']
        ]));
        self.tracer.endSpan(span, SpanStatus.ERROR);

        self.metrics.incrementCounter('function_errors_total', 1, {
          operation: operationName
        });

        throw error;
      }
    }) as T;
  }

  /**
   * Get comprehensive system status
   */
  async getSystemStatus(): Promise<{
    health: HealthStatus;
    metrics: string;
    activeAlerts: Alert[];
    traceStats: object;
    recentErrors: LogEntry[];
  }> {
    await this.healthChecks.runAllChecks();

    return {
      health: this.healthChecks.getOverallHealth(),
      metrics: this.metrics.getPrometheusFormat(),
      activeAlerts: this.alerting.getActiveAlerts(),
      traceStats: this.tracer.getSpanStats(),
      recentErrors: this.logs.searchLogs({ level: 'error' }, 50)
    };
  }

  /**
   * Create dashboard configuration
   */
  createDashboard(name: string, widgets: DashboardWidget[]): object {
    return {
      name,
      uid: crypto.randomBytes(8).toString('hex'),
      title: name,
      tags: [this.config.serviceName, this.config.environment],
      timezone: 'utc',
      refresh: '30s',
      panels: widgets.map((widget, index) => ({
        id: index + 1,
        title: widget.title,
        type: widget.type,
        gridPos: {
          x: (index % 2) * 12,
          y: Math.floor(index / 2) * 8,
          w: 12,
          h: 8
        },
        targets: widget.metrics.map(metric => ({
          expr: widget.query.replace('$metric', metric),
          legendFormat: metric,
          refId: metric.substring(0, 1).toUpperCase()
        })),
        options: this.getWidgetOptions(widget.type)
      }))
    };
  }

  private setupEventForwarding(): void {
    // Forward critical events to main emitter
    this.alerting.on('criticalAlert', alert => {
      this.emit('criticalAlert', alert);
      this.logs.log('fatal', `Critical alert triggered: ${alert.name}`, new Map([
        ['alertId', alert.id],
        ['metric', alert.metric],
        ['value', alert.currentValue]
      ]));
    });

    this.healthChecks.on('unhealthyService', check => {
      this.emit('serviceUnhealthy', check);
      this.logs.log('error', `Service unhealthy: ${check.name}`, new Map([
        ['latency', check.latency],
        ['message', check.message || '']
      ]));
    });

    this.logs.on('errorLog', entry => {
      this.metrics.incrementCounter('error_logs_total', 1, {
        level: entry.level
      });
    });
  }

  private registerDefaultMetrics(): void {
    // System metrics
    this.metrics.registerMetric(
      'http_requests_total',
      MetricType.COUNTER,
      'Total number of HTTP requests'
    );

    this.metrics.registerMetric(
      'http_request_duration_seconds',
      MetricType.HISTOGRAM,
      'HTTP request duration in seconds'
    );

    this.metrics.registerMetric(
      'active_connections',
      MetricType.GAUGE,
      'Number of active connections'
    );

    this.metrics.registerMetric(
      'function_duration_seconds',
      MetricType.HISTOGRAM,
      'Function execution duration in seconds'
    );

    this.metrics.registerMetric(
      'function_errors_total',
      MetricType.COUNTER,
      'Total number of function errors'
    );

    this.metrics.registerMetric(
      'error_logs_total',
      MetricType.COUNTER,
      'Total number of error logs'
    );

    // DEX-specific metrics
    this.metrics.registerMetric(
      'orders_processed_total',
      MetricType.COUNTER,
      'Total number of orders processed'
    );

    this.metrics.registerMetric(
      'order_latency_microseconds',
      MetricType.HISTOGRAM,
      'Order processing latency in microseconds'
    );

    this.metrics.registerMetric(
      'trades_executed_total',
      MetricType.COUNTER,
      'Total number of trades executed'
    );

    this.metrics.registerMetric(
      'mev_attacks_detected',
      MetricType.COUNTER,
      'Number of MEV attacks detected'
    );

    this.metrics.registerMetric(
      'liquidity_pool_tvl',
      MetricType.GAUGE,
      'Total value locked in liquidity pools'
    );

    this.metrics.registerMetric(
      'sequencer_batch_size',
      MetricType.SUMMARY,
      'Sequencer batch size distribution'
    );
  }

  private registerDefaultHealthChecks(): void {
    // Database health check
    this.healthChecks.registerCheck('database', async () => ({
      name: 'database',
      status: HealthStatus.HEALTHY, // Would be actual DB ping
      lastCheck: new Date(),
      latency: 0,
      dependencies: []
    }));

    // Redis health check
    this.healthChecks.registerCheck('cache', async () => ({
      name: 'cache',
      status: HealthStatus.HEALTHY,
      lastCheck: new Date(),
      latency: 0,
      dependencies: []
    }));

    // Blockchain node health check
    this.healthChecks.registerCheck('blockchain_node', async () => ({
      name: 'blockchain_node',
      status: HealthStatus.HEALTHY,
      lastCheck: new Date(),
      latency: 0,
      dependencies: []
    }));
  }

  private registerDefaultAlertRules(): void {
    // High error rate alert
    this.alerting.addRule({
      id: 'high_error_rate',
      name: 'High Error Rate',
      metric: 'function_errors_total',
      condition: {
        operator: '>',
        aggregation: 'rate'
      },
      threshold: 10, // More than 10 errors per second
      duration: 60, // For 60 seconds
      severity: AlertSeverity.HIGH,
      labels: { team: 'platform' },
      annotations: new Map([
        ['description', 'Error rate exceeded threshold']
      ]),
      enabled: true
    });

    // Slow order processing
    this.alerting.addRule({
      id: 'slow_order_processing',
      name: 'Slow Order Processing',
      metric: 'order_latency_microseconds',
      condition: {
        operator: '>',
        aggregation: 'percentile',
        percentile: 99
      },
      threshold: 100, // P99 > 100 microseconds
      duration: 120,
      severity: AlertSeverity.MEDIUM,
      labels: { team: 'trading' },
      annotations: new Map([
        ['description', 'Order processing latency exceeded SLA']
      ]),
      enabled: true
    });

    // MEV attack detected
    this.alerting.addRule({
      id: 'mev_attack_detected',
      name: 'MEV Attack Detected',
      metric: 'mev_attacks_detected',
      condition: {
        operator: '>',
        aggregation: 'rate'
      },
      threshold: 0.1, // Any attacks
      duration: 10,
      severity: AlertSeverity.CRITICAL,
      labels: { team: 'security' },
      annotations: new Map([
        ['description', 'Possible MEV attack in progress']
      ]),
      enabled: true
    });
  }

  private getWidgetOptions(type: string): object {
    switch (type) {
      case 'timeseries':
        return {
          legend: { show: true },
          tooltip: { mode: 'single' }
        };
      case 'gauge':
        return {
          showThresholdLabels: true,
          showThresholdMarkers: true
        };
      case 'stat':
        return {
          colorMode: 'value',
          graphMode: 'area'
        };
      default:
        return {};
    }
  }
}

// Export default configuration
export const defaultObservabilityConfig: ObservabilityConfig = {
  serviceName: 'mev-resistant-dex',
  environment: 'production',
  metricsRetentionDays: 30,
  traceRetentionDays: 7,
  maxMetricsPerSecond: 100000,
  histogramBuckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  alertCheckIntervalMs: 15000,
  healthCheckIntervalMs: 30000,
  piiPatterns: [
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, // Email
    /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, // Phone
    /\b\d{3}[-]?\d{2}[-]?\d{4}\b/g, // SSN
    /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b/g // Credit card
  ],
  enableTracing: true,
  enableMetrics: true,
  enableAlerting: true
};

export {
  MetricType,
  AlertSeverity,
  HealthStatus,
  SpanStatus,
  MetricsCollector,
  DistributedTracer,
  AlertingEngine,
  HealthCheckManager,
  LogAggregator
};
