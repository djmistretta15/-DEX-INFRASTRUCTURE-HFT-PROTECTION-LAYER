import { EventEmitter } from 'events';
import * as crypto from 'crypto';

/**
 * CIRCUIT BREAKER AND RATE LIMITING SYSTEM
 *
 * HYPOTHESIS: Implementing circuit breakers with adaptive thresholds and
 * token bucket rate limiting will prevent cascade failures and ensure
 * fair resource allocation with <1ms overhead.
 *
 * SUCCESS METRICS:
 * - Zero cascade failures
 * - Rate limiting overhead < 1ms
 * - 99.99% request fairness
 * - Automatic recovery within 30 seconds of issue resolution
 *
 * SECURITY CONSIDERATIONS:
 * - DDoS protection through rate limiting
 * - Resource exhaustion prevention
 * - Fair queuing to prevent starvation
 * - Backpressure propagation
 */

// Circuit Breaker States
enum CircuitState {
  CLOSED = 'closed',     // Normal operation
  OPEN = 'open',         // Failing, reject requests
  HALF_OPEN = 'half_open' // Testing if service recovered
}

// Rate Limit Strategy
enum RateLimitStrategy {
  TOKEN_BUCKET = 'token_bucket',
  SLIDING_WINDOW = 'sliding_window',
  FIXED_WINDOW = 'fixed_window',
  LEAKY_BUCKET = 'leaky_bucket'
}

// Interfaces
interface CircuitBreakerConfig {
  name: string;
  failureThreshold: number;
  successThreshold: number;
  timeout: number; // ms before attempting recovery
  halfOpenMaxRequests: number;
  monitoringWindow: number; // ms
  volumeThreshold: number; // min requests before tripping
}

interface CircuitBreakerStats {
  totalRequests: number;
  failures: number;
  successes: number;
  rejections: number;
  lastFailure?: Date;
  lastSuccess?: Date;
  stateChanges: { state: CircuitState; timestamp: Date }[];
}

interface RateLimitConfig {
  name: string;
  strategy: RateLimitStrategy;
  maxRequests: number;
  windowMs: number;
  burstSize?: number; // For token bucket
  refillRate?: number; // Tokens per second for token bucket
  fairnessEnabled: boolean;
}

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: Date;
  retryAfter?: number; // ms
  queuePosition?: number;
}

interface BulkheadConfig {
  name: string;
  maxConcurrent: number;
  maxQueue: number;
  queueTimeout: number; // ms
}

interface RetryConfig {
  maxRetries: number;
  initialDelay: number; // ms
  maxDelay: number; // ms
  backoffMultiplier: number;
  jitterFactor: number;
  retryableErrors: string[];
}

interface FallbackConfig<T> {
  handler: () => Promise<T>;
  timeout: number;
  cacheDuration?: number;
}

/**
 * Circuit Breaker implementation
 */
class CircuitBreaker extends EventEmitter {
  private config: CircuitBreakerConfig;
  private state: CircuitState = CircuitState.CLOSED;
  private stats: CircuitBreakerStats;
  private failureWindow: number[] = [];
  private successWindow: number[] = [];
  private halfOpenRequests: number = 0;
  private lastStateChange: Date;
  private resetTimeout?: NodeJS.Timeout;

  constructor(config: CircuitBreakerConfig) {
    super();
    this.config = config;
    this.lastStateChange = new Date();
    this.stats = {
      totalRequests: 0,
      failures: 0,
      successes: 0,
      rejections: 0,
      stateChanges: [{ state: CircuitState.CLOSED, timestamp: new Date() }]
    };
  }

  /**
   * Execute function through circuit breaker
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    this.stats.totalRequests++;

    // Check if we should allow the request
    if (!this.canExecute()) {
      this.stats.rejections++;
      this.emit('rejected', { circuitName: this.config.name, state: this.state });
      throw new Error(`Circuit breaker ${this.config.name} is ${this.state}`);
    }

    if (this.state === CircuitState.HALF_OPEN) {
      this.halfOpenRequests++;
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure(error);
      throw error;
    }
  }

  /**
   * Check if request can be executed
   */
  private canExecute(): boolean {
    switch (this.state) {
      case CircuitState.CLOSED:
        return true;

      case CircuitState.OPEN:
        return false;

      case CircuitState.HALF_OPEN:
        return this.halfOpenRequests < this.config.halfOpenMaxRequests;

      default:
        return false;
    }
  }

  /**
   * Handle successful execution
   */
  private onSuccess(): void {
    this.stats.successes++;
    this.stats.lastSuccess = new Date();

    const now = Date.now();
    this.successWindow.push(now);

    // Clean old entries
    this.cleanWindow(this.successWindow);

    if (this.state === CircuitState.HALF_OPEN) {
      // Check if we should close the circuit
      if (this.successWindow.length >= this.config.successThreshold) {
        this.transitionTo(CircuitState.CLOSED);
      }
    }

    this.emit('success', { circuitName: this.config.name });
  }

  /**
   * Handle failed execution
   */
  private onFailure(error: any): void {
    this.stats.failures++;
    this.stats.lastFailure = new Date();

    const now = Date.now();
    this.failureWindow.push(now);

    // Clean old entries
    this.cleanWindow(this.failureWindow);

    if (this.state === CircuitState.HALF_OPEN) {
      // Immediately open on failure in half-open
      this.transitionTo(CircuitState.OPEN);
    } else if (this.state === CircuitState.CLOSED) {
      // Check if we should trip the circuit
      const totalInWindow = this.failureWindow.length + this.successWindow.length;

      if (totalInWindow >= this.config.volumeThreshold) {
        const failureRate = this.failureWindow.length / totalInWindow;

        if (failureRate >= this.config.failureThreshold / 100) {
          this.transitionTo(CircuitState.OPEN);
        }
      }
    }

    this.emit('failure', {
      circuitName: this.config.name,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }

  /**
   * Transition to new state
   */
  private transitionTo(newState: CircuitState): void {
    const previousState = this.state;
    this.state = newState;
    this.lastStateChange = new Date();

    this.stats.stateChanges.push({
      state: newState,
      timestamp: this.lastStateChange
    });

    // Reset counters
    if (newState === CircuitState.CLOSED) {
      this.failureWindow = [];
      this.successWindow = [];
      this.halfOpenRequests = 0;

      if (this.resetTimeout) {
        clearTimeout(this.resetTimeout);
        this.resetTimeout = undefined;
      }
    } else if (newState === CircuitState.OPEN) {
      // Schedule transition to half-open
      this.resetTimeout = setTimeout(() => {
        this.transitionTo(CircuitState.HALF_OPEN);
      }, this.config.timeout);
    } else if (newState === CircuitState.HALF_OPEN) {
      this.halfOpenRequests = 0;
    }

    this.emit('stateChange', {
      circuitName: this.config.name,
      previousState,
      newState
    });
  }

  /**
   * Clean old entries from window
   */
  private cleanWindow(window: number[]): void {
    const cutoff = Date.now() - this.config.monitoringWindow;
    while (window.length > 0 && window[0] < cutoff) {
      window.shift();
    }
  }

  /**
   * Get circuit breaker status
   */
  getStatus(): {
    name: string;
    state: CircuitState;
    stats: CircuitBreakerStats;
    lastStateChange: Date;
  } {
    return {
      name: this.config.name,
      state: this.state,
      stats: { ...this.stats },
      lastStateChange: this.lastStateChange
    };
  }

  /**
   * Force circuit to specific state (for testing/admin)
   */
  forceState(state: CircuitState): void {
    this.transitionTo(state);
  }
}

/**
 * Token Bucket Rate Limiter
 */
class TokenBucketRateLimiter {
  private tokens: Map<string, number> = new Map();
  private lastRefill: Map<string, number> = new Map();
  private maxTokens: number;
  private refillRate: number; // tokens per millisecond

  constructor(maxTokens: number, refillRatePerSecond: number) {
    this.maxTokens = maxTokens;
    this.refillRate = refillRatePerSecond / 1000;
  }

  /**
   * Try to consume tokens
   */
  tryConsume(key: string, tokens: number = 1): RateLimitResult {
    const now = Date.now();
    this.refillTokens(key, now);

    const currentTokens = this.tokens.get(key) || this.maxTokens;

    if (currentTokens >= tokens) {
      this.tokens.set(key, currentTokens - tokens);

      const resetTime = new Date(now + (tokens / this.refillRate));

      return {
        allowed: true,
        remaining: currentTokens - tokens,
        resetTime
      };
    }

    // Calculate when enough tokens will be available
    const tokensNeeded = tokens - currentTokens;
    const waitTime = tokensNeeded / this.refillRate;

    return {
      allowed: false,
      remaining: currentTokens,
      resetTime: new Date(now + waitTime),
      retryAfter: Math.ceil(waitTime)
    };
  }

  private refillTokens(key: string, now: number): void {
    const lastTime = this.lastRefill.get(key) || now;
    const timePassed = now - lastTime;

    if (timePassed > 0) {
      const newTokens = timePassed * this.refillRate;
      const currentTokens = this.tokens.get(key) || this.maxTokens;
      const updatedTokens = Math.min(this.maxTokens, currentTokens + newTokens);

      this.tokens.set(key, updatedTokens);
      this.lastRefill.set(key, now);
    }
  }

  /**
   * Get current token count for key
   */
  getTokens(key: string): number {
    this.refillTokens(key, Date.now());
    return this.tokens.get(key) || this.maxTokens;
  }
}

/**
 * Sliding Window Rate Limiter
 */
class SlidingWindowRateLimiter {
  private windows: Map<string, number[]> = new Map();
  private maxRequests: number;
  private windowMs: number;

  constructor(maxRequests: number, windowMs: number) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  /**
   * Check if request is allowed
   */
  tryRequest(key: string): RateLimitResult {
    const now = Date.now();
    const window = this.windows.get(key) || [];

    // Clean old entries
    const cutoff = now - this.windowMs;
    const validEntries = window.filter(t => t > cutoff);

    if (validEntries.length < this.maxRequests) {
      validEntries.push(now);
      this.windows.set(key, validEntries);

      return {
        allowed: true,
        remaining: this.maxRequests - validEntries.length,
        resetTime: new Date(now + this.windowMs)
      };
    }

    // Calculate when the oldest request will expire
    const oldestRequest = validEntries[0];
    const retryAfter = oldestRequest + this.windowMs - now;

    return {
      allowed: false,
      remaining: 0,
      resetTime: new Date(oldestRequest + this.windowMs),
      retryAfter: Math.ceil(retryAfter)
    };
  }

  /**
   * Get current request count for key
   */
  getRequestCount(key: string): number {
    const now = Date.now();
    const window = this.windows.get(key) || [];
    const cutoff = now - this.windowMs;
    return window.filter(t => t > cutoff).length;
  }
}

/**
 * Fair Queuing Rate Limiter
 */
class FairQueueRateLimiter extends EventEmitter {
  private queues: Map<string, Array<{ resolve: (value: RateLimitResult) => void; timestamp: number }>> = new Map();
  private processingRate: number; // requests per second
  private lastProcessed: number = Date.now();
  private processing: boolean = false;

  constructor(requestsPerSecond: number) {
    super();
    this.processingRate = requestsPerSecond;
    this.startProcessing();
  }

  /**
   * Enqueue request for fair processing
   */
  enqueueRequest(key: string): Promise<RateLimitResult> {
    return new Promise((resolve) => {
      if (!this.queues.has(key)) {
        this.queues.set(key, []);
      }

      const queue = this.queues.get(key)!;
      const queuePosition = this.getTotalQueueSize();

      queue.push({
        resolve,
        timestamp: Date.now()
      });

      this.emit('enqueued', { key, queuePosition });
    });
  }

  private startProcessing(): void {
    setInterval(() => {
      this.processQueues();
    }, 1000 / this.processingRate);
  }

  private processQueues(): void {
    if (this.processing) return;
    this.processing = true;

    // Round-robin processing across all queues (fair queuing)
    const keys = Array.from(this.queues.keys());
    let processed = false;

    for (const key of keys) {
      const queue = this.queues.get(key)!;
      if (queue.length > 0) {
        const request = queue.shift()!;
        request.resolve({
          allowed: true,
          remaining: this.processingRate,
          resetTime: new Date(Date.now() + 1000)
        });
        processed = true;
        break; // Process one request per cycle for fairness
      }
    }

    // Clean empty queues
    for (const key of keys) {
      if (this.queues.get(key)!.length === 0) {
        this.queues.delete(key);
      }
    }

    this.processing = false;

    if (processed) {
      this.emit('processed');
    }
  }

  private getTotalQueueSize(): number {
    let total = 0;
    for (const queue of this.queues.values()) {
      total += queue.length;
    }
    return total;
  }

  /**
   * Get queue status
   */
  getQueueStatus(): { totalQueued: number; keyCount: number; queuesByKey: Map<string, number> } {
    const queuesByKey = new Map<string, number>();
    for (const [key, queue] of this.queues) {
      queuesByKey.set(key, queue.length);
    }

    return {
      totalQueued: this.getTotalQueueSize(),
      keyCount: this.queues.size,
      queuesByKey
    };
  }
}

/**
 * Bulkhead pattern for resource isolation
 */
class Bulkhead extends EventEmitter {
  private config: BulkheadConfig;
  private activeCount: number = 0;
  private queue: Array<{
    resolve: () => void;
    reject: (error: Error) => void;
    timeout: NodeJS.Timeout;
  }> = [];

  constructor(config: BulkheadConfig) {
    super();
    this.config = config;
  }

  /**
   * Execute function within bulkhead
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    // Wait for permit
    await this.acquirePermit();

    try {
      const result = await fn();
      return result;
    } finally {
      this.releasePermit();
    }
  }

  private acquirePermit(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.activeCount < this.config.maxConcurrent) {
        this.activeCount++;
        this.emit('permitAcquired', {
          active: this.activeCount,
          queued: this.queue.length
        });
        resolve();
      } else if (this.queue.length < this.config.maxQueue) {
        // Add to queue with timeout
        const timeout = setTimeout(() => {
          const index = this.queue.findIndex(item => item.timeout === timeout);
          if (index !== -1) {
            this.queue.splice(index, 1);
            reject(new Error(`Bulkhead ${this.config.name} queue timeout`));
          }
        }, this.config.queueTimeout);

        this.queue.push({ resolve, reject, timeout });
        this.emit('queued', {
          active: this.activeCount,
          queued: this.queue.length
        });
      } else {
        reject(new Error(`Bulkhead ${this.config.name} queue full`));
      }
    });
  }

  private releasePermit(): void {
    this.activeCount--;

    if (this.queue.length > 0) {
      const next = this.queue.shift()!;
      clearTimeout(next.timeout);
      this.activeCount++;
      next.resolve();
      this.emit('dequeuedAndAcquired', {
        active: this.activeCount,
        queued: this.queue.length
      });
    } else {
      this.emit('permitReleased', {
        active: this.activeCount,
        queued: this.queue.length
      });
    }
  }

  /**
   * Get bulkhead status
   */
  getStatus(): { active: number; queued: number; available: number } {
    return {
      active: this.activeCount,
      queued: this.queue.length,
      available: this.config.maxConcurrent - this.activeCount
    };
  }
}

/**
 * Retry policy with exponential backoff
 */
class RetryPolicy {
  private config: RetryConfig;

  constructor(config: RetryConfig) {
    this.config = config;
  }

  /**
   * Execute function with retry policy
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        // Check if error is retryable
        if (!this.isRetryable(lastError)) {
          throw lastError;
        }

        // Don't delay after last attempt
        if (attempt < this.config.maxRetries) {
          const delay = this.calculateDelay(attempt);
          await this.sleep(delay);
        }
      }
    }

    throw lastError || new Error('Max retries exceeded');
  }

  private isRetryable(error: Error): boolean {
    return this.config.retryableErrors.some(pattern =>
      error.message.includes(pattern) || error.name.includes(pattern)
    );
  }

  private calculateDelay(attempt: number): number {
    // Exponential backoff with jitter
    const exponentialDelay = this.config.initialDelay *
      Math.pow(this.config.backoffMultiplier, attempt);

    const cappedDelay = Math.min(exponentialDelay, this.config.maxDelay);

    // Add jitter to prevent thundering herd
    const jitter = cappedDelay * this.config.jitterFactor * Math.random();

    return cappedDelay + jitter;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Fallback handler
 */
class FallbackHandler<T> {
  private config: FallbackConfig<T>;
  private cache?: { value: T; timestamp: number };

  constructor(config: FallbackConfig<T>) {
    this.config = config;
  }

  /**
   * Execute with fallback
   */
  async execute(primaryFn: () => Promise<T>): Promise<T> {
    try {
      // Try primary function with timeout
      const result = await this.withTimeout(primaryFn(), this.config.timeout);

      // Cache result if caching is enabled
      if (this.config.cacheDuration) {
        this.cache = {
          value: result,
          timestamp: Date.now()
        };
      }

      return result;
    } catch (error) {
      // Check cache first
      if (this.cache && this.config.cacheDuration) {
        const cacheAge = Date.now() - this.cache.timestamp;
        if (cacheAge < this.config.cacheDuration) {
          return this.cache.value;
        }
      }

      // Execute fallback
      return await this.config.handler();
    }
  }

  private withTimeout<R>(promise: Promise<R>, timeoutMs: number): Promise<R> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Operation timed out'));
      }, timeoutMs);

      promise
        .then(result => {
          clearTimeout(timeout);
          resolve(result);
        })
        .catch(error => {
          clearTimeout(timeout);
          reject(error);
        });
    });
  }
}

/**
 * Main Resilience Manager - orchestrates all resilience patterns
 */
export class ResilienceManager extends EventEmitter {
  private circuitBreakers: Map<string, CircuitBreaker> = new Map();
  private rateLimiters: Map<string, TokenBucketRateLimiter | SlidingWindowRateLimiter> = new Map();
  private bulkheads: Map<string, Bulkhead> = new Map();
  private retryPolicies: Map<string, RetryPolicy> = new Map();

  constructor() {
    super();
  }

  /**
   * Create a circuit breaker
   */
  createCircuitBreaker(config: CircuitBreakerConfig): CircuitBreaker {
    const cb = new CircuitBreaker(config);

    // Wire up events
    cb.on('stateChange', event => this.emit('circuitStateChange', event));
    cb.on('failure', event => this.emit('circuitFailure', event));
    cb.on('rejected', event => this.emit('circuitRejected', event));

    this.circuitBreakers.set(config.name, cb);
    return cb;
  }

  /**
   * Create a rate limiter
   */
  createRateLimiter(config: RateLimitConfig): TokenBucketRateLimiter | SlidingWindowRateLimiter {
    let limiter: TokenBucketRateLimiter | SlidingWindowRateLimiter;

    if (config.strategy === RateLimitStrategy.TOKEN_BUCKET) {
      limiter = new TokenBucketRateLimiter(
        config.burstSize || config.maxRequests,
        config.refillRate || config.maxRequests / (config.windowMs / 1000)
      );
    } else {
      limiter = new SlidingWindowRateLimiter(config.maxRequests, config.windowMs);
    }

    this.rateLimiters.set(config.name, limiter);
    return limiter;
  }

  /**
   * Create a bulkhead
   */
  createBulkhead(config: BulkheadConfig): Bulkhead {
    const bulkhead = new Bulkhead(config);

    bulkhead.on('queued', event => this.emit('bulkheadQueued', { ...event, name: config.name }));
    bulkhead.on('permitAcquired', event => this.emit('bulkheadAcquired', { ...event, name: config.name }));

    this.bulkheads.set(config.name, bulkhead);
    return bulkhead;
  }

  /**
   * Create a retry policy
   */
  createRetryPolicy(name: string, config: RetryConfig): RetryPolicy {
    const policy = new RetryPolicy(config);
    this.retryPolicies.set(name, policy);
    return policy;
  }

  /**
   * Get circuit breaker by name
   */
  getCircuitBreaker(name: string): CircuitBreaker | undefined {
    return this.circuitBreakers.get(name);
  }

  /**
   * Get rate limiter by name
   */
  getRateLimiter(name: string): TokenBucketRateLimiter | SlidingWindowRateLimiter | undefined {
    return this.rateLimiters.get(name);
  }

  /**
   * Get bulkhead by name
   */
  getBulkhead(name: string): Bulkhead | undefined {
    return this.bulkheads.get(name);
  }

  /**
   * Execute with full resilience stack
   */
  async executeWithResilience<T>(
    fn: () => Promise<T>,
    options: {
      circuitBreaker?: string;
      rateLimiter?: { name: string; key: string };
      bulkhead?: string;
      retryPolicy?: string;
      fallback?: FallbackConfig<T>;
    }
  ): Promise<T> {
    let executor = fn;

    // Wrap with fallback (innermost)
    if (options.fallback) {
      const fallbackHandler = new FallbackHandler(options.fallback);
      const originalExecutor = executor;
      executor = () => fallbackHandler.execute(originalExecutor);
    }

    // Wrap with retry policy
    if (options.retryPolicy) {
      const policy = this.retryPolicies.get(options.retryPolicy);
      if (policy) {
        const originalExecutor = executor;
        executor = () => policy.execute(originalExecutor);
      }
    }

    // Wrap with circuit breaker
    if (options.circuitBreaker) {
      const cb = this.circuitBreakers.get(options.circuitBreaker);
      if (cb) {
        const originalExecutor = executor;
        executor = () => cb.execute(originalExecutor);
      }
    }

    // Wrap with bulkhead
    if (options.bulkhead) {
      const bulkhead = this.bulkheads.get(options.bulkhead);
      if (bulkhead) {
        const originalExecutor = executor;
        executor = () => bulkhead.execute(originalExecutor);
      }
    }

    // Check rate limit first (outermost)
    if (options.rateLimiter) {
      const limiter = this.rateLimiters.get(options.rateLimiter.name);
      if (limiter) {
        let result: RateLimitResult;

        if (limiter instanceof TokenBucketRateLimiter) {
          result = limiter.tryConsume(options.rateLimiter.key);
        } else {
          result = limiter.tryRequest(options.rateLimiter.key);
        }

        if (!result.allowed) {
          this.emit('rateLimited', {
            limiter: options.rateLimiter.name,
            key: options.rateLimiter.key,
            retryAfter: result.retryAfter
          });
          throw new Error(`Rate limit exceeded. Retry after ${result.retryAfter}ms`);
        }
      }
    }

    return await executor();
  }

  /**
   * Get status of all resilience components
   */
  getStatus(): {
    circuitBreakers: Map<string, any>;
    bulkheads: Map<string, any>;
  } {
    const cbStatus = new Map<string, any>();
    for (const [name, cb] of this.circuitBreakers) {
      cbStatus.set(name, cb.getStatus());
    }

    const bulkheadStatus = new Map<string, any>();
    for (const [name, bulkhead] of this.bulkheads) {
      bulkheadStatus.set(name, bulkhead.getStatus());
    }

    return {
      circuitBreakers: cbStatus,
      bulkheads: bulkheadStatus
    };
  }
}

// Export all components
export {
  CircuitState,
  RateLimitStrategy,
  CircuitBreaker,
  TokenBucketRateLimiter,
  SlidingWindowRateLimiter,
  FairQueueRateLimiter,
  Bulkhead,
  RetryPolicy,
  FallbackHandler
};

// Default configurations
export const defaultCircuitBreakerConfig: CircuitBreakerConfig = {
  name: 'default',
  failureThreshold: 50, // 50% failure rate
  successThreshold: 5, // 5 successes to close
  timeout: 30000, // 30 seconds
  halfOpenMaxRequests: 3,
  monitoringWindow: 60000, // 1 minute
  volumeThreshold: 20 // Min 20 requests
};

export const defaultRateLimitConfig: RateLimitConfig = {
  name: 'default',
  strategy: RateLimitStrategy.TOKEN_BUCKET,
  maxRequests: 1000,
  windowMs: 60000,
  burstSize: 100,
  refillRate: 50, // 50 tokens/second
  fairnessEnabled: true
};

export const defaultRetryConfig: RetryConfig = {
  maxRetries: 3,
  initialDelay: 100,
  maxDelay: 5000,
  backoffMultiplier: 2,
  jitterFactor: 0.1,
  retryableErrors: ['ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED', 'NetworkError']
};
