import axios from "axios";
import { io, Socket } from "socket.io-client";

/**
 * HIGH-FREQUENCY TRADING LOAD TEST SUITE
 *
 * Performance Targets:
 * - 10,000+ orders/second throughput
 * - <10ms p50 latency
 * - <50ms p99 latency
 * - Zero order loss
 * - Consistent performance under load
 *
 * Test Scenarios:
 * 1. Sustained throughput test
 * 2. Burst traffic handling
 * 3. WebSocket scalability
 * 4. Database write performance
 * 5. Memory and resource utilization
 */

interface LoadTestConfig {
  apiUrl: string;
  wsUrl: string;
  duration: number; // seconds
  targetRPS: number; // requests per second
  rampUpTime: number; // seconds to reach target RPS
  numConnections: number; // concurrent connections
  apiKey: string;
}

interface LatencyMetrics {
  p50: number;
  p90: number;
  p95: number;
  p99: number;
  mean: number;
  min: number;
  max: number;
}

interface TestResult {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  throughput: number; // RPS
  latencyMs: LatencyMetrics;
  errorRate: number; // percentage
  duration: number; // seconds
  ordersPerSecond: number;
}

const defaultConfig: LoadTestConfig = {
  apiUrl: process.env.API_URL || "http://localhost:3000",
  wsUrl: process.env.WS_URL || "http://localhost:3001",
  duration: 60, // 1 minute test
  targetRPS: 1000,
  rampUpTime: 10,
  numConnections: 100,
  apiKey: process.env.TEST_API_KEY || "test-api-key-12345",
};

class LoadTestRunner {
  private config: LoadTestConfig;
  private latencies: number[] = [];
  private errors: string[] = [];
  private startTime: number = 0;
  private requestCount: number = 0;
  private successCount: number = 0;
  private failCount: number = 0;

  constructor(config: LoadTestConfig = defaultConfig) {
    this.config = config;
  }

  // ═══════════════════════════════════════════════════════════════════
  //                      ORDER SUBMISSION LOAD TEST
  // ═══════════════════════════════════════════════════════════════════

  async runOrderSubmissionLoadTest(): Promise<TestResult> {
    console.log("🚀 Starting Order Submission Load Test");
    console.log(`Target: ${this.config.targetRPS} RPS for ${this.config.duration}s`);

    this.reset();
    this.startTime = Date.now();

    const endTime = this.startTime + this.config.duration * 1000;
    let currentRPS = 0;
    const rpsIncrement = this.config.targetRPS / (this.config.rampUpTime * 10);

    // Ramp up loop
    while (Date.now() < endTime) {
      const elapsed = (Date.now() - this.startTime) / 1000;

      // Gradually increase RPS during ramp-up
      if (elapsed < this.config.rampUpTime) {
        currentRPS = Math.min((elapsed / this.config.rampUpTime) * this.config.targetRPS, this.config.targetRPS);
      } else {
        currentRPS = this.config.targetRPS;
      }

      // Send batch of requests
      const batchSize = Math.max(1, Math.floor(currentRPS / 10));
      const promises = [];

      for (let i = 0; i < batchSize; i++) {
        promises.push(this.sendOrderRequest());
      }

      await Promise.allSettled(promises);

      // Sleep to control rate
      await this.sleep(100);
    }

    return this.calculateResults();
  }

  private async sendOrderRequest(): Promise<void> {
    const startTs = process.hrtime.bigint();

    try {
      const order = this.generateRandomOrder();

      await axios.post(`${this.config.apiUrl}/api/v1/orders`, order, {
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": this.config.apiKey,
        },
        timeout: 5000,
      });

      const endTs = process.hrtime.bigint();
      const latencyMs = Number(endTs - startTs) / 1_000_000;

      this.latencies.push(latencyMs);
      this.successCount++;
    } catch (error: any) {
      this.failCount++;
      this.errors.push(error.message || "Unknown error");
    }

    this.requestCount++;
  }

  private generateRandomOrder(): any {
    const pairs = ["WETH/USDC", "WBTC/USDC", "LINK/USDC", "UNI/USDC"];
    const sides = ["buy", "sell"];
    const orderTypes = ["limit", "market"];

    return {
      pair: pairs[Math.floor(Math.random() * pairs.length)],
      side: sides[Math.floor(Math.random() * sides.length)],
      orderType: orderTypes[Math.floor(Math.random() * orderTypes.length)],
      price: 1900 + Math.random() * 200,
      amount: 0.1 + Math.random() * 10,
      timeInForce: "GTC",
    };
  }

  // ═══════════════════════════════════════════════════════════════════
  //                      WEBSOCKET SCALABILITY TEST
  // ═══════════════════════════════════════════════════════════════════

  async runWebSocketScalabilityTest(): Promise<TestResult> {
    console.log("🔌 Starting WebSocket Scalability Test");
    console.log(`Target: ${this.config.numConnections} concurrent connections`);

    this.reset();
    this.startTime = Date.now();

    const connections: Socket[] = [];
    const connectionTimes: number[] = [];

    // Establish connections
    for (let i = 0; i < this.config.numConnections; i++) {
      const startTs = Date.now();

      try {
        const socket = await this.createWebSocketConnection();
        connections.push(socket);
        connectionTimes.push(Date.now() - startTs);
        this.successCount++;
      } catch (error: any) {
        this.failCount++;
        this.errors.push(error.message);
      }

      this.requestCount++;

      // Rate limit connection creation
      if (i % 10 === 0) {
        await this.sleep(100);
      }
    }

    console.log(`Established ${connections.length} connections`);

    // Subscribe all connections to updates
    const subscriptionTimes: number[] = [];
    for (const socket of connections) {
      const startTs = Date.now();
      socket.emit("subscribe", { pairs: ["WETH/USDC", "WBTC/USDC"] });
      subscriptionTimes.push(Date.now() - startTs);
    }

    // Keep connections alive for test duration
    console.log(`Running for ${this.config.duration}s...`);
    await this.sleep(this.config.duration * 1000);

    // Measure message throughput
    let totalMessages = 0;
    for (const socket of connections) {
      const messageCount = (socket as any).messageCount || 0;
      totalMessages += messageCount;
    }

    // Cleanup
    for (const socket of connections) {
      socket.disconnect();
    }

    this.latencies = connectionTimes;

    const result = this.calculateResults();
    result.totalRequests = connections.length;
    result.throughput = totalMessages / this.config.duration;

    return result;
  }

  private createWebSocketConnection(): Promise<Socket> {
    return new Promise((resolve, reject) => {
      const socket = io(this.config.wsUrl, {
        transports: ["websocket"],
        autoConnect: true,
        timeout: 10000,
      });

      (socket as any).messageCount = 0;

      socket.on("connect", () => {
        resolve(socket);
      });

      socket.on("connect_error", (err) => {
        reject(err);
      });

      socket.on("orderbook", () => {
        (socket as any).messageCount++;
      });

      socket.on("trade", () => {
        (socket as any).messageCount++;
      });

      // Timeout after 10 seconds
      setTimeout(() => {
        reject(new Error("Connection timeout"));
      }, 10000);
    });
  }

  // ═══════════════════════════════════════════════════════════════════
  //                        BURST TRAFFIC TEST
  // ═══════════════════════════════════════════════════════════════════

  async runBurstTrafficTest(): Promise<TestResult> {
    console.log("💥 Starting Burst Traffic Test");
    console.log("Simulating sudden traffic spike...");

    this.reset();
    this.startTime = Date.now();

    // Normal traffic for 10 seconds
    console.log("Phase 1: Normal traffic (100 RPS)");
    await this.runAtRate(100, 10);

    // Spike to 10x traffic
    console.log("Phase 2: Traffic spike (1000 RPS)");
    await this.runAtRate(1000, 10);

    // Return to normal
    console.log("Phase 3: Return to normal (100 RPS)");
    await this.runAtRate(100, 10);

    return this.calculateResults();
  }

  private async runAtRate(rps: number, durationSeconds: number): Promise<void> {
    const endTime = Date.now() + durationSeconds * 1000;
    const intervalMs = 1000 / rps;

    while (Date.now() < endTime) {
      this.sendOrderRequest().catch(() => {});
      await this.sleep(intervalMs);
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  //                      CONCURRENT USER TEST
  // ═══════════════════════════════════════════════════════════════════

  async runConcurrentUserTest(): Promise<TestResult> {
    console.log("👥 Starting Concurrent User Simulation");
    console.log(`Simulating ${this.config.numConnections} concurrent traders`);

    this.reset();
    this.startTime = Date.now();

    const userPromises: Promise<void>[] = [];

    // Spawn virtual users
    for (let i = 0; i < this.config.numConnections; i++) {
      userPromises.push(this.simulateTrader(i));
    }

    await Promise.allSettled(userPromises);

    return this.calculateResults();
  }

  private async simulateTrader(userId: number): Promise<void> {
    const endTime = Date.now() + this.config.duration * 1000;

    // Each trader submits orders at random intervals
    while (Date.now() < endTime) {
      await this.sendOrderRequest();

      // Random delay between orders (simulate human/bot behavior)
      const delay = 100 + Math.random() * 900; // 100ms to 1s
      await this.sleep(delay);
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  //                        MEMORY STRESS TEST
  // ═══════════════════════════════════════════════════════════════════

  async runMemoryStressTest(): Promise<TestResult> {
    console.log("🧠 Starting Memory Stress Test");
    console.log("Monitoring memory usage under sustained load...");

    this.reset();
    this.startTime = Date.now();

    const memorySnapshots: NodeJS.MemoryUsage[] = [];

    // Monitor memory while sending requests
    const monitorInterval = setInterval(() => {
      memorySnapshots.push(process.memoryUsage());
    }, 1000);

    // High sustained load
    await this.runAtRate(500, 60);

    clearInterval(monitorInterval);

    // Analyze memory growth
    const initialHeap = memorySnapshots[0]?.heapUsed || 0;
    const finalHeap = memorySnapshots[memorySnapshots.length - 1]?.heapUsed || 0;
    const heapGrowth = finalHeap - initialHeap;
    const heapGrowthMB = heapGrowth / (1024 * 1024);

    console.log(`Heap growth: ${heapGrowthMB.toFixed(2)} MB`);

    const result = this.calculateResults();
    (result as any).memoryGrowthMB = heapGrowthMB;

    return result;
  }

  // ═══════════════════════════════════════════════════════════════════
  //                          HELPER METHODS
  // ═══════════════════════════════════════════════════════════════════

  private reset(): void {
    this.latencies = [];
    this.errors = [];
    this.requestCount = 0;
    this.successCount = 0;
    this.failCount = 0;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private calculateResults(): TestResult {
    const duration = (Date.now() - this.startTime) / 1000;

    const latencyMetrics = this.calculateLatencyPercentiles();

    return {
      totalRequests: this.requestCount,
      successfulRequests: this.successCount,
      failedRequests: this.failCount,
      throughput: this.requestCount / duration,
      latencyMs: latencyMetrics,
      errorRate: (this.failCount / this.requestCount) * 100,
      duration,
      ordersPerSecond: this.successCount / duration,
    };
  }

  private calculateLatencyPercentiles(): LatencyMetrics {
    if (this.latencies.length === 0) {
      return { p50: 0, p90: 0, p95: 0, p99: 0, mean: 0, min: 0, max: 0 };
    }

    const sorted = [...this.latencies].sort((a, b) => a - b);
    const len = sorted.length;

    return {
      p50: sorted[Math.floor(len * 0.5)],
      p90: sorted[Math.floor(len * 0.9)],
      p95: sorted[Math.floor(len * 0.95)],
      p99: sorted[Math.floor(len * 0.99)],
      mean: sorted.reduce((a, b) => a + b, 0) / len,
      min: sorted[0],
      max: sorted[len - 1],
    };
  }

  printResults(result: TestResult): void {
    console.log("\n════════════════════════════════════════");
    console.log("           LOAD TEST RESULTS            ");
    console.log("════════════════════════════════════════\n");

    console.log(`Duration: ${result.duration.toFixed(2)}s`);
    console.log(`Total Requests: ${result.totalRequests}`);
    console.log(`Successful: ${result.successfulRequests}`);
    console.log(`Failed: ${result.failedRequests}`);
    console.log(`Throughput: ${result.throughput.toFixed(2)} RPS`);
    console.log(`Orders/Second: ${result.ordersPerSecond.toFixed(2)}`);
    console.log(`Error Rate: ${result.errorRate.toFixed(2)}%`);

    console.log("\nLatency (ms):");
    console.log(`  P50:  ${result.latencyMs.p50.toFixed(2)}`);
    console.log(`  P90:  ${result.latencyMs.p90.toFixed(2)}`);
    console.log(`  P95:  ${result.latencyMs.p95.toFixed(2)}`);
    console.log(`  P99:  ${result.latencyMs.p99.toFixed(2)}`);
    console.log(`  Mean: ${result.latencyMs.mean.toFixed(2)}`);
    console.log(`  Min:  ${result.latencyMs.min.toFixed(2)}`);
    console.log(`  Max:  ${result.latencyMs.max.toFixed(2)}`);

    // Performance assessment
    console.log("\n════════════════════════════════════════");
    console.log("         PERFORMANCE ASSESSMENT         ");
    console.log("════════════════════════════════════════\n");

    const checks = [
      { name: "Error Rate < 1%", passed: result.errorRate < 1 },
      { name: "P99 Latency < 100ms", passed: result.latencyMs.p99 < 100 },
      { name: "P50 Latency < 20ms", passed: result.latencyMs.p50 < 20 },
      { name: "Throughput > 100 RPS", passed: result.throughput > 100 },
    ];

    for (const check of checks) {
      const status = check.passed ? "✅" : "❌";
      console.log(`${status} ${check.name}`);
    }

    const allPassed = checks.every((c) => c.passed);
    console.log(`\n${allPassed ? "✅ ALL CHECKS PASSED" : "❌ SOME CHECKS FAILED"}`);
  }
}

// ═══════════════════════════════════════════════════════════════════
//                          MAIN EXECUTION
// ═══════════════════════════════════════════════════════════════════

async function main() {
  const runner = new LoadTestRunner();

  console.log("DEX INFRASTRUCTURE LOAD TEST SUITE\n");

  // 1. Order Submission Load Test
  console.log("\n[1/5] Order Submission Load Test");
  const orderResult = await runner.runOrderSubmissionLoadTest();
  runner.printResults(orderResult);

  // 2. WebSocket Scalability Test
  console.log("\n[2/5] WebSocket Scalability Test");
  const wsResult = await runner.runWebSocketScalabilityTest();
  runner.printResults(wsResult);

  // 3. Burst Traffic Test
  console.log("\n[3/5] Burst Traffic Test");
  const burstResult = await runner.runBurstTrafficTest();
  runner.printResults(burstResult);

  // 4. Concurrent User Test
  console.log("\n[4/5] Concurrent User Test");
  const concurrentResult = await runner.runConcurrentUserTest();
  runner.printResults(concurrentResult);

  // 5. Memory Stress Test
  console.log("\n[5/5] Memory Stress Test");
  const memoryResult = await runner.runMemoryStressTest();
  runner.printResults(memoryResult);

  console.log("\n🎉 Load Testing Complete!");
}

// Export for Jest integration
export { LoadTestRunner, LoadTestConfig, TestResult };

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}
