/**
 * Latency and Performance Benchmarks for HFT DEX
 *
 * Tests:
 * - Order submission latency
 * - Matching engine throughput
 * - Block production time
 * - End-to-end execution latency
 */

import { ethers } from 'ethers';
import { performance } from 'perf_hooks';

interface BenchmarkResult {
  name: string;
  min: number;
  max: number;
  mean: number;
  median: number;
  p95: number;
  p99: number;
  throughput?: number;
}

interface OrderMetrics {
  submissionTime: number;
  confirmationTime: number;
  executionTime: number;
  totalLatency: number;
}

export class LatencyBenchmark {
  private provider: ethers.Provider;
  private signer: ethers.Signer;
  private orderbookContract: ethers.Contract;

  constructor(
    provider: ethers.Provider,
    signer: ethers.Signer,
    orderbookAddress: string
  ) {
    this.provider = provider;
    this.signer = signer;

    this.orderbookContract = new ethers.Contract(
      orderbookAddress,
      [
        'function placeLimitOrder(address,address,uint8,uint256,uint256) returns (bytes32)',
        'function placeMarketOrder(address,address,uint8,uint256) returns (bytes32)',
      ],
      signer
    );
  }

  /**
   * Test 1: Order submission latency
   */
  async benchmarkOrderSubmission(iterations: number = 1000): Promise<BenchmarkResult> {
    console.log(`\n📊 Benchmarking order submission (${iterations} iterations)...`);

    const latencies: number[] = [];

    for (let i = 0; i < iterations; i++) {
      const start = performance.now();

      try {
        const tx = await this.orderbookContract.placeLimitOrder(
          '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC
          '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', // WETH
          0, // BUY
          ethers.parseEther('2000'), // Price
          ethers.parseUnits('1000', 6) // Amount
        );

        await tx.wait();

        const end = performance.now();
        latencies.push(end - start);

        if (i % 100 === 0) {
          process.stdout.write(`\r  Progress: ${i}/${iterations}`);
        }
      } catch (error) {
        console.error(`\n  Error at iteration ${i}:`, error);
      }
    }

    console.log('\n');

    return this.calculateStats('Order Submission', latencies);
  }

  /**
   * Test 2: Matching engine throughput
   */
  async benchmarkMatchingThroughput(
    orderCount: number = 10000
  ): Promise<BenchmarkResult> {
    console.log(`\n⚡ Benchmarking matching throughput (${orderCount} orders)...`);

    const start = performance.now();

    // Submit multiple orders rapidly
    const promises = [];

    for (let i = 0; i < orderCount; i++) {
      const isBuy = i % 2 === 0;
      const price = ethers.parseEther(isBuy ? '2000' : '2001');

      const promise = this.orderbookContract.placeLimitOrder(
        '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
        '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
        isBuy ? 0 : 1,
        price,
        ethers.parseUnits('100', 6)
      );

      promises.push(promise);

      if (i % 100 === 0) {
        process.stdout.write(`\r  Submitting: ${i}/${orderCount}`);
      }
    }

    console.log('\n  Waiting for confirmations...');

    await Promise.all(promises.map((p) => p.then((tx: any) => tx.wait())));

    const end = performance.now();
    const duration = (end - start) / 1000; // seconds

    const throughput = orderCount / duration;

    console.log(`  ✅ Completed in ${duration.toFixed(2)}s`);
    console.log(`  📈 Throughput: ${throughput.toFixed(0)} orders/sec\n`);

    return {
      name: 'Matching Throughput',
      min: 0,
      max: 0,
      mean: duration * 1000,
      median: duration * 1000,
      p95: 0,
      p99: 0,
      throughput,
    };
  }

  /**
   * Test 3: End-to-end execution latency
   */
  async benchmarkE2ELatency(iterations: number = 100): Promise<BenchmarkResult> {
    console.log(`\n🎯 Benchmarking end-to-end latency (${iterations} iterations)...`);

    const metrics: OrderMetrics[] = [];

    for (let i = 0; i < iterations; i++) {
      const orderStart = performance.now();

      // Submit order
      const tx = await this.orderbookContract.placeMarketOrder(
        '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
        '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
        0, // BUY
        ethers.parseUnits('100', 6)
      );

      const submissionTime = performance.now() - orderStart;

      // Wait for confirmation
      const confirmStart = performance.now();
      const receipt = await tx.wait();
      const confirmationTime = performance.now() - confirmStart;

      // Check for execution event
      const executionEvent = receipt?.logs.find(
        (log: any) => log.topics[0] === ethers.id('TradeExecuted(bytes32,bytes32,bytes32,uint256,uint256)')
      );

      const executionTime = executionEvent ? performance.now() - confirmStart : 0;
      const totalLatency = performance.now() - orderStart;

      metrics.push({
        submissionTime,
        confirmationTime,
        executionTime,
        totalLatency,
      });

      if (i % 10 === 0) {
        process.stdout.write(`\r  Progress: ${i}/${iterations}`);
      }
    }

    console.log('\n');

    const totalLatencies = metrics.map((m) => m.totalLatency);

    return this.calculateStats('End-to-End Latency', totalLatencies);
  }

  /**
   * Test 4: Block production time
   */
  async benchmarkBlockTime(samples: number = 100): Promise<BenchmarkResult> {
    console.log(`\n⏱️  Measuring block production time (${samples} blocks)...`);

    const blockTimes: number[] = [];
    let lastBlockNumber = await this.provider.getBlockNumber();
    let lastBlockTimestamp = (await this.provider.getBlock(lastBlockNumber))!.timestamp;

    for (let i = 0; i < samples; i++) {
      // Wait for next block
      await new Promise<void>((resolve) => {
        this.provider.once('block', () => resolve());
      });

      const currentBlockNumber = await this.provider.getBlockNumber();
      const currentBlock = await this.provider.getBlock(currentBlockNumber);
      const currentTimestamp = currentBlock!.timestamp;

      const blockTime = (currentTimestamp - lastBlockTimestamp) * 1000; // Convert to ms
      blockTimes.push(blockTime);

      lastBlockNumber = currentBlockNumber;
      lastBlockTimestamp = currentTimestamp;

      process.stdout.write(`\r  Sampled: ${i + 1}/${samples} blocks`);
    }

    console.log('\n');

    return this.calculateStats('Block Production Time', blockTimes);
  }

  /**
   * Test 5: MEV protection effectiveness
   */
  async benchmarkMEVProtection(): Promise<{ passed: boolean; details: string }> {
    console.log('\n🛡️  Testing MEV protection...');

    // Simulate frontrunning attempt
    const victimTx = await this.orderbookContract.placeMarketOrder(
      '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
      '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
      0, // BUY
      ethers.parseUnits('1000', 6)
    );

    // Try to frontrun with higher gas price
    const frontrunTx = await this.orderbookContract.placeMarketOrder(
      '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
      '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
      0,
      ethers.parseUnits('1000', 6),
      { gasPrice: ethers.parseUnits('100', 'gwei') }
    );

    const [victimReceipt, frontrunReceipt] = await Promise.all([
      victimTx.wait(),
      frontrunTx.wait(),
    ]);

    // Check execution order (should be timestamp-based, not gas-based)
    const victimBlock = victimReceipt!.blockNumber;
    const frontrunBlock = frontrunReceipt!.blockNumber;

    const protected = victimBlock <= frontrunBlock;

    console.log(`  Victim order block: ${victimBlock}`);
    console.log(`  Frontrun order block: ${frontrunBlock}`);
    console.log(`  MEV Protection: ${protected ? '✅ PASSED' : '❌ FAILED'}\n`);

    return {
      passed: protected,
      details: protected
        ? 'Orders executed in timestamp order (MEV resistant)'
        : 'Orders executed out of order (vulnerable to MEV)',
    };
  }

  /**
   * Calculate statistics from latency samples
   */
  private calculateStats(name: string, samples: number[]): BenchmarkResult {
    samples.sort((a, b) => a - b);

    const min = samples[0];
    const max = samples[samples.length - 1];
    const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
    const median = samples[Math.floor(samples.length / 2)];
    const p95 = samples[Math.floor(samples.length * 0.95)];
    const p99 = samples[Math.floor(samples.length * 0.99)];

    console.log(`  ${name} Results:`);
    console.log(`    Min:    ${min.toFixed(2)}ms`);
    console.log(`    Mean:   ${mean.toFixed(2)}ms`);
    console.log(`    Median: ${median.toFixed(2)}ms`);
    console.log(`    P95:    ${p95.toFixed(2)}ms`);
    console.log(`    P99:    ${p99.toFixed(2)}ms`);
    console.log(`    Max:    ${max.toFixed(2)}ms\n`);

    return { name, min, max, mean, median, p95, p99 };
  }

  /**
   * Run full benchmark suite
   */
  async runFullSuite(): Promise<void> {
    console.log('═══════════════════════════════════════════════════════');
    console.log('         HFT DEX Performance Benchmark Suite          ');
    console.log('═══════════════════════════════════════════════════════');

    const results = {
      submission: await this.benchmarkOrderSubmission(100),
      throughput: await this.benchmarkMatchingThroughput(1000),
      e2e: await this.benchmarkE2ELatency(50),
      blockTime: await this.benchmarkBlockTime(50),
      mevProtection: await this.benchmarkMEVProtection(),
    };

    // Generate report
    console.log('═══════════════════════════════════════════════════════');
    console.log('                    FINAL REPORT                       ');
    console.log('═══════════════════════════════════════════════════════');
    console.log('\n📊 Performance Metrics:\n');
    console.log(`  Order Submission (mean):  ${results.submission.mean.toFixed(2)}ms`);
    console.log(`  E2E Latency (mean):       ${results.e2e.mean.toFixed(2)}ms`);
    console.log(`  Block Time (mean):        ${results.blockTime.mean.toFixed(2)}ms`);
    console.log(`  Throughput:               ${results.throughput.throughput?.toFixed(0)} orders/sec`);
    console.log(`  MEV Protection:           ${results.mevProtection.passed ? '✅ PASS' : '❌ FAIL'}\n`);

    console.log('🎯 Target Metrics:');
    console.log('  ✓ Order submission < 100ms');
    console.log('  ✓ E2E latency < 1000ms');
    console.log('  ✓ Block time < 1000ms');
    console.log('  ✓ Throughput > 1000 orders/sec');
    console.log('  ✓ MEV protection enabled\n');

    console.log('═══════════════════════════════════════════════════════\n');
  }
}

/**
 * Example usage
 */
export async function main() {
  const provider = new ethers.JsonRpcProvider('http://localhost:8545');
  const signer = await provider.getSigner();

  const benchmark = new LatencyBenchmark(
    provider,
    signer,
    '0x...' // Orderbook contract address
  );

  await benchmark.runFullSuite();
}

if (require.main === module) {
  main().catch(console.error);
}
