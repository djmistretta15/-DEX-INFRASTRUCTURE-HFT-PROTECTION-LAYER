/**
 * Market Maker Trading Simulation
 *
 * Simulates high-frequency market making strategies to test:
 * - Order placement and cancellation speed
 * - Spread management
 * - Inventory risk management
 * - MEV resistance under real trading conditions
 */

import { ethers } from 'ethers';

interface MarketMakerConfig {
  spread: number; // Basis points
  orderSize: bigint;
  maxInventory: bigint;
  refreshRate: number; // milliseconds
  numLevels: number; // Depth of orders on each side
}

interface Position {
  baseBalance: bigint;
  quoteBalance: bigint;
  pnl: bigint;
}

export class MarketMakerSimulation {
  private provider: ethers.Provider;
  private signer: ethers.Signer;
  private orderbook: ethers.Contract;
  private config: MarketMakerConfig;
  private position: Position;
  private activeOrders: Map<string, any> = new Map();
  private isRunning: boolean = false;

  constructor(
    provider: ethers.Provider,
    signer: ethers.Signer,
    orderbookAddress: string,
    config: MarketMakerConfig
  ) {
    this.provider = provider;
    this.signer = signer;
    this.orderbook = new ethers.Contract(
      orderbookAddress,
      [
        'function placeLimitOrder(address,address,uint8,uint256,uint256) returns (bytes32)',
        'function cancelOrder(bytes32)',
        'function getOrderbook(address,address,uint256) view returns (uint256[],uint256[],uint256[],uint256[])',
      ],
      signer
    );
    this.config = config;
    this.position = {
      baseBalance: 0n,
      quoteBalance: 0n,
      pnl: 0n,
    };
  }

  /**
   * Start market making
   */
  async start(): Promise<void> {
    console.log('🤖 Starting Market Maker Simulation...');
    console.log(`  Spread: ${this.config.spread} bps`);
    console.log(`  Order Size: ${ethers.formatUnits(this.config.orderSize, 6)} USDC`);
    console.log(`  Refresh Rate: ${this.config.refreshRate}ms`);
    console.log(`  Levels: ${this.config.numLevels}\n`);

    this.isRunning = true;

    // Start event listeners
    this.listenToTrades();

    // Main market making loop
    while (this.isRunning) {
      try {
        await this.updateQuotes();
        await this.sleep(this.config.refreshRate);
      } catch (error) {
        console.error('Error in market making loop:', error);
        await this.sleep(1000);
      }
    }
  }

  /**
   * Stop market making
   */
  async stop(): Promise<void> {
    console.log('\n🛑 Stopping Market Maker...');
    this.isRunning = false;

    // Cancel all active orders
    await this.cancelAllOrders();

    console.log(`\n📊 Final Position:`);
    console.log(`  Base: ${ethers.formatEther(this.position.baseBalance)} WETH`);
    console.log(`  Quote: ${ethers.formatUnits(this.position.quoteBalance, 6)} USDC`);
    console.log(`  PnL: ${ethers.formatUnits(this.position.pnl, 6)} USDC\n`);
  }

  /**
   * Update quotes (cancel-replace strategy)
   */
  private async updateQuotes(): Promise<void> {
    // Get current mid-price
    const midPrice = await this.getMidPrice();

    if (midPrice === 0n) {
      console.log('  ⚠️  No market data available');
      return;
    }

    // Calculate spreads
    const spreadAmount = (midPrice * BigInt(this.config.spread)) / 10000n;

    // Check inventory and adjust quotes
    const inventorySkew = this.calculateInventorySkew();

    // Cancel old orders
    await this.cancelAllOrders();

    // Place new orders
    for (let level = 1; level <= this.config.numLevels; level++) {
      const levelSpread = spreadAmount * BigInt(level);

      // Adjust for inventory skew
      const bidPrice = midPrice - levelSpread - inventorySkew;
      const askPrice = midPrice + levelSpread + inventorySkew;

      // Place buy order
      const buyOrderId = await this.placeBuyOrder(bidPrice, this.config.orderSize);
      if (buyOrderId) {
        this.activeOrders.set(buyOrderId, {
          side: 'buy',
          price: bidPrice,
          size: this.config.orderSize,
        });
      }

      // Place sell order
      const sellOrderId = await this.placeSellOrder(askPrice, this.config.orderSize);
      if (sellOrderId) {
        this.activeOrders.set(sellOrderId, {
          side: 'sell',
          price: askPrice,
          size: this.config.orderSize,
        });
      }
    }

    console.log(
      `  📈 Updated quotes: Bid ${ethers.formatEther(midPrice - spreadAmount)} | ` +
      `Ask ${ethers.formatEther(midPrice + spreadAmount)} | ` +
      `Active orders: ${this.activeOrders.size}`
    );
  }

  /**
   * Calculate inventory skew adjustment
   */
  private calculateInventorySkew(): bigint {
    const targetInventory = this.config.maxInventory / 2n;
    const currentInventory = this.position.baseBalance;

    const skew = currentInventory - targetInventory;

    // Skew quotes based on inventory (if long, widen asks and tighten bids)
    return (skew * 100n) / this.config.maxInventory;
  }

  /**
   * Get mid-price from orderbook
   */
  private async getMidPrice(): Promise<bigint> {
    try {
      const [bidPrices, , askPrices] = await this.orderbook.getOrderbook(
        '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC
        '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', // WETH
        10
      );

      if (bidPrices.length === 0 || askPrices.length === 0) {
        return 0n;
      }

      const bestBid = bidPrices[0];
      const bestAsk = askPrices[0];

      return (bestBid + bestAsk) / 2n;
    } catch (error) {
      return ethers.parseEther('2000'); // Fallback price
    }
  }

  /**
   * Place buy order
   */
  private async placeBuyOrder(price: bigint, size: bigint): Promise<string | null> {
    try {
      const tx = await this.orderbook.placeLimitOrder(
        '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC
        '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', // WETH
        0, // BUY
        price,
        size
      );

      const receipt = await tx.wait();
      const event = receipt?.logs.find((log: any) =>
        log.topics[0] === ethers.id('OrderPlaced(bytes32,address,uint8,uint256,uint256)')
      );

      return event?.topics[1] || null;
    } catch (error) {
      console.error('  ❌ Failed to place buy order:', error);
      return null;
    }
  }

  /**
   * Place sell order
   */
  private async placeSellOrder(price: bigint, size: bigint): Promise<string | null> {
    try {
      const tx = await this.orderbook.placeLimitOrder(
        '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
        '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
        1, // SELL
        price,
        size
      );

      const receipt = await tx.wait();
      const event = receipt?.logs.find((log: any) =>
        log.topics[0] === ethers.id('OrderPlaced(bytes32,address,uint8,uint256,uint256)')
      );

      return event?.topics[1] || null;
    } catch (error) {
      console.error('  ❌ Failed to place sell order:', error);
      return null;
    }
  }

  /**
   * Cancel all active orders
   */
  private async cancelAllOrders(): Promise<void> {
    const cancelPromises = Array.from(this.activeOrders.keys()).map(async (orderId) => {
      try {
        const tx = await this.orderbook.cancelOrder(orderId);
        await tx.wait();
      } catch (error) {
        // Order may already be filled
      }
    });

    await Promise.all(cancelPromises);
    this.activeOrders.clear();
  }

  /**
   * Listen to trade events
   */
  private listenToTrades(): void {
    this.orderbook.on(
      'TradeExecuted',
      async (tradeId: string, makerOrderId: string, takerOrderId: string, price: bigint, amount: bigint) => {
        // Check if our order was filled
        const ourOrder = this.activeOrders.get(makerOrderId);

        if (ourOrder) {
          console.log(`  ✅ Order filled: ${ourOrder.side} ${ethers.formatUnits(amount, 6)} @ ${ethers.formatEther(price)}`);

          // Update position
          if (ourOrder.side === 'buy') {
            this.position.baseBalance += amount;
            this.position.quoteBalance -= (amount * price) / ethers.parseEther('1');
          } else {
            this.position.baseBalance -= amount;
            this.position.quoteBalance += (amount * price) / ethers.parseEther('1');
          }

          // Remove from active orders
          this.activeOrders.delete(makerOrderId);

          // Update PnL
          this.updatePnL();
        }
      }
    );
  }

  /**
   * Update PnL calculation
   */
  private updatePnL(): void {
    // Simplified PnL: quote balance + (base balance * current price)
    const midPrice = ethers.parseEther('2000'); // Would fetch real price
    const baseValue = (this.position.baseBalance * midPrice) / ethers.parseEther('1');
    const totalValue = this.position.quoteBalance + baseValue;

    this.position.pnl = totalValue;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

/**
 * Run simulation
 */
export async function runMarketMakerSimulation() {
  const provider = new ethers.JsonRpcProvider('http://localhost:8545');
  const signer = await provider.getSigner();

  const config: MarketMakerConfig = {
    spread: 10, // 10 bps (0.1%)
    orderSize: ethers.parseUnits('1000', 6), // 1000 USDC
    maxInventory: ethers.parseEther('10'), // 10 WETH
    refreshRate: 500, // 500ms
    numLevels: 5, // 5 levels on each side
  };

  const marketMaker = new MarketMakerSimulation(
    provider,
    signer,
    '0x...', // Orderbook address
    config
  );

  // Run for 5 minutes
  marketMaker.start();

  setTimeout(async () => {
    await marketMaker.stop();
  }, 5 * 60 * 1000);
}

if (require.main === module) {
  runMarketMakerSimulation().catch(console.error);
}
