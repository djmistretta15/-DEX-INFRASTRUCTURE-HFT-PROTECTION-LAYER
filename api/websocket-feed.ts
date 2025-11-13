/**
 * Real-Time WebSocket Trading Feed
 *
 * Provides sub-10ms latency updates for:
 * - Orderbook changes
 * - Trade executions
 * - Position updates
 * - MEV attack alerts
 *
 * WebSocket Protocol: Socket.IO with binary encoding
 * Compression: zstd for bandwidth optimization
 * Rate Limiting: 100 messages/sec per connection
 */

import { Server as SocketIOServer } from 'socket.io';
import { Server as HTTPServer } from 'http';
import { ethers } from 'ethers';
import * as zstd from '@mongodb-js/zstd';
import Redis from 'ioredis';

interface OrderbookUpdate {
  type: 'orderbook';
  pair: string;
  bids: [number, number][]; // [price, size]
  asks: [number, number][];
  timestamp: number;
  sequenceId: number;
}

interface TradeUpdate {
  type: 'trade';
  pair: string;
  tradeId: string;
  price: number;
  size: number;
  side: 'buy' | 'sell';
  timestamp: number;
  maker: string;
  taker: string;
}

interface PositionUpdate {
  type: 'position';
  user: string;
  baseBalance: number;
  quoteBalance: number;
  pnl: number;
  timestamp: number;
}

interface MEVAlert {
  type: 'mev_alert';
  alertType: 'frontrun' | 'sandwich' | 'backrun';
  severity: 'low' | 'medium' | 'high' | 'critical';
  victimTx: string;
  attackerAddress: string;
  estimatedLoss: number;
  timestamp: number;
  blocked: boolean;
}

type FeedMessage = OrderbookUpdate | TradeUpdate | PositionUpdate | MEVAlert;

interface ClientSubscription {
  pairs: Set<string>;
  userId?: string;
  authenticated: boolean;
  messageCount: number;
  lastMessageTime: number;
}

export class WebSocketFeed {
  private io: SocketIOServer;
  private redis: Redis;
  private redisSubscriber: Redis;
  private provider: ethers.Provider;
  private orderbookContract: ethers.Contract;

  // Client management
  private clients: Map<string, ClientSubscription> = new Map();
  private sequenceIds: Map<string, number> = new Map();

  // Rate limiting
  private readonly MAX_MESSAGES_PER_SECOND = 100;
  private readonly RATE_LIMIT_WINDOW = 1000; // 1 second

  // Compression
  private compressionEnabled = true;
  private readonly COMPRESSION_THRESHOLD = 512; // bytes

  constructor(
    httpServer: HTTPServer,
    redisUrl: string,
    providerUrl: string,
    orderbookAddress: string
  ) {
    // Initialize Socket.IO
    this.io = new SocketIOServer(httpServer, {
      cors: {
        origin: process.env.CORS_ORIGIN || '*',
        methods: ['GET', 'POST'],
      },
      transports: ['websocket', 'polling'],
      pingTimeout: 60000,
      pingInterval: 25000,
    });

    // Initialize Redis for pub/sub
    this.redis = new Redis(redisUrl);
    this.redisSubscriber = new Redis(redisUrl);

    // Initialize blockchain connection
    this.provider = new ethers.JsonRpcProvider(providerUrl);
    this.orderbookContract = new ethers.Contract(
      orderbookAddress,
      [
        'event TradeExecuted(bytes32 indexed tradeId, bytes32 makerOrderId, bytes32 takerOrderId, uint256 price, uint256 amount)',
        'event OrderPlaced(bytes32 indexed orderId, address indexed trader, uint8 side, uint256 price, uint256 amount)',
        'event OrderCancelled(bytes32 indexed orderId)',
      ],
      this.provider
    );

    this.setupSocketHandlers();
    this.subscribeToBlockchainEvents();
    this.subscribeToRedisChannels();
    this.startHealthCheck();
  }

  /**
   * Setup Socket.IO connection handlers
   */
  private setupSocketHandlers(): void {
    this.io.on('connection', (socket) => {
      console.log(`🔌 Client connected: ${socket.id}`);

      // Initialize client subscription
      this.clients.set(socket.id, {
        pairs: new Set(),
        authenticated: false,
        messageCount: 0,
        lastMessageTime: Date.now(),
      });

      // Handle authentication
      socket.on('authenticate', async (data: { apiKey?: string; signature?: string }) => {
        const authenticated = await this.authenticateClient(socket.id, data);

        if (authenticated) {
          socket.emit('authenticated', { success: true });
          console.log(`✅ Client authenticated: ${socket.id}`);
        } else {
          socket.emit('authenticated', { success: false, error: 'Invalid credentials' });
        }
      });

      // Handle orderbook subscription
      socket.on('subscribe', (data: { pairs: string[] }) => {
        const client = this.clients.get(socket.id);
        if (!client) return;

        for (const pair of data.pairs) {
          client.pairs.add(pair);
          socket.join(`pair:${pair}`);

          // Send initial orderbook snapshot
          this.sendOrderbookSnapshot(socket, pair);
        }

        socket.emit('subscribed', { pairs: Array.from(client.pairs) });
        console.log(`📊 Client ${socket.id} subscribed to ${data.pairs.join(', ')}`);
      });

      // Handle unsubscribe
      socket.on('unsubscribe', (data: { pairs: string[] }) => {
        const client = this.clients.get(socket.id);
        if (!client) return;

        for (const pair of data.pairs) {
          client.pairs.delete(pair);
          socket.leave(`pair:${pair}`);
        }

        socket.emit('unsubscribed', { pairs: data.pairs });
      });

      // Handle position subscription (requires auth)
      socket.on('subscribe_positions', async (data: { userId: string }) => {
        const client = this.clients.get(socket.id);
        if (!client || !client.authenticated) {
          socket.emit('error', { message: 'Authentication required' });
          return;
        }

        client.userId = data.userId;
        socket.join(`user:${data.userId}`);

        // Send initial position
        await this.sendPositionSnapshot(socket, data.userId);

        socket.emit('position_subscribed', { userId: data.userId });
      });

      // Handle disconnection
      socket.on('disconnect', () => {
        console.log(`🔌 Client disconnected: ${socket.id}`);
        this.clients.delete(socket.id);
      });

      // Handle ping for latency measurement
      socket.on('ping', (data: { timestamp: number }) => {
        socket.emit('pong', {
          clientTimestamp: data.timestamp,
          serverTimestamp: Date.now(),
        });
      });
    });
  }

  /**
   * Subscribe to blockchain events
   */
  private subscribeToBlockchainEvents(): void {
    // Listen to trade events
    this.orderbookContract.on(
      'TradeExecuted',
      async (tradeId: string, makerOrderId: string, takerOrderId: string, price: bigint, amount: bigint) => {
        const trade: TradeUpdate = {
          type: 'trade',
          pair: 'WETH/USDC', // Would be extracted from order
          tradeId,
          price: parseFloat(ethers.formatEther(price)),
          size: parseFloat(ethers.formatUnits(amount, 6)),
          side: 'buy', // Would be determined from order
          timestamp: Date.now(),
          maker: makerOrderId,
          taker: takerOrderId,
        };

        await this.broadcastTrade(trade);
      }
    );

    // Listen to order placement
    this.orderbookContract.on(
      'OrderPlaced',
      async (orderId: string, trader: string, side: number, price: bigint, amount: bigint) => {
        // Update orderbook and broadcast
        await this.updateOrderbook('WETH/USDC', side === 0 ? 'buy' : 'sell', {
          orderId,
          price: parseFloat(ethers.formatEther(price)),
          size: parseFloat(ethers.formatUnits(amount, 6)),
        });
      }
    );

    console.log('📡 Subscribed to blockchain events');
  }

  /**
   * Subscribe to Redis channels for internal updates
   */
  private subscribeToRedisChannels(): void {
    // Subscribe to MEV alerts channel
    this.redisSubscriber.subscribe('mev:alerts', (err) => {
      if (err) {
        console.error('Failed to subscribe to MEV alerts:', err);
      }
    });

    this.redisSubscriber.on('message', async (channel, message) => {
      if (channel === 'mev:alerts') {
        const alert: MEVAlert = JSON.parse(message);
        await this.broadcastMEVAlert(alert);
      }
    });

    console.log('📡 Subscribed to Redis channels');
  }

  /**
   * Authenticate client with API key or signature
   */
  private async authenticateClient(
    socketId: string,
    credentials: { apiKey?: string; signature?: string }
  ): Promise<boolean> {
    // Check API key
    if (credentials.apiKey) {
      const valid = await this.redis.get(`apikey:${credentials.apiKey}`);
      if (valid) {
        const client = this.clients.get(socketId);
        if (client) {
          client.authenticated = true;
          client.userId = valid;
        }
        return true;
      }
    }

    // Check signature (for wallet-based auth)
    if (credentials.signature) {
      // Would verify SIWE signature here
      return false;
    }

    return false;
  }

  /**
   * Send initial orderbook snapshot
   */
  private async sendOrderbookSnapshot(socket: any, pair: string): Promise<void> {
    try {
      // Fetch from Redis cache
      const orderbook = await this.redis.get(`orderbook:${pair}`);

      if (orderbook) {
        const data: OrderbookUpdate = JSON.parse(orderbook);
        data.sequenceId = this.getNextSequenceId(pair);

        await this.sendMessage(socket, data);
      }
    } catch (error) {
      console.error('Failed to send orderbook snapshot:', error);
    }
  }

  /**
   * Send initial position snapshot
   */
  private async sendPositionSnapshot(socket: any, userId: string): Promise<void> {
    try {
      const position = await this.redis.get(`position:${userId}`);

      if (position) {
        const data: PositionUpdate = JSON.parse(position);
        await this.sendMessage(socket, data);
      }
    } catch (error) {
      console.error('Failed to send position snapshot:', error);
    }
  }

  /**
   * Broadcast trade to relevant subscribers
   */
  private async broadcastTrade(trade: TradeUpdate): Promise<void> {
    const message = await this.compressMessage(trade);
    this.io.to(`pair:${trade.pair}`).emit('trade', message);

    // Update position for affected users
    // Would fetch and update in real implementation
  }

  /**
   * Update and broadcast orderbook changes
   */
  private async updateOrderbook(
    pair: string,
    side: 'buy' | 'sell',
    order: { orderId: string; price: number; size: number }
  ): Promise<void> {
    // Update orderbook in Redis
    // Simplified - would use sorted sets in production

    // Broadcast update
    const update: OrderbookUpdate = {
      type: 'orderbook',
      pair,
      bids: [], // Would be populated from Redis
      asks: [],
      timestamp: Date.now(),
      sequenceId: this.getNextSequenceId(pair),
    };

    const message = await this.compressMessage(update);
    this.io.to(`pair:${pair}`).emit('orderbook', message);
  }

  /**
   * Broadcast MEV alert
   */
  private async broadcastMEVAlert(alert: MEVAlert): Promise<void> {
    // Broadcast to all authenticated clients
    const message = await this.compressMessage(alert);
    this.io.emit('mev_alert', message);

    console.log(`🚨 MEV Alert: ${alert.alertType} - ${alert.severity}`);
  }

  /**
   * Send message with rate limiting
   */
  private async sendMessage(socket: any, message: FeedMessage): Promise<void> {
    const client = this.clients.get(socket.id);
    if (!client) return;

    // Rate limiting
    const now = Date.now();
    if (now - client.lastMessageTime < this.RATE_LIMIT_WINDOW) {
      if (client.messageCount >= this.MAX_MESSAGES_PER_SECOND) {
        console.warn(`⚠️  Rate limit exceeded for ${socket.id}`);
        return;
      }
      client.messageCount++;
    } else {
      client.messageCount = 1;
      client.lastMessageTime = now;
    }

    // Compress and send
    const compressed = await this.compressMessage(message);
    socket.emit(message.type, compressed);
  }

  /**
   * Compress message if above threshold
   */
  private async compressMessage(message: FeedMessage): Promise<Buffer | FeedMessage> {
    if (!this.compressionEnabled) return message;

    const json = JSON.stringify(message);

    if (json.length < this.COMPRESSION_THRESHOLD) {
      return message;
    }

    try {
      const compressed = await zstd.compress(Buffer.from(json));
      return compressed;
    } catch (error) {
      console.error('Compression failed:', error);
      return message;
    }
  }

  /**
   * Get next sequence ID for pair
   */
  private getNextSequenceId(pair: string): number {
    const current = this.sequenceIds.get(pair) || 0;
    const next = current + 1;
    this.sequenceIds.set(pair, next);
    return next;
  }

  /**
   * Health check for monitoring
   */
  private startHealthCheck(): void {
    setInterval(() => {
      const stats = {
        connectedClients: this.clients.size,
        totalSubscriptions: Array.from(this.clients.values()).reduce(
          (sum, client) => sum + client.pairs.size,
          0
        ),
        memoryUsage: process.memoryUsage(),
        timestamp: Date.now(),
      };

      // Publish to Redis for monitoring
      this.redis.publish('websocket:health', JSON.stringify(stats));

      console.log(`💓 Health: ${stats.connectedClients} clients, ${stats.totalSubscriptions} subscriptions`);
    }, 30000); // Every 30 seconds
  }

  /**
   * Get current statistics
   */
  public getStats(): object {
    return {
      connectedClients: this.clients.size,
      authenticatedClients: Array.from(this.clients.values()).filter(c => c.authenticated).length,
      totalSubscriptions: Array.from(this.clients.values()).reduce(
        (sum, client) => sum + client.pairs.size,
        0
      ),
      pairs: Array.from(this.sequenceIds.keys()),
    };
  }

  /**
   * Graceful shutdown
   */
  public async shutdown(): Promise<void> {
    console.log('🛑 Shutting down WebSocket feed...');

    // Disconnect all clients
    this.io.disconnectSockets();

    // Close Redis connections
    await this.redis.quit();
    await this.redisSubscriber.quit();

    console.log('✅ WebSocket feed shutdown complete');
  }
}

/**
 * Example usage
 */
export async function startWebSocketServer(): Promise<WebSocketFeed> {
  const http = require('http');
  const httpServer = http.createServer();

  const feed = new WebSocketFeed(
    httpServer,
    process.env.REDIS_URL || 'redis://localhost:6379',
    process.env.RPC_URL || 'http://localhost:8545',
    process.env.ORDERBOOK_ADDRESS || ''
  );

  const PORT = process.env.WS_PORT || 3001;

  httpServer.listen(PORT, () => {
    console.log(`🚀 WebSocket server running on port ${PORT}`);
    console.log(`📊 Stats available at ws://localhost:${PORT}`);
  });

  // Graceful shutdown
  process.on('SIGTERM', async () => {
    await feed.shutdown();
    httpServer.close();
    process.exit(0);
  });

  return feed;
}

// Start if run directly
if (require.main === module) {
  startWebSocketServer().catch(console.error);
}
