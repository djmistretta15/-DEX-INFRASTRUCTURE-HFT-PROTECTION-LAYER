/**
 * RESTful Order Management API
 *
 * Endpoints:
 * - POST /api/v1/orders - Submit order
 * - GET /api/v1/orders/:id - Get order status
 * - DELETE /api/v1/orders/:id - Cancel order
 * - GET /api/v1/orders - List user orders
 * - GET /api/v1/orderbook/:pair - Get orderbook
 * - GET /api/v1/trades/:pair - Get trade history
 * - GET /api/v1/positions - Get user positions
 *
 * Authentication: API Key or JWT
 * Rate Limiting: 1000 req/min per user
 */

import express, { Request, Response, NextFunction } from 'express';
import { ethers } from 'ethers';
import Redis from 'ioredis';
import { body, param, query, validationResult } from 'express-validator';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import * as jwt from 'jsonwebtoken';

// Types
interface AuthRequest extends Request {
  userId?: string;
  apiKey?: string;
}

interface OrderSubmission {
  pair: string;
  side: 'buy' | 'sell';
  orderType: 'limit' | 'market' | 'stop_loss';
  price?: number;
  amount: number;
  stopPrice?: number;
  timeInForce?: 'GTC' | 'IOC' | 'FOK';
  postOnly?: boolean;
}

interface OrderStatus {
  orderId: string;
  status: 'pending' | 'open' | 'filled' | 'partially_filled' | 'cancelled' | 'rejected';
  pair: string;
  side: 'buy' | 'sell';
  orderType: string;
  price: number;
  amount: number;
  filled: number;
  remaining: number;
  averagePrice: number;
  fees: number;
  createdAt: number;
  updatedAt: number;
}

interface Position {
  pair: string;
  baseBalance: number;
  quoteBalance: number;
  averageEntryPrice: number;
  unrealizedPnl: number;
  realizedPnl: number;
  totalPnl: number;
}

export class OrderAPI {
  private app: express.Application;
  private redis: Redis;
  private provider: ethers.Provider;
  private orderbookContract: ethers.Contract;
  private jwtSecret: string;

  constructor(
    redisUrl: string,
    providerUrl: string,
    orderbookAddress: string,
    jwtSecret: string
  ) {
    this.app = express();
    this.redis = new Redis(redisUrl);
    this.provider = new ethers.JsonRpcProvider(providerUrl);
    this.jwtSecret = jwtSecret;

    this.orderbookContract = new ethers.Contract(
      orderbookAddress,
      [
        'function placeLimitOrder(address,address,uint8,uint256,uint256) returns (bytes32)',
        'function placeMarketOrder(address,address,uint8,uint256) returns (bytes32)',
        'function cancelOrder(bytes32)',
        'function getOrderbook(address,address,uint256) view returns (uint256[],uint256[],uint256[],uint256[])',
        'function orders(bytes32) view returns (tuple)',
      ],
      this.provider
    );

    this.setupMiddleware();
    this.setupRoutes();
  }

  /**
   * Setup Express middleware
   */
  private setupMiddleware(): void {
    // Security
    this.app.use(helmet());
    this.app.use(cors({
      origin: process.env.CORS_ORIGIN || '*',
      credentials: true,
    }));

    // Logging
    this.app.use(morgan('combined'));

    // Body parsing
    this.app.use(express.json({ limit: '1mb' }));
    this.app.use(express.urlencoded({ extended: true }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 60 * 1000, // 1 minute
      max: 1000, // 1000 requests per minute
      message: 'Too many requests, please try again later',
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req) => {
        return (req as AuthRequest).userId || req.ip || 'anonymous';
      },
    });

    this.app.use('/api/', limiter);

    // Health check (no rate limit)
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: Date.now(),
        uptime: process.uptime(),
      });
    });
  }

  /**
   * Setup API routes
   */
  private setupRoutes(): void {
    const router = express.Router();

    // Authentication endpoints
    router.post('/auth/api-key', this.generateApiKey.bind(this));
    router.post('/auth/jwt', this.generateJWT.bind(this));

    // Order management (requires auth)
    router.post(
      '/orders',
      this.authenticate.bind(this),
      [
        body('pair').isString().notEmpty(),
        body('side').isIn(['buy', 'sell']),
        body('orderType').isIn(['limit', 'market', 'stop_loss']),
        body('amount').isFloat({ gt: 0 }),
        body('price').optional().isFloat({ gt: 0 }),
        body('timeInForce').optional().isIn(['GTC', 'IOC', 'FOK']),
      ],
      this.submitOrder.bind(this)
    );

    router.get(
      '/orders/:orderId',
      this.authenticate.bind(this),
      param('orderId').isString(),
      this.getOrder.bind(this)
    );

    router.delete(
      '/orders/:orderId',
      this.authenticate.bind(this),
      param('orderId').isString(),
      this.cancelOrder.bind(this)
    );

    router.get(
      '/orders',
      this.authenticate.bind(this),
      [
        query('pair').optional().isString(),
        query('status').optional().isIn(['open', 'filled', 'cancelled']),
        query('limit').optional().isInt({ min: 1, max: 100 }),
        query('offset').optional().isInt({ min: 0 }),
      ],
      this.listOrders.bind(this)
    );

    // Market data (public)
    router.get(
      '/orderbook/:pair',
      [
        param('pair').isString(),
        query('depth').optional().isInt({ min: 1, max: 100 }),
      ],
      this.getOrderbook.bind(this)
    );

    router.get(
      '/trades/:pair',
      [
        param('pair').isString(),
        query('limit').optional().isInt({ min: 1, max: 1000 }),
        query('since').optional().isInt(),
      ],
      this.getTrades.bind(this)
    );

    router.get(
      '/ticker/:pair',
      param('pair').isString(),
      this.getTicker.bind(this)
    );

    // Portfolio (requires auth)
    router.get(
      '/positions',
      this.authenticate.bind(this),
      this.getPositions.bind(this)
    );

    router.get(
      '/balances',
      this.authenticate.bind(this),
      this.getBalances.bind(this)
    );

    // Mount router
    this.app.use('/api/v1', router);

    // Error handler
    this.app.use(this.errorHandler.bind(this));
  }

  /**
   * Authentication middleware
   */
  private async authenticate(req: AuthRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      const apiKey = req.headers['x-api-key'] as string;
      const authHeader = req.headers.authorization;

      // API Key authentication
      if (apiKey) {
        const userId = await this.redis.get(`apikey:${apiKey}`);

        if (userId) {
          req.userId = userId;
          req.apiKey = apiKey;
          return next();
        }
      }

      // JWT authentication
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);

        try {
          const payload = jwt.verify(token, this.jwtSecret) as { userId: string };
          req.userId = payload.userId;
          return next();
        } catch (error) {
          res.status(401).json({ error: 'Invalid token' });
          return;
        }
      }

      res.status(401).json({ error: 'Authentication required' });
    } catch (error) {
      next(error);
    }
  }

  /**
   * Generate API key
   */
  private async generateApiKey(req: Request, res: Response): Promise<void> {
    const { userId, signature } = req.body;

    // Verify signature (SIWE or similar)
    // Simplified for example

    const apiKey = ethers.hexlify(ethers.randomBytes(32));

    // Store in Redis with 1 year expiration
    await this.redis.setex(`apikey:${apiKey}`, 31536000, userId);

    res.json({
      apiKey,
      expiresAt: Date.now() + 31536000 * 1000,
    });
  }

  /**
   * Generate JWT
   */
  private async generateJWT(req: Request, res: Response): Promise<void> {
    const { userId, signature } = req.body;

    // Verify signature
    // Simplified for example

    const token = jwt.sign({ userId }, this.jwtSecret, { expiresIn: '7d' });

    res.json({
      token,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
    });
  }

  /**
   * Submit order
   */
  private async submitOrder(req: AuthRequest, res: Response): Promise<void> {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const order: OrderSubmission = req.body;
    const userId = req.userId!;

    try {
      // Get user's signer (would fetch from secure storage)
      const signer = await this.getUserSigner(userId);

      let txHash: string;

      if (order.orderType === 'limit') {
        const priceWei = ethers.parseEther(order.price!.toString());
        const amountWei = ethers.parseUnits(order.amount.toString(), 6);

        const tx = await this.orderbookContract.connect(signer).placeLimitOrder(
          this.getTokenAddress(order.pair, 'base'),
          this.getTokenAddress(order.pair, 'quote'),
          order.side === 'buy' ? 0 : 1,
          priceWei,
          amountWei
        );

        const receipt = await tx.wait();
        txHash = receipt.hash;

        // Extract order ID from event
        const event = receipt.logs.find((log: any) =>
          log.topics[0] === ethers.id('OrderPlaced(bytes32,address,uint8,uint256,uint256)')
        );

        const orderId = event?.topics[1] || txHash;

        // Cache order in Redis
        await this.cacheOrder(orderId, {
          orderId,
          userId,
          status: 'open',
          pair: order.pair,
          side: order.side,
          orderType: order.orderType,
          price: order.price!,
          amount: order.amount,
          filled: 0,
          remaining: order.amount,
          averagePrice: 0,
          fees: 0,
          createdAt: Date.now(),
          updatedAt: Date.now(),
        });

        res.status(201).json({
          orderId,
          txHash,
          status: 'pending',
          timestamp: Date.now(),
        });
      } else if (order.orderType === 'market') {
        const amountWei = ethers.parseUnits(order.amount.toString(), 6);

        const tx = await this.orderbookContract.connect(signer).placeMarketOrder(
          this.getTokenAddress(order.pair, 'base'),
          this.getTokenAddress(order.pair, 'quote'),
          order.side === 'buy' ? 0 : 1,
          amountWei
        );

        const receipt = await tx.wait();
        txHash = receipt.hash;

        res.status(201).json({
          orderId: txHash,
          txHash,
          status: 'filled',
          timestamp: Date.now(),
        });
      } else {
        res.status(400).json({ error: 'Unsupported order type' });
      }
    } catch (error) {
      console.error('Order submission failed:', error);
      res.status(500).json({
        error: 'Order submission failed',
        details: (error as Error).message,
      });
    }
  }

  /**
   * Get order status
   */
  private async getOrder(req: AuthRequest, res: Response): Promise<void> {
    const { orderId } = req.params;
    const userId = req.userId!;

    try {
      // Check cache first
      const cached = await this.redis.get(`order:${orderId}`);

      if (cached) {
        const order: OrderStatus = JSON.parse(cached);

        // Verify ownership
        if (order.userId !== userId) {
          res.status(403).json({ error: 'Forbidden' });
          return;
        }

        res.json(order);
        return;
      }

      // Fetch from contract
      const orderData = await this.orderbookContract.orders(orderId);

      // Transform and return
      const order: OrderStatus = {
        orderId,
        status: orderData.isActive ? 'open' : 'filled',
        pair: 'WETH/USDC', // Would be determined from order
        side: orderData.side === 0 ? 'buy' : 'sell',
        orderType: orderData.orderType === 0 ? 'limit' : 'market',
        price: parseFloat(ethers.formatEther(orderData.price)),
        amount: parseFloat(ethers.formatUnits(orderData.baseAmount, 6)),
        filled: parseFloat(ethers.formatUnits(orderData.filled, 6)),
        remaining: parseFloat(ethers.formatUnits(orderData.baseAmount - orderData.filled, 6)),
        averagePrice: 0, // Would be calculated
        fees: 0, // Would be calculated
        createdAt: Number(orderData.timestamp) * 1000,
        updatedAt: Date.now(),
      };

      res.json(order);
    } catch (error) {
      res.status(404).json({ error: 'Order not found' });
    }
  }

  /**
   * Cancel order
   */
  private async cancelOrder(req: AuthRequest, res: Response): Promise<void> {
    const { orderId } = req.params;
    const userId = req.userId!;

    try {
      const signer = await this.getUserSigner(userId);

      const tx = await this.orderbookContract.connect(signer).cancelOrder(orderId);
      await tx.wait();

      // Update cache
      const cached = await this.redis.get(`order:${orderId}`);
      if (cached) {
        const order: OrderStatus = JSON.parse(cached);
        order.status = 'cancelled';
        order.updatedAt = Date.now();
        await this.redis.set(`order:${orderId}`, JSON.stringify(order));
      }

      res.json({
        orderId,
        status: 'cancelled',
        timestamp: Date.now(),
      });
    } catch (error) {
      res.status(500).json({
        error: 'Cancellation failed',
        details: (error as Error).message,
      });
    }
  }

  /**
   * List user orders
   */
  private async listOrders(req: AuthRequest, res: Response): Promise<void> {
    const userId = req.userId!;
    const { pair, status, limit = 50, offset = 0 } = req.query;

    // Would query from database in production
    const orders: OrderStatus[] = [];

    res.json({
      orders,
      total: orders.length,
      limit: Number(limit),
      offset: Number(offset),
    });
  }

  /**
   * Get orderbook
   */
  private async getOrderbook(req: Request, res: Response): Promise<void> {
    const { pair } = req.params;
    const depth = Number(req.query.depth) || 20;

    try {
      const [bidPrices, bidSizes, askPrices, askSizes] =
        await this.orderbookContract.getOrderbook(
          this.getTokenAddress(pair, 'base'),
          this.getTokenAddress(pair, 'quote'),
          depth
        );

      const bids = bidPrices.map((price: bigint, i: number) => [
        parseFloat(ethers.formatEther(price)),
        parseFloat(ethers.formatUnits(bidSizes[i], 6)),
      ]);

      const asks = askPrices.map((price: bigint, i: number) => [
        parseFloat(ethers.formatEther(price)),
        parseFloat(ethers.formatUnits(askSizes[i], 6)),
      ]);

      res.json({
        pair,
        bids,
        asks,
        timestamp: Date.now(),
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch orderbook' });
    }
  }

  /**
   * Get trade history
   */
  private async getTrades(req: Request, res: Response): Promise<void> {
    const { pair } = req.params;
    const limit = Number(req.query.limit) || 100;

    // Would fetch from database in production
    const trades: any[] = [];

    res.json({
      pair,
      trades,
      timestamp: Date.now(),
    });
  }

  /**
   * Get ticker
   */
  private async getTicker(req: Request, res: Response): Promise<void> {
    const { pair } = req.params;

    // Would fetch from Redis cache in production
    res.json({
      pair,
      lastPrice: 2000,
      volume24h: 1000000,
      high24h: 2100,
      low24h: 1900,
      change24h: 5.2,
      timestamp: Date.now(),
    });
  }

  /**
   * Get user positions
   */
  private async getPositions(req: AuthRequest, res: Response): Promise<void> {
    const userId = req.userId!;

    // Would fetch from database in production
    const positions: Position[] = [];

    res.json({
      positions,
      totalPnl: 0,
      timestamp: Date.now(),
    });
  }

  /**
   * Get user balances
   */
  private async getBalances(req: AuthRequest, res: Response): Promise<void> {
    const userId = req.userId!;

    // Would fetch from contract in production
    res.json({
      balances: [],
      timestamp: Date.now(),
    });
  }

  /**
   * Error handler
   */
  private errorHandler(err: Error, req: Request, res: Response, next: NextFunction): void {
    console.error('API Error:', err);

    res.status(500).json({
      error: 'Internal server error',
      message: process.env.NODE_ENV === 'development' ? err.message : undefined,
    });
  }

  // Helper methods

  private async getUserSigner(userId: string): Promise<ethers.Signer> {
    // Would fetch private key from secure storage in production
    // For now, return a mock signer
    const wallet = ethers.Wallet.createRandom();
    return wallet.connect(this.provider);
  }

  private getTokenAddress(pair: string, type: 'base' | 'quote'): string {
    // Mock implementation
    const tokens: Record<string, { base: string; quote: string }> = {
      'WETH/USDC': {
        base: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
        quote: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
      },
    };

    return tokens[pair]?.[type] || '0x0';
  }

  private async cacheOrder(orderId: string, order: any): Promise<void> {
    await this.redis.setex(`order:${orderId}`, 86400, JSON.stringify(order));
  }

  /**
   * Start server
   */
  public listen(port: number): void {
    this.app.listen(port, () => {
      console.log(`🚀 Order API running on port ${port}`);
      console.log(`📡 Endpoints: http://localhost:${port}/api/v1`);
    });
  }
}

/**
 * Start server
 */
export function startOrderAPI(): OrderAPI {
  const api = new OrderAPI(
    process.env.REDIS_URL || 'redis://localhost:6379',
    process.env.RPC_URL || 'http://localhost:8545',
    process.env.ORDERBOOK_ADDRESS || '',
    process.env.JWT_SECRET || 'change-me-in-production'
  );

  const PORT = Number(process.env.API_PORT) || 3000;
  api.listen(PORT);

  return api;
}

// Start if run directly
if (require.main === module) {
  startOrderAPI();
}
