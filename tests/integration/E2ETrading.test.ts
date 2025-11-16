import { io, Socket } from "socket.io-client";
import axios from "axios";
import Redis from "ioredis";
import { Pool } from "pg";

/**
 * END-TO-END TRADING INTEGRATION TESTS
 *
 * Tests complete trading flows through all system components:
 * - REST API order submission
 * - WebSocket real-time updates
 * - Redis pub/sub messaging
 * - PostgreSQL order persistence
 * - Order matching engine
 * - MEV protection integration
 *
 * Requirements:
 * - Full system running (docker-compose up)
 * - All services healthy
 */

describe("E2E Trading Flow", () => {
  let redis: Redis;
  let dbPool: Pool;
  let wsClient: Socket;
  const API_BASE = process.env.API_URL || "http://localhost:3000";
  const WS_URL = process.env.WS_URL || "http://localhost:3001";

  beforeAll(async () => {
    // Connect to Redis
    redis = new Redis(process.env.REDIS_URL || "redis://localhost:6379");

    // Connect to PostgreSQL
    dbPool = new Pool({
      connectionString: process.env.DATABASE_URL || "postgresql://dex_user:dex_password@localhost:5432/dex_db",
    });

    // Verify connections
    await redis.ping();
    await dbPool.query("SELECT 1");
  });

  afterAll(async () => {
    await redis.quit();
    await dbPool.end();
  });

  beforeEach(() => {
    // Fresh WebSocket connection for each test
    wsClient = io(WS_URL, {
      transports: ["websocket"],
      autoConnect: false,
    });
  });

  afterEach(() => {
    if (wsClient?.connected) {
      wsClient.disconnect();
    }
  });

  // ═══════════════════════════════════════════════════════════════════
  //                         API HEALTH CHECKS
  // ═══════════════════════════════════════════════════════════════════

  describe("System Health", () => {
    it("should have healthy REST API", async () => {
      const response = await axios.get(`${API_BASE}/health`);

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty("status", "healthy");
      expect(response.data).toHaveProperty("uptime");
      expect(response.data).toHaveProperty("timestamp");
    });

    it("should have healthy WebSocket service", (done) => {
      wsClient.connect();

      wsClient.on("connect", () => {
        expect(wsClient.connected).toBe(true);
        done();
      });

      wsClient.on("connect_error", (err) => {
        done.fail(err);
      });
    });

    it("should have Redis connectivity", async () => {
      const pong = await redis.ping();
      expect(pong).toBe("PONG");
    });

    it("should have database connectivity", async () => {
      const result = await dbPool.query("SELECT NOW() as time");
      expect(result.rows[0]).toHaveProperty("time");
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                      ORDER SUBMISSION FLOW
  // ═══════════════════════════════════════════════════════════════════

  describe("Order Submission", () => {
    const testApiKey = process.env.TEST_API_KEY || "test-api-key-12345";

    it("should submit limit buy order via REST API", async () => {
      const orderPayload = {
        pair: "WETH/USDC",
        side: "buy",
        orderType: "limit",
        price: 2000,
        amount: 1.5,
        timeInForce: "GTC",
      };

      const response = await axios.post(`${API_BASE}/api/v1/orders`, orderPayload, {
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": testApiKey,
        },
      });

      expect(response.status).toBe(201);
      expect(response.data).toHaveProperty("orderId");
      expect(response.data).toHaveProperty("status", "pending");
      expect(response.data.pair).toBe("WETH/USDC");
      expect(response.data.side).toBe("buy");
      expect(response.data.price).toBe(2000);
      expect(response.data.amount).toBe(1.5);
    });

    it("should submit limit sell order via REST API", async () => {
      const orderPayload = {
        pair: "WETH/USDC",
        side: "sell",
        orderType: "limit",
        price: 2050,
        amount: 2.0,
        timeInForce: "GTC",
      };

      const response = await axios.post(`${API_BASE}/api/v1/orders`, orderPayload, {
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": testApiKey,
        },
      });

      expect(response.status).toBe(201);
      expect(response.data.side).toBe("sell");
    });

    it("should reject order without authentication", async () => {
      const orderPayload = {
        pair: "WETH/USDC",
        side: "buy",
        orderType: "limit",
        price: 2000,
        amount: 1.0,
      };

      await expect(axios.post(`${API_BASE}/api/v1/orders`, orderPayload)).rejects.toThrow();
    });

    it("should validate order parameters", async () => {
      const invalidOrder = {
        pair: "INVALID",
        side: "buy",
        orderType: "limit",
        price: -100, // Invalid negative price
        amount: 0, // Invalid zero amount
      };

      await expect(
        axios.post(`${API_BASE}/api/v1/orders`, invalidOrder, {
          headers: { "X-API-Key": testApiKey },
        })
      ).rejects.toMatchObject({
        response: { status: 400 },
      });
    });

    it("should persist order to database", async () => {
      const orderPayload = {
        pair: "WETH/USDC",
        side: "buy",
        orderType: "limit",
        price: 1999,
        amount: 0.1,
        timeInForce: "GTC",
      };

      const response = await axios.post(`${API_BASE}/api/v1/orders`, orderPayload, {
        headers: { "X-API-Key": testApiKey },
      });

      const { orderId } = response.data;

      // Check database directly
      const dbResult = await dbPool.query("SELECT * FROM orders WHERE order_id = $1", [orderId]);

      expect(dbResult.rows.length).toBe(1);
      expect(dbResult.rows[0].pair).toBe("WETH/USDC");
      expect(dbResult.rows[0].price).toBe("1999");
    });

    it("should publish order to Redis", async () => {
      const orderPayload = {
        pair: "WETH/USDC",
        side: "buy",
        orderType: "limit",
        price: 2001,
        amount: 0.5,
        timeInForce: "GTC",
      };

      // Subscribe to order events
      const subscriber = redis.duplicate();
      await subscriber.subscribe("dex:orders:new");

      const orderPromise = new Promise<any>((resolve) => {
        subscriber.on("message", (channel, message) => {
          if (channel === "dex:orders:new") {
            resolve(JSON.parse(message));
          }
        });
      });

      await axios.post(`${API_BASE}/api/v1/orders`, orderPayload, {
        headers: { "X-API-Key": testApiKey },
      });

      const redisOrder = await orderPromise;
      expect(redisOrder).toHaveProperty("orderId");
      expect(redisOrder.pair).toBe("WETH/USDC");

      await subscriber.quit();
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                    WEBSOCKET REAL-TIME UPDATES
  // ═══════════════════════════════════════════════════════════════════

  describe("WebSocket Real-Time Updates", () => {
    const testApiKey = process.env.TEST_API_KEY || "test-api-key-12345";

    it("should receive orderbook updates via WebSocket", (done) => {
      wsClient.connect();

      wsClient.on("connect", () => {
        wsClient.emit("subscribe", { pairs: ["WETH/USDC"] });
      });

      wsClient.on("orderbook", (data) => {
        expect(data).toHaveProperty("pair", "WETH/USDC");
        expect(data).toHaveProperty("bids");
        expect(data).toHaveProperty("asks");
        expect(data).toHaveProperty("timestamp");
        expect(Array.isArray(data.bids)).toBe(true);
        expect(Array.isArray(data.asks)).toBe(true);
        done();
      });

      // Trigger orderbook update by submitting order
      setTimeout(async () => {
        await axios.post(
          `${API_BASE}/api/v1/orders`,
          {
            pair: "WETH/USDC",
            side: "buy",
            orderType: "limit",
            price: 1995,
            amount: 1.0,
          },
          { headers: { "X-API-Key": testApiKey } }
        );
      }, 100);
    });

    it("should receive trade notifications", (done) => {
      wsClient.connect();

      wsClient.on("connect", () => {
        wsClient.emit("subscribe", { pairs: ["WETH/USDC"] });
      });

      wsClient.on("trade", (data) => {
        expect(data).toHaveProperty("pair");
        expect(data).toHaveProperty("price");
        expect(data).toHaveProperty("amount");
        expect(data).toHaveProperty("side");
        expect(data).toHaveProperty("timestamp");
        done();
      });

      // Submit matching orders to trigger trade
      setTimeout(async () => {
        // Seller
        await axios.post(
          `${API_BASE}/api/v1/orders`,
          {
            pair: "WETH/USDC",
            side: "sell",
            orderType: "limit",
            price: 2000,
            amount: 1.0,
          },
          { headers: { "X-API-Key": testApiKey } }
        );

        // Buyer at same price (should match)
        await axios.post(
          `${API_BASE}/api/v1/orders`,
          {
            pair: "WETH/USDC",
            side: "buy",
            orderType: "limit",
            price: 2000,
            amount: 1.0,
          },
          { headers: { "X-API-Key": testApiKey } }
        );
      }, 100);
    });

    it("should handle multiple subscriptions", (done) => {
      wsClient.connect();
      const receivedPairs = new Set<string>();

      wsClient.on("connect", () => {
        wsClient.emit("subscribe", { pairs: ["WETH/USDC", "WBTC/USDC", "LINK/USDC"] });
      });

      wsClient.on("orderbook", (data) => {
        receivedPairs.add(data.pair);

        if (receivedPairs.size === 3) {
          expect(receivedPairs.has("WETH/USDC")).toBe(true);
          expect(receivedPairs.has("WBTC/USDC")).toBe(true);
          expect(receivedPairs.has("LINK/USDC")).toBe(true);
          done();
        }
      });
    });

    it("should handle unsubscribe", (done) => {
      wsClient.connect();
      let messageCount = 0;

      wsClient.on("connect", () => {
        wsClient.emit("subscribe", { pairs: ["WETH/USDC"] });

        // Unsubscribe after first message
        setTimeout(() => {
          wsClient.emit("unsubscribe", { pairs: ["WETH/USDC"] });

          // Verify no more messages
          setTimeout(() => {
            expect(messageCount).toBeLessThanOrEqual(2); // Initial + maybe one more
            done();
          }, 500);
        }, 200);
      });

      wsClient.on("orderbook", () => {
        messageCount++;
      });
    });

    it("should receive MEV alert notifications", (done) => {
      wsClient.connect();

      wsClient.on("connect", () => {
        wsClient.emit("subscribe", { pairs: ["WETH/USDC"] });
      });

      wsClient.on("mev_alert", (data) => {
        expect(data).toHaveProperty("type");
        expect(data).toHaveProperty("severity");
        expect(data).toHaveProperty("details");
        expect(data).toHaveProperty("timestamp");
        done();
      });

      // Simulate MEV alert via Redis
      setTimeout(async () => {
        const alert = {
          type: "SANDWICH_ATTACK",
          severity: "HIGH",
          details: {
            attackerAddress: "0x123...",
            victimTx: "0xabc...",
            estimatedLoss: "100000000", // 100 USDC
          },
          timestamp: Date.now(),
        };

        await redis.publish("dex:mev:alerts", JSON.stringify(alert));
      }, 100);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                      ORDER MATCHING ENGINE
  // ═══════════════════════════════════════════════════════════════════

  describe("Order Matching", () => {
    const testApiKey = process.env.TEST_API_KEY || "test-api-key-12345";

    it("should match buy and sell orders at same price", async () => {
      // Clear orderbook first
      await redis.del("orderbook:WETH/USDC");

      // Submit sell order
      const sellOrder = await axios.post(
        `${API_BASE}/api/v1/orders`,
        {
          pair: "WETH/USDC",
          side: "sell",
          orderType: "limit",
          price: 2000,
          amount: 5.0,
        },
        { headers: { "X-API-Key": testApiKey } }
      );

      // Submit matching buy order
      const buyOrder = await axios.post(
        `${API_BASE}/api/v1/orders`,
        {
          pair: "WETH/USDC",
          side: "buy",
          orderType: "limit",
          price: 2000,
          amount: 5.0,
        },
        { headers: { "X-API-Key": testApiKey } }
      );

      // Check both orders filled
      await new Promise((resolve) => setTimeout(resolve, 500)); // Wait for matching

      const sellOrderStatus = await axios.get(`${API_BASE}/api/v1/orders/${sellOrder.data.orderId}`, {
        headers: { "X-API-Key": testApiKey },
      });

      const buyOrderStatus = await axios.get(`${API_BASE}/api/v1/orders/${buyOrder.data.orderId}`, {
        headers: { "X-API-Key": testApiKey },
      });

      expect(sellOrderStatus.data.status).toBe("filled");
      expect(buyOrderStatus.data.status).toBe("filled");
    });

    it("should partially fill orders when sizes mismatch", async () => {
      // Sell 10 WETH
      const sellOrder = await axios.post(
        `${API_BASE}/api/v1/orders`,
        {
          pair: "WETH/USDC",
          side: "sell",
          orderType: "limit",
          price: 2010,
          amount: 10.0,
        },
        { headers: { "X-API-Key": testApiKey } }
      );

      // Buy only 3 WETH
      const buyOrder = await axios.post(
        `${API_BASE}/api/v1/orders`,
        {
          pair: "WETH/USDC",
          side: "buy",
          orderType: "limit",
          price: 2010,
          amount: 3.0,
        },
        { headers: { "X-API-Key": testApiKey } }
      );

      await new Promise((resolve) => setTimeout(resolve, 500));

      const sellOrderStatus = await axios.get(`${API_BASE}/api/v1/orders/${sellOrder.data.orderId}`, {
        headers: { "X-API-Key": testApiKey },
      });

      expect(sellOrderStatus.data.status).toBe("partially_filled");
      expect(sellOrderStatus.data.filledAmount).toBe(3.0);
      expect(sellOrderStatus.data.remainingAmount).toBe(7.0);
    });

    it("should respect price-time priority (FIFO)", async () => {
      // First seller at 2000
      const firstSeller = await axios.post(
        `${API_BASE}/api/v1/orders`,
        {
          pair: "WETH/USDC",
          side: "sell",
          orderType: "limit",
          price: 2000,
          amount: 5.0,
        },
        { headers: { "X-API-Key": testApiKey } }
      );

      // Second seller at same price (should fill second)
      const secondSeller = await axios.post(
        `${API_BASE}/api/v1/orders`,
        {
          pair: "WETH/USDC",
          side: "sell",
          orderType: "limit",
          price: 2000,
          amount: 5.0,
        },
        { headers: { "X-API-Key": testApiKey } }
      );

      // Buyer takes only 5 WETH (should match first seller only)
      await axios.post(
        `${API_BASE}/api/v1/orders`,
        {
          pair: "WETH/USDC",
          side: "buy",
          orderType: "limit",
          price: 2000,
          amount: 5.0,
        },
        { headers: { "X-API-Key": testApiKey } }
      );

      await new Promise((resolve) => setTimeout(resolve, 500));

      const firstSellerStatus = await axios.get(`${API_BASE}/api/v1/orders/${firstSeller.data.orderId}`, {
        headers: { "X-API-Key": testApiKey },
      });

      const secondSellerStatus = await axios.get(`${API_BASE}/api/v1/orders/${secondSeller.data.orderId}`, {
        headers: { "X-API-Key": testApiKey },
      });

      expect(firstSellerStatus.data.status).toBe("filled"); // First filled
      expect(secondSellerStatus.data.status).toBe("open"); // Second still waiting
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                       ORDER CANCELLATION
  // ═══════════════════════════════════════════════════════════════════

  describe("Order Cancellation", () => {
    const testApiKey = process.env.TEST_API_KEY || "test-api-key-12345";

    it("should cancel open order", async () => {
      // Submit order
      const orderResponse = await axios.post(
        `${API_BASE}/api/v1/orders`,
        {
          pair: "WETH/USDC",
          side: "buy",
          orderType: "limit",
          price: 1900,
          amount: 1.0,
        },
        { headers: { "X-API-Key": testApiKey } }
      );

      const { orderId } = orderResponse.data;

      // Cancel order
      const cancelResponse = await axios.delete(`${API_BASE}/api/v1/orders/${orderId}`, {
        headers: { "X-API-Key": testApiKey },
      });

      expect(cancelResponse.status).toBe(200);
      expect(cancelResponse.data.status).toBe("cancelled");

      // Verify in database
      const dbResult = await dbPool.query("SELECT status FROM orders WHERE order_id = $1", [orderId]);
      expect(dbResult.rows[0].status).toBe("cancelled");
    });

    it("should not cancel filled order", async () => {
      // Create and fill an order
      await axios.post(
        `${API_BASE}/api/v1/orders`,
        {
          pair: "WETH/USDC",
          side: "sell",
          orderType: "limit",
          price: 2000,
          amount: 1.0,
        },
        { headers: { "X-API-Key": testApiKey } }
      );

      const buyOrder = await axios.post(
        `${API_BASE}/api/v1/orders`,
        {
          pair: "WETH/USDC",
          side: "buy",
          orderType: "limit",
          price: 2000,
          amount: 1.0,
        },
        { headers: { "X-API-Key": testApiKey } }
      );

      await new Promise((resolve) => setTimeout(resolve, 500));

      // Try to cancel filled order
      await expect(
        axios.delete(`${API_BASE}/api/v1/orders/${buyOrder.data.orderId}`, {
          headers: { "X-API-Key": testApiKey },
        })
      ).rejects.toMatchObject({
        response: { status: 400 },
      });
    });

    it("should update orderbook on cancellation", async () => {
      const orderResponse = await axios.post(
        `${API_BASE}/api/v1/orders`,
        {
          pair: "WETH/USDC",
          side: "buy",
          orderType: "limit",
          price: 1850,
          amount: 10.0,
        },
        { headers: { "X-API-Key": testApiKey } }
      );

      // Get initial orderbook
      const beforeCancel = await axios.get(`${API_BASE}/api/v1/orderbook/WETH-USDC`);
      const bidsBefore = beforeCancel.data.bids.find((b: any) => b.price === 1850);
      expect(bidsBefore).toBeDefined();

      // Cancel
      await axios.delete(`${API_BASE}/api/v1/orders/${orderResponse.data.orderId}`, {
        headers: { "X-API-Key": testApiKey },
      });

      // Verify orderbook updated
      const afterCancel = await axios.get(`${API_BASE}/api/v1/orderbook/WETH-USDC`);
      const bidsAfter = afterCancel.data.bids.find((b: any) => b.price === 1850);
      expect(bidsAfter).toBeUndefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                        HISTORICAL DATA
  // ═══════════════════════════════════════════════════════════════════

  describe("Historical Data", () => {
    const testApiKey = process.env.TEST_API_KEY || "test-api-key-12345";

    it("should retrieve trade history", async () => {
      const response = await axios.get(`${API_BASE}/api/v1/trades/WETH-USDC?limit=10`, {
        headers: { "X-API-Key": testApiKey },
      });

      expect(response.status).toBe(200);
      expect(Array.isArray(response.data)).toBe(true);
      if (response.data.length > 0) {
        expect(response.data[0]).toHaveProperty("price");
        expect(response.data[0]).toHaveProperty("amount");
        expect(response.data[0]).toHaveProperty("timestamp");
      }
    });

    it("should retrieve user order history", async () => {
      const response = await axios.get(`${API_BASE}/api/v1/orders?status=all&limit=20`, {
        headers: { "X-API-Key": testApiKey },
      });

      expect(response.status).toBe(200);
      expect(Array.isArray(response.data)).toBe(true);
    });

    it("should retrieve user positions", async () => {
      const response = await axios.get(`${API_BASE}/api/v1/positions`, {
        headers: { "X-API-Key": testApiKey },
      });

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty("positions");
      expect(Array.isArray(response.data.positions)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //                     RATE LIMITING & SECURITY
  // ═══════════════════════════════════════════════════════════════════

  describe("Rate Limiting & Security", () => {
    const testApiKey = process.env.TEST_API_KEY || "test-api-key-12345";

    it("should enforce API rate limits", async () => {
      const requests = [];

      // Send many requests quickly
      for (let i = 0; i < 150; i++) {
        requests.push(
          axios.get(`${API_BASE}/api/v1/orderbook/WETH-USDC`).catch((err) => err.response)
        );
      }

      const responses = await Promise.all(requests);
      const tooManyRequests = responses.filter((r) => r?.status === 429);

      // Should have some rate-limited responses
      expect(tooManyRequests.length).toBeGreaterThan(0);
    });

    it("should include security headers", async () => {
      const response = await axios.get(`${API_BASE}/health`);

      expect(response.headers).toHaveProperty("x-content-type-options", "nosniff");
      expect(response.headers).toHaveProperty("x-frame-options", "DENY");
      expect(response.headers).toHaveProperty("x-xss-protection");
    });

    it("should validate Content-Type", async () => {
      await expect(
        axios.post(
          `${API_BASE}/api/v1/orders`,
          "invalid data",
          {
            headers: {
              "X-API-Key": testApiKey,
              "Content-Type": "text/plain",
            },
          }
        )
      ).rejects.toMatchObject({
        response: { status: 415 },
      });
    });
  });
});

export {};
