import { EventEmitter } from 'events';
import * as crypto from 'crypto';

/**
 * WEBSOCKET API GATEWAY
 *
 * HYPOTHESIS: A high-performance WebSocket gateway with intelligent load
 * balancing and message prioritization will handle >100,000 concurrent
 * connections with <10ms latency.
 *
 * SUCCESS METRICS:
 * - Concurrent connections: >100,000
 * - Message latency: <10ms p99
 * - Throughput: >1M messages/second
 * - Connection stability: >99.9% uptime
 * - Reconnection success: >99%
 *
 * SECURITY CONSIDERATIONS:
 * - JWT authentication
 * - Rate limiting per connection
 * - Message validation
 * - DDoS protection
 * - TLS encryption
 * - Origin validation
 */

// Connection state
enum ConnectionState {
  CONNECTING = 'connecting',
  OPEN = 'open',
  CLOSING = 'closing',
  CLOSED = 'closed',
  RECONNECTING = 'reconnecting'
}

// Message priority
enum MessagePriority {
  CRITICAL = 1,
  HIGH = 2,
  NORMAL = 3,
  LOW = 4
}

// Subscription type
enum SubscriptionType {
  TICKER = 'ticker',
  ORDERBOOK = 'orderbook',
  TRADES = 'trades',
  CANDLES = 'candles',
  ACCOUNT = 'account',
  ORDERS = 'orders',
  FILLS = 'fills',
  POSITIONS = 'positions'
}

// WebSocket connection
interface WSConnection {
  id: string;
  userId?: string;
  apiKey?: string;
  state: ConnectionState;
  subscriptions: Map<string, Subscription>;
  createdAt: Date;
  lastPingAt: Date;
  lastPongAt: Date;
  messageCount: number;
  bytesReceived: number;
  bytesSent: number;
  ipAddress: string;
  userAgent: string;
  rateLimit: RateLimitState;
  authenticated: boolean;
}

// Subscription
interface Subscription {
  id: string;
  connectionId: string;
  type: SubscriptionType;
  channels: string[];
  filters?: any;
  createdAt: Date;
  lastMessageAt?: Date;
  messageCount: number;
}

// WebSocket message
interface WSMessage {
  id: string;
  type: 'subscribe' | 'unsubscribe' | 'request' | 'response' | 'event' | 'ping' | 'pong' | 'error';
  channel?: string;
  data?: any;
  timestamp: number;
  priority: MessagePriority;
}

// Rate limit state
interface RateLimitState {
  messageCount: number;
  windowStart: number;
  maxMessages: number;
  windowMs: number;
  blocked: boolean;
  blockUntil?: number;
}

// Server statistics
interface ServerStats {
  totalConnections: number;
  activeConnections: number;
  totalSubscriptions: number;
  messagesPerSecond: number;
  bytesPerSecond: number;
  uptime: number;
  lastMinuteMessages: number[];
  cpuUsage: number;
  memoryUsage: number;
}

// Channel data
interface ChannelData {
  channel: string;
  type: SubscriptionType;
  data: any;
  timestamp: Date;
  sequence: number;
}

// Authentication token
interface AuthToken {
  userId: string;
  apiKey: string;
  permissions: string[];
  expiresAt: Date;
}

// Load balancer node
interface LoadBalancerNode {
  id: string;
  address: string;
  port: number;
  connections: number;
  capacity: number;
  healthy: boolean;
  lastHealthCheck: Date;
}

// Main WebSocket Gateway
export class WebSocketGateway extends EventEmitter {
  private connections: Map<string, WSConnection> = new Map();
  private subscriptions: Map<string, Set<string>> = new Map(); // channel -> connection IDs
  private messageQueue: WSMessage[] = [];
  private channelSequences: Map<string, number> = new Map();
  private loadBalancerNodes: LoadBalancerNode[] = [];

  // Statistics
  private stats: ServerStats;
  private messageHistory: number[] = [];

  // Configuration
  private maxConnectionsPerIP: number = 10;
  private maxSubscriptionsPerConnection: number = 100;
  private pingInterval: number = 30000; // 30 seconds
  private pongTimeout: number = 10000; // 10 seconds
  private maxMessageSize: number = 1024 * 1024; // 1MB
  private compressionThreshold: number = 1024; // Compress messages > 1KB

  // Rate limiting defaults
  private defaultRateLimit: Omit<RateLimitState, 'messageCount' | 'windowStart' | 'blocked'> = {
    maxMessages: 100,
    windowMs: 1000
  };

  // Allowed origins for CORS
  private allowedOrigins: Set<string> = new Set();

  // Message buffer for batching
  private messageBuffer: Map<string, WSMessage[]> = new Map();
  private bufferFlushInterval: number = 10; // ms

  constructor() {
    super();
    this.stats = this.initializeStats();
    this.startPeriodicTasks();
  }

  private initializeStats(): ServerStats {
    return {
      totalConnections: 0,
      activeConnections: 0,
      totalSubscriptions: 0,
      messagesPerSecond: 0,
      bytesPerSecond: 0,
      uptime: Date.now(),
      lastMinuteMessages: [],
      cpuUsage: 0,
      memoryUsage: 0
    };
  }

  /**
   * Handle new connection
   */
  handleConnection(
    connectionId: string,
    ipAddress: string,
    userAgent: string,
    origin?: string
  ): WSConnection | null {
    // Validate origin
    if (origin && this.allowedOrigins.size > 0 && !this.allowedOrigins.has(origin)) {
      this.emit('connectionRejected', { connectionId, reason: 'Invalid origin' });
      return null;
    }

    // Check IP connection limit
    const connectionsFromIP = Array.from(this.connections.values())
      .filter(c => c.ipAddress === ipAddress).length;

    if (connectionsFromIP >= this.maxConnectionsPerIP) {
      this.emit('connectionRejected', { connectionId, reason: 'Max connections per IP reached' });
      return null;
    }

    const connection: WSConnection = {
      id: connectionId,
      state: ConnectionState.OPEN,
      subscriptions: new Map(),
      createdAt: new Date(),
      lastPingAt: new Date(),
      lastPongAt: new Date(),
      messageCount: 0,
      bytesReceived: 0,
      bytesSent: 0,
      ipAddress,
      userAgent,
      rateLimit: {
        messageCount: 0,
        windowStart: Date.now(),
        ...this.defaultRateLimit,
        blocked: false
      },
      authenticated: false
    };

    this.connections.set(connectionId, connection);
    this.stats.totalConnections++;
    this.stats.activeConnections++;

    this.emit('connectionOpened', connection);

    // Send welcome message
    this.sendMessage(connectionId, {
      id: crypto.randomBytes(16).toString('hex'),
      type: 'event',
      channel: 'system',
      data: {
        event: 'connected',
        connectionId,
        serverTime: Date.now()
      },
      timestamp: Date.now(),
      priority: MessagePriority.HIGH
    });

    return connection;
  }

  /**
   * Authenticate connection
   */
  authenticateConnection(
    connectionId: string,
    token: string
  ): boolean {
    const connection = this.connections.get(connectionId);
    if (!connection) return false;

    // Verify JWT token (simplified)
    const authToken = this.verifyToken(token);
    if (!authToken) {
      this.sendError(connectionId, 'Authentication failed', 'invalid_token');
      return false;
    }

    connection.userId = authToken.userId;
    connection.apiKey = authToken.apiKey;
    connection.authenticated = true;

    // Upgrade rate limits for authenticated users
    connection.rateLimit.maxMessages = 1000;

    this.emit('connectionAuthenticated', { connectionId, userId: authToken.userId });

    this.sendMessage(connectionId, {
      id: crypto.randomBytes(16).toString('hex'),
      type: 'response',
      channel: 'auth',
      data: {
        success: true,
        userId: authToken.userId,
        permissions: authToken.permissions
      },
      timestamp: Date.now(),
      priority: MessagePriority.HIGH
    });

    return true;
  }

  /**
   * Handle incoming message
   */
  handleMessage(connectionId: string, rawMessage: string): void {
    const connection = this.connections.get(connectionId);
    if (!connection) return;

    // Check message size
    if (rawMessage.length > this.maxMessageSize) {
      this.sendError(connectionId, 'Message too large', 'message_too_large');
      return;
    }

    // Rate limiting
    if (this.isRateLimited(connection)) {
      this.sendError(connectionId, 'Rate limit exceeded', 'rate_limited');
      return;
    }

    connection.messageCount++;
    connection.bytesReceived += rawMessage.length;
    connection.rateLimit.messageCount++;

    let message: WSMessage;
    try {
      message = JSON.parse(rawMessage);
    } catch {
      this.sendError(connectionId, 'Invalid JSON', 'parse_error');
      return;
    }

    // Validate message structure
    if (!this.validateMessage(message)) {
      this.sendError(connectionId, 'Invalid message structure', 'validation_error');
      return;
    }

    // Process by type
    switch (message.type) {
      case 'subscribe':
        this.handleSubscribe(connectionId, message);
        break;
      case 'unsubscribe':
        this.handleUnsubscribe(connectionId, message);
        break;
      case 'ping':
        this.handlePing(connectionId);
        break;
      case 'request':
        this.handleRequest(connectionId, message);
        break;
      default:
        this.sendError(connectionId, 'Unknown message type', 'unknown_type');
    }
  }

  /**
   * Handle subscription request
   */
  private handleSubscribe(connectionId: string, message: WSMessage): void {
    const connection = this.connections.get(connectionId);
    if (!connection) return;

    const { channel, data } = message;
    if (!channel) {
      this.sendError(connectionId, 'Channel required', 'missing_channel');
      return;
    }

    // Check subscription limit
    if (connection.subscriptions.size >= this.maxSubscriptionsPerConnection) {
      this.sendError(connectionId, 'Max subscriptions reached', 'subscription_limit');
      return;
    }

    // Check if private channel requires authentication
    if (this.isPrivateChannel(channel) && !connection.authenticated) {
      this.sendError(connectionId, 'Authentication required', 'auth_required');
      return;
    }

    // Create subscription
    const subscriptionId = crypto.randomBytes(16).toString('hex');
    const subscription: Subscription = {
      id: subscriptionId,
      connectionId,
      type: this.getChannelType(channel),
      channels: [channel],
      filters: data?.filters,
      createdAt: new Date(),
      messageCount: 0
    };

    connection.subscriptions.set(subscriptionId, subscription);

    // Add to channel index
    if (!this.subscriptions.has(channel)) {
      this.subscriptions.set(channel, new Set());
    }
    this.subscriptions.get(channel)!.add(connectionId);

    this.stats.totalSubscriptions++;

    this.emit('subscriptionCreated', subscription);

    // Send confirmation
    this.sendMessage(connectionId, {
      id: crypto.randomBytes(16).toString('hex'),
      type: 'response',
      channel: 'subscription',
      data: {
        subscriptionId,
        channel,
        status: 'subscribed'
      },
      timestamp: Date.now(),
      priority: MessagePriority.NORMAL
    });

    // Send initial snapshot if applicable
    this.sendInitialSnapshot(connectionId, channel);
  }

  /**
   * Handle unsubscribe request
   */
  private handleUnsubscribe(connectionId: string, message: WSMessage): void {
    const connection = this.connections.get(connectionId);
    if (!connection) return;

    const { channel } = message;
    if (!channel) {
      this.sendError(connectionId, 'Channel required', 'missing_channel');
      return;
    }

    // Find and remove subscription
    let found = false;
    for (const [subId, sub] of connection.subscriptions) {
      if (sub.channels.includes(channel)) {
        connection.subscriptions.delete(subId);
        found = true;
        break;
      }
    }

    if (found) {
      // Remove from channel index
      const channelSubs = this.subscriptions.get(channel);
      if (channelSubs) {
        channelSubs.delete(connectionId);
        if (channelSubs.size === 0) {
          this.subscriptions.delete(channel);
        }
      }

      this.stats.totalSubscriptions--;

      this.sendMessage(connectionId, {
        id: crypto.randomBytes(16).toString('hex'),
        type: 'response',
        channel: 'subscription',
        data: {
          channel,
          status: 'unsubscribed'
        },
        timestamp: Date.now(),
        priority: MessagePriority.NORMAL
      });
    }
  }

  /**
   * Handle ping message
   */
  private handlePing(connectionId: string): void {
    const connection = this.connections.get(connectionId);
    if (!connection) return;

    connection.lastPingAt = new Date();

    this.sendMessage(connectionId, {
      id: crypto.randomBytes(16).toString('hex'),
      type: 'pong',
      timestamp: Date.now(),
      priority: MessagePriority.CRITICAL
    });
  }

  /**
   * Handle data request
   */
  private handleRequest(connectionId: string, message: WSMessage): void {
    const connection = this.connections.get(connectionId);
    if (!connection) return;

    const { channel, data } = message;

    // Process different request types
    if (channel === 'orderbook') {
      this.sendOrderbookSnapshot(connectionId, data.symbol);
    } else if (channel === 'trades') {
      this.sendTradeHistory(connectionId, data.symbol, data.limit);
    } else if (channel === 'account' && connection.authenticated) {
      this.sendAccountInfo(connectionId);
    }
  }

  /**
   * Broadcast message to channel subscribers
   */
  broadcast(channel: string, data: any, priority: MessagePriority = MessagePriority.NORMAL): void {
    const subscribers = this.subscriptions.get(channel);
    if (!subscribers || subscribers.size === 0) return;

    const sequence = this.getNextSequence(channel);

    const message: WSMessage = {
      id: crypto.randomBytes(16).toString('hex'),
      type: 'event',
      channel,
      data: {
        ...data,
        sequence
      },
      timestamp: Date.now(),
      priority
    };

    // Batch messages for performance
    for (const connectionId of subscribers) {
      this.addToBuffer(connectionId, message);
    }

    this.messageHistory.push(subscribers.size);
    this.emit('messageBroadcast', { channel, subscriberCount: subscribers.size });
  }

  /**
   * Broadcast to specific user
   */
  broadcastToUser(userId: string, channel: string, data: any): void {
    const userConnections = Array.from(this.connections.values())
      .filter(c => c.userId === userId);

    const message: WSMessage = {
      id: crypto.randomBytes(16).toString('hex'),
      type: 'event',
      channel,
      data,
      timestamp: Date.now(),
      priority: MessagePriority.HIGH
    };

    for (const connection of userConnections) {
      this.sendMessage(connection.id, message);
    }
  }

  /**
   * Send message to specific connection
   */
  sendMessage(connectionId: string, message: WSMessage): void {
    const connection = this.connections.get(connectionId);
    if (!connection || connection.state !== ConnectionState.OPEN) return;

    const serialized = JSON.stringify(message);

    // Apply compression if needed
    const finalMessage = serialized.length > this.compressionThreshold
      ? this.compressMessage(serialized)
      : serialized;

    connection.bytesSent += finalMessage.length;

    this.emit('messageSent', { connectionId, message, size: finalMessage.length });
  }

  /**
   * Send error message
   */
  sendError(connectionId: string, message: string, code: string): void {
    this.sendMessage(connectionId, {
      id: crypto.randomBytes(16).toString('hex'),
      type: 'error',
      data: {
        code,
        message
      },
      timestamp: Date.now(),
      priority: MessagePriority.HIGH
    });
  }

  /**
   * Handle connection close
   */
  handleDisconnect(connectionId: string): void {
    const connection = this.connections.get(connectionId);
    if (!connection) return;

    connection.state = ConnectionState.CLOSED;

    // Clean up subscriptions
    for (const subscription of connection.subscriptions.values()) {
      for (const channel of subscription.channels) {
        const channelSubs = this.subscriptions.get(channel);
        if (channelSubs) {
          channelSubs.delete(connectionId);
          if (channelSubs.size === 0) {
            this.subscriptions.delete(channel);
          }
        }
      }
      this.stats.totalSubscriptions--;
    }

    this.connections.delete(connectionId);
    this.stats.activeConnections--;

    this.emit('connectionClosed', { connectionId, stats: this.getConnectionStats(connection) });
  }

  /**
   * Add load balancer node
   */
  addLoadBalancerNode(address: string, port: number, capacity: number): string {
    const nodeId = crypto.randomBytes(8).toString('hex');

    const node: LoadBalancerNode = {
      id: nodeId,
      address,
      port,
      connections: 0,
      capacity,
      healthy: true,
      lastHealthCheck: new Date()
    };

    this.loadBalancerNodes.push(node);
    return nodeId;
  }

  /**
   * Get best node for new connection
   */
  getBestNode(): LoadBalancerNode | null {
    const healthyNodes = this.loadBalancerNodes.filter(n => n.healthy && n.connections < n.capacity);

    if (healthyNodes.length === 0) return null;

    // Least connections strategy
    return healthyNodes.reduce((best, node) =>
      node.connections < best.connections ? node : best
    );
  }

  /**
   * Get server statistics
   */
  getStatistics(): ServerStats {
    // Calculate messages per second
    const recentMessages = this.messageHistory.slice(-60);
    this.stats.messagesPerSecond = recentMessages.length > 0
      ? recentMessages.reduce((sum, count) => sum + count, 0) / recentMessages.length
      : 0;

    return { ...this.stats };
  }

  /**
   * Get connection details
   */
  getConnectionInfo(connectionId: string): WSConnection | undefined {
    return this.connections.get(connectionId);
  }

  /**
   * Get all active subscriptions
   */
  getAllSubscriptions(): Map<string, Set<string>> {
    return new Map(this.subscriptions);
  }

  /**
   * Add allowed origin
   */
  addAllowedOrigin(origin: string): void {
    this.allowedOrigins.add(origin);
  }

  /**
   * Update rate limits
   */
  updateRateLimits(maxMessages: number, windowMs: number): void {
    this.defaultRateLimit.maxMessages = maxMessages;
    this.defaultRateLimit.windowMs = windowMs;
  }

  private isRateLimited(connection: WSConnection): boolean {
    const now = Date.now();
    const { rateLimit } = connection;

    // Reset window if expired
    if (now - rateLimit.windowStart > rateLimit.windowMs) {
      rateLimit.windowStart = now;
      rateLimit.messageCount = 0;
      rateLimit.blocked = false;
    }

    // Check if blocked
    if (rateLimit.blocked) {
      if (rateLimit.blockUntil && now > rateLimit.blockUntil) {
        rateLimit.blocked = false;
      } else {
        return true;
      }
    }

    // Check rate limit
    if (rateLimit.messageCount >= rateLimit.maxMessages) {
      rateLimit.blocked = true;
      rateLimit.blockUntil = now + rateLimit.windowMs;
      this.emit('rateLimitExceeded', { connectionId: connection.id });
      return true;
    }

    return false;
  }

  private validateMessage(message: any): message is WSMessage {
    return (
      typeof message === 'object' &&
      typeof message.type === 'string' &&
      ['subscribe', 'unsubscribe', 'request', 'ping', 'pong'].includes(message.type)
    );
  }

  private isPrivateChannel(channel: string): boolean {
    return channel.startsWith('account') ||
           channel.startsWith('orders') ||
           channel.startsWith('fills') ||
           channel.startsWith('positions');
  }

  private getChannelType(channel: string): SubscriptionType {
    if (channel.startsWith('ticker')) return SubscriptionType.TICKER;
    if (channel.startsWith('orderbook')) return SubscriptionType.ORDERBOOK;
    if (channel.startsWith('trades')) return SubscriptionType.TRADES;
    if (channel.startsWith('candles')) return SubscriptionType.CANDLES;
    if (channel.startsWith('account')) return SubscriptionType.ACCOUNT;
    if (channel.startsWith('orders')) return SubscriptionType.ORDERS;
    if (channel.startsWith('fills')) return SubscriptionType.FILLS;
    if (channel.startsWith('positions')) return SubscriptionType.POSITIONS;
    return SubscriptionType.TICKER;
  }

  private getNextSequence(channel: string): number {
    const current = this.channelSequences.get(channel) || 0;
    const next = current + 1;
    this.channelSequences.set(channel, next);
    return next;
  }

  private addToBuffer(connectionId: string, message: WSMessage): void {
    if (!this.messageBuffer.has(connectionId)) {
      this.messageBuffer.set(connectionId, []);
    }

    const buffer = this.messageBuffer.get(connectionId)!;
    buffer.push(message);

    // Prioritize critical messages
    buffer.sort((a, b) => a.priority - b.priority);
  }

  private flushBuffers(): void {
    for (const [connectionId, messages] of this.messageBuffer) {
      if (messages.length === 0) continue;

      // Batch send
      for (const message of messages) {
        this.sendMessage(connectionId, message);
      }

      this.messageBuffer.set(connectionId, []);
    }
  }

  private verifyToken(token: string): AuthToken | null {
    // In production, verify JWT signature
    // Simplified: decode and validate
    try {
      const decoded = JSON.parse(Buffer.from(token, 'base64').toString());

      if (new Date(decoded.expiresAt) < new Date()) {
        return null;
      }

      return decoded as AuthToken;
    } catch {
      return null;
    }
  }

  private compressMessage(message: string): string {
    // In production, use zlib compression
    return message;
  }

  private sendInitialSnapshot(connectionId: string, channel: string): void {
    // Send current state for the channel
    this.emit('snapshotRequested', { connectionId, channel });
  }

  private sendOrderbookSnapshot(connectionId: string, symbol: string): void {
    this.emit('orderbookSnapshotRequested', { connectionId, symbol });
  }

  private sendTradeHistory(connectionId: string, symbol: string, limit: number): void {
    this.emit('tradeHistoryRequested', { connectionId, symbol, limit });
  }

  private sendAccountInfo(connectionId: string): void {
    this.emit('accountInfoRequested', { connectionId });
  }

  private getConnectionStats(connection: WSConnection): any {
    return {
      duration: Date.now() - connection.createdAt.getTime(),
      messageCount: connection.messageCount,
      bytesReceived: connection.bytesReceived,
      bytesSent: connection.bytesSent,
      subscriptionCount: connection.subscriptions.size
    };
  }

  private startPeriodicTasks(): void {
    // Flush message buffers
    setInterval(() => {
      this.flushBuffers();
    }, this.bufferFlushInterval);

    // Send pings to check connection health
    setInterval(() => {
      const now = new Date();
      for (const [connectionId, connection] of this.connections) {
        if (connection.state !== ConnectionState.OPEN) continue;

        const timeSincePong = now.getTime() - connection.lastPongAt.getTime();

        if (timeSincePong > this.pingInterval + this.pongTimeout) {
          // Connection dead
          this.handleDisconnect(connectionId);
        } else if (timeSincePong > this.pingInterval) {
          // Send ping
          this.sendMessage(connectionId, {
            id: crypto.randomBytes(16).toString('hex'),
            type: 'ping',
            timestamp: Date.now(),
            priority: MessagePriority.CRITICAL
          });
        }
      }
    }, this.pingInterval);

    // Health check load balancer nodes
    setInterval(() => {
      for (const node of this.loadBalancerNodes) {
        this.checkNodeHealth(node);
      }
    }, 10000);

    // Update statistics
    setInterval(() => {
      this.stats.cpuUsage = Math.random() * 0.3; // Simulated
      this.stats.memoryUsage = process.memoryUsage().heapUsed;

      // Trim message history
      if (this.messageHistory.length > 3600) {
        this.messageHistory = this.messageHistory.slice(-3600);
      }
    }, 1000);
  }

  private checkNodeHealth(node: LoadBalancerNode): void {
    // In production, actually ping the node
    node.lastHealthCheck = new Date();
    this.emit('nodeHealthCheck', node);
  }
}

// Export types
export {
  ConnectionState,
  MessagePriority,
  SubscriptionType,
  WSConnection,
  Subscription,
  WSMessage,
  RateLimitState,
  ServerStats,
  ChannelData,
  AuthToken,
  LoadBalancerNode
};
