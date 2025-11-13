/**
 * Circle API Integration for USDC/EURC Minting and Redemption
 *
 * Provides institutional-grade fiat on/off ramps via Circle
 */

import axios, { AxiosInstance } from 'axios';
import crypto from 'crypto';

export interface CircleConfig {
  apiKey: string;
  apiSecret: string;
  baseUrl: string;
  environment: 'sandbox' | 'production';
}

export interface BankAccount {
  id: string;
  accountNumber: string;
  routingNumber: string;
  bankName: string;
  currency: 'USD' | 'EUR';
}

export interface WireTransfer {
  id: string;
  amount: number;
  currency: string;
  status: 'pending' | 'confirmed' | 'failed';
  externalRef: string;
}

export interface MintRequest {
  amount: number;
  currency: 'USD' | 'EUR';
  destination: string; // Ethereum address
  sourceWireTransfer: string;
}

export interface RedemptionRequest {
  amount: number;
  currency: 'USD' | 'EUR';
  bankAccount: string;
  destination: BankAccount;
}

/**
 * Circle API Client
 */
export class CircleAPIClient {
  private client: AxiosInstance;
  private config: CircleConfig;

  constructor(config: CircleConfig) {
    this.config = config;

    const baseURL = config.environment === 'production'
      ? 'https://api.circle.com'
      : 'https://api-sandbox.circle.com';

    this.client = axios.create({
      baseURL,
      headers: {
        'Authorization': `Bearer ${config.apiKey}`,
        'Content-Type': 'application/json',
      },
    });
  }

  /**
   * Create bank account for wire transfers
   */
  async createBankAccount(account: Omit<BankAccount, 'id'>): Promise<BankAccount> {
    const response = await this.client.post('/v1/banks/wires', {
      idempotencyKey: this.generateIdempotencyKey(),
      accountNumber: account.accountNumber,
      routingNumber: account.routingNumber,
      billingDetails: {
        name: account.bankName,
        country: account.currency === 'USD' ? 'US' : 'EU',
      },
      bankAddress: {
        bankName: account.bankName,
      },
    });

    return {
      id: response.data.data.id,
      ...account,
    };
  }

  /**
   * Initiate wire transfer for USDC minting
   */
  async initiateWireTransfer(
    amount: number,
    currency: 'USD' | 'EUR',
    sourceAccount: string
  ): Promise<WireTransfer> {
    const response = await this.client.post('/v1/transfers', {
      idempotencyKey: this.generateIdempotencyKey(),
      source: {
        type: 'wire',
        id: sourceAccount,
      },
      destination: {
        type: 'wallet',
        id: 'master', // Circle's master wallet
      },
      amount: {
        amount: amount.toString(),
        currency,
      },
    });

    return {
      id: response.data.data.id,
      amount,
      currency,
      status: 'pending',
      externalRef: response.data.data.trackingRef,
    };
  }

  /**
   * Request USDC/EURC minting after wire confirmed
   */
  async mintStablecoin(request: MintRequest): Promise<string> {
    const stablecoin = request.currency === 'USD' ? 'USDC' : 'EURC';

    const response = await this.client.post('/v1/transfers', {
      idempotencyKey: this.generateIdempotencyKey(),
      source: {
        type: 'wallet',
        id: 'master',
      },
      destination: {
        type: 'blockchain',
        address: request.destination,
        chain: 'ETH', // Can support multiple chains
      },
      amount: {
        amount: request.amount.toString(),
        currency: stablecoin,
      },
    });

    return response.data.data.id; // Transaction ID
  }

  /**
   * Redeem USDC/EURC for fiat
   */
  async redeemStablecoin(request: RedemptionRequest): Promise<string> {
    const stablecoin = request.currency === 'USD' ? 'USDC' : 'EURC';

    // First, receive stablecoin to Circle wallet
    const receiveResponse = await this.client.post('/v1/transfers', {
      idempotencyKey: this.generateIdempotencyKey(),
      source: {
        type: 'blockchain',
        chain: 'ETH',
      },
      destination: {
        type: 'wallet',
        id: 'master',
      },
      amount: {
        amount: request.amount.toString(),
        currency: stablecoin,
      },
    });

    // Then, initiate wire transfer to bank
    const wireResponse = await this.client.post('/v1/transfers', {
      idempotencyKey: this.generateIdempotencyKey(),
      source: {
        type: 'wallet',
        id: 'master',
      },
      destination: {
        type: 'wire',
        id: request.bankAccount,
      },
      amount: {
        amount: request.amount.toString(),
        currency: request.currency,
      },
    });

    return wireResponse.data.data.id;
  }

  /**
   * Get transfer status
   */
  async getTransferStatus(transferId: string): Promise<WireTransfer> {
    const response = await this.client.get(`/v1/transfers/${transferId}`);

    return {
      id: response.data.data.id,
      amount: parseFloat(response.data.data.amount.amount),
      currency: response.data.data.amount.currency,
      status: response.data.data.status,
      externalRef: response.data.data.trackingRef || '',
    };
  }

  /**
   * Get Circle account balance
   */
  async getBalance(): Promise<{ [currency: string]: number }> {
    const response = await this.client.get('/v1/balances');

    const balances: { [currency: string]: number } = {};

    for (const balance of response.data.data) {
      balances[balance.currency] = parseFloat(balance.amount);
    }

    return balances;
  }

  /**
   * List all wire transfers
   */
  async listTransfers(
    startDate?: Date,
    endDate?: Date
  ): Promise<WireTransfer[]> {
    const params: any = {};

    if (startDate) {
      params.from = startDate.toISOString();
    }

    if (endDate) {
      params.to = endDate.toISOString();
    }

    const response = await this.client.get('/v1/transfers', { params });

    return response.data.data.map((transfer: any) => ({
      id: transfer.id,
      amount: parseFloat(transfer.amount.amount),
      currency: transfer.amount.currency,
      status: transfer.status,
      externalRef: transfer.trackingRef || '',
    }));
  }

  /**
   * Webhook signature verification
   */
  verifyWebhookSignature(
    payload: string,
    signature: string
  ): boolean {
    const hmac = crypto.createHmac('sha256', this.config.apiSecret);
    hmac.update(payload);
    const computed = hmac.digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(computed)
    );
  }

  /**
   * Generate idempotency key for requests
   */
  private generateIdempotencyKey(): string {
    return crypto.randomUUID();
  }
}

/**
 * MoonPay Integration (Alternative provider)
 */
export class MoonPayClient {
  private apiKey: string;
  private baseUrl: string;

  constructor(apiKey: string, isProduction: boolean = false) {
    this.apiKey = apiKey;
    this.baseUrl = isProduction
      ? 'https://api.moonpay.com'
      : 'https://api-sandbox.moonpay.com';
  }

  /**
   * Generate widget URL for on-ramp
   */
  generateWidgetUrl(
    walletAddress: string,
    currency: string = 'USDC',
    amount?: number
  ): string {
    const params = new URLSearchParams({
      apiKey: this.apiKey,
      walletAddress,
      currencyCode: currency,
      colorCode: '#4F46E5',
    });

    if (amount) {
      params.append('baseCurrencyAmount', amount.toString());
    }

    return `${this.baseUrl}/buy?${params.toString()}`;
  }

  /**
   * Generate sell widget URL for off-ramp
   */
  generateSellWidgetUrl(
    walletAddress: string,
    currency: string = 'USDC'
  ): string {
    const params = new URLSearchParams({
      apiKey: this.apiKey,
      walletAddress,
      baseCurrencyCode: currency,
    });

    return `${this.baseUrl}/sell?${params.toString()}`;
  }
}

/**
 * Example usage
 */
export async function exampleCircleIntegration() {
  const circleClient = new CircleAPIClient({
    apiKey: process.env.CIRCLE_API_KEY!,
    apiSecret: process.env.CIRCLE_API_SECRET!,
    baseUrl: 'https://api-sandbox.circle.com',
    environment: 'sandbox',
  });

  // Create bank account
  const bankAccount = await circleClient.createBankAccount({
    accountNumber: '1234567890',
    routingNumber: '021000021',
    bankName: 'Chase Bank',
    currency: 'USD',
  });

  console.log('Bank account created:', bankAccount.id);

  // Initiate wire transfer
  const transfer = await circleClient.initiateWireTransfer(
    10000,
    'USD',
    bankAccount.id
  );

  console.log('Wire transfer initiated:', transfer.externalRef);

  // Mint USDC after wire confirmed
  const mintTx = await circleClient.mintStablecoin({
    amount: 10000,
    currency: 'USD',
    destination: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
    sourceWireTransfer: transfer.id,
  });

  console.log('USDC mint transaction:', mintTx);

  // Check balance
  const balances = await circleClient.getBalance();
  console.log('Circle balances:', balances);
}
