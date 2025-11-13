/**
 * KYC/AML Service Integration
 *
 * Integrates with Jumio, Onfido, or Chainalysis for compliance
 */

import axios, { AxiosInstance } from 'axios';

export enum KYCLevel {
  NONE = 0,
  BASIC = 1,      // Email + Phone verification
  INTERMEDIATE = 2, // ID document verification
  ADVANCED = 3,    // Enhanced due diligence + source of funds
}

export enum DocumentType {
  PASSPORT = 'PASSPORT',
  DRIVERS_LICENSE = 'DRIVERS_LICENSE',
  NATIONAL_ID = 'NATIONAL_ID',
  PROOF_OF_ADDRESS = 'PROOF_OF_ADDRESS',
}

export interface KYCSubmission {
  userId: string;
  walletAddress: string;
  level: KYCLevel;
  documents: DocumentSubmission[];
  personalInfo: PersonalInfo;
}

export interface DocumentSubmission {
  type: DocumentType;
  frontImage: string; // Base64 or URL
  backImage?: string;
  selfieImage?: string;
}

export interface PersonalInfo {
  firstName: string;
  lastName: string;
  dateOfBirth: string;
  nationality: string;
  email: string;
  phone: string;
  address: Address;
}

export interface Address {
  street: string;
  city: string;
  state: string;
  postalCode: string;
  country: string;
}

export interface KYCResult {
  userId: string;
  status: 'approved' | 'rejected' | 'pending' | 'review_required';
  level: KYCLevel;
  verificationId: string;
  riskScore?: number;
  documentsHash: string;
  expiresAt: Date;
  rejectionReason?: string;
}

/**
 * Jumio KYC Integration
 */
export class JumioKYCProvider {
  private client: AxiosInstance;
  private apiToken: string;
  private apiSecret: string;

  constructor(apiToken: string, apiSecret: string, isProduction: boolean = false) {
    this.apiToken = apiToken;
    this.apiSecret = apiSecret;

    const baseURL = isProduction
      ? 'https://netverify.com/api'
      : 'https://netverify.amer-1.jumio.ai/api';

    this.client = axios.create({
      baseURL,
      auth: {
        username: apiToken,
        password: apiSecret,
      },
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'DEX-Gateway/1.0',
      },
    });
  }

  /**
   * Initiate KYC verification
   */
  async initiateVerification(submission: KYCSubmission): Promise<string> {
    const response = await this.client.post('/v4/initiate', {
      customerInternalReference: submission.userId,
      userReference: submission.walletAddress,
      callbackUrl: process.env.KYC_WEBHOOK_URL,
      workflowId: this.getWorkflowId(submission.level),
    });

    return response.data.redirectUrl;
  }

  /**
   * Get verification status
   */
  async getVerificationStatus(verificationId: string): Promise<KYCResult> {
    const response = await this.client.get(`/v4/accounts/${verificationId}`);

    const data = response.data;
    const status = this.mapJumioStatus(data.status);

    return {
      userId: data.customerInternalReference,
      status,
      level: this.mapToKYCLevel(data.verificationLevel),
      verificationId,
      riskScore: data.riskAssessment?.score,
      documentsHash: this.hashDocuments(data.documents),
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
      rejectionReason: data.rejectReason?.description,
    };
  }

  /**
   * Webhook handler for verification updates
   */
  async handleWebhook(payload: any, signature: string): Promise<KYCResult> {
    // Verify webhook signature
    if (!this.verifyWebhookSignature(payload, signature)) {
      throw new Error('Invalid webhook signature');
    }

    return this.getVerificationStatus(payload.verificationId);
  }

  private getWorkflowId(level: KYCLevel): string {
    switch (level) {
      case KYCLevel.BASIC:
        return 'basic-verification';
      case KYCLevel.INTERMEDIATE:
        return 'standard-verification';
      case KYCLevel.ADVANCED:
        return 'enhanced-verification';
      default:
        throw new Error('Invalid KYC level');
    }
  }

  private mapJumioStatus(status: string): KYCResult['status'] {
    switch (status) {
      case 'APPROVED_VERIFIED':
        return 'approved';
      case 'DENIED_FRAUD':
      case 'DENIED_UNSUPPORTED_ID_TYPE':
        return 'rejected';
      case 'PENDING':
        return 'pending';
      default:
        return 'review_required';
    }
  }

  private mapToKYCLevel(verificationLevel: string): KYCLevel {
    if (verificationLevel.includes('ENHANCED')) {
      return KYCLevel.ADVANCED;
    } else if (verificationLevel.includes('STANDARD')) {
      return KYCLevel.INTERMEDIATE;
    }
    return KYCLevel.BASIC;
  }

  private hashDocuments(documents: any[]): string {
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256');

    for (const doc of documents) {
      hash.update(JSON.stringify(doc));
    }

    return hash.digest('hex');
  }

  private verifyWebhookSignature(payload: any, signature: string): boolean {
    const crypto = require('crypto');
    const hmac = crypto.createHmac('sha256', this.apiSecret);
    hmac.update(JSON.stringify(payload));
    const computed = hmac.digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(computed)
    );
  }
}

/**
 * Chainalysis AML Screening
 */
export class ChainalysisAMLProvider {
  private client: AxiosInstance;
  private apiKey: string;

  constructor(apiKey: string) {
    this.apiKey = apiKey;

    this.client = axios.create({
      baseURL: 'https://api.chainalysis.com',
      headers: {
        'Token': apiKey,
        'Content-Type': 'application/json',
      },
    });
  }

  /**
   * Screen wallet address for sanctions/risk
   */
  async screenAddress(address: string): Promise<RiskAssessment> {
    const response = await this.client.post('/api/kyt/v2/users', {
      address,
      asset: 'ETH',
      direction: 'received',
    });

    const alerts = await this.client.get(`/api/kyt/v2/users/${response.data.userId}/alerts`);

    const riskScore = this.calculateRiskScore(alerts.data);

    return {
      address,
      riskLevel: this.getRiskLevel(riskScore),
      riskScore,
      sanctioned: alerts.data.some((a: any) => a.alertLevel === 'SEVERE'),
      alerts: alerts.data.map((a: any) => ({
        type: a.alertType,
        severity: a.alertLevel,
        description: a.description,
      })),
    };
  }

  /**
   * Monitor transactions for ongoing compliance
   */
  async monitorTransaction(
    txHash: string,
    address: string
  ): Promise<TransactionRisk> {
    const response = await this.client.post('/api/kyt/v2/transfers', {
      transferReference: txHash,
      asset: 'ETH',
      network: 'ethereum',
      direction: 'received',
      receivedAmount: 0, // Would be actual amount
      receivedAddress: address,
    });

    return {
      txHash,
      riskScore: response.data.rating,
      alerts: response.data.alerts || [],
      approved: response.data.rating < 500, // Threshold
    };
  }

  private calculateRiskScore(alerts: any[]): number {
    if (alerts.length === 0) return 0;

    const severityScores = {
      SEVERE: 1000,
      HIGH: 700,
      MEDIUM: 400,
      LOW: 100,
    };

    const maxScore = Math.max(
      ...alerts.map((a) => severityScores[a.alertLevel as keyof typeof severityScores] || 0)
    );

    return maxScore;
  }

  private getRiskLevel(score: number): 'low' | 'medium' | 'high' | 'severe' {
    if (score >= 1000) return 'severe';
    if (score >= 700) return 'high';
    if (score >= 400) return 'medium';
    return 'low';
  }
}

export interface RiskAssessment {
  address: string;
  riskLevel: 'low' | 'medium' | 'high' | 'severe';
  riskScore: number;
  sanctioned: boolean;
  alerts: Array<{
    type: string;
    severity: string;
    description: string;
  }>;
}

export interface TransactionRisk {
  txHash: string;
  riskScore: number;
  alerts: any[];
  approved: boolean;
}

/**
 * Combined KYC/AML Service
 */
export class ComplianceService {
  private kycProvider: JumioKYCProvider;
  private amlProvider: ChainalysisAMLProvider;

  constructor(
    jumioToken: string,
    jumioSecret: string,
    chainalysisKey: string
  ) {
    this.kycProvider = new JumioKYCProvider(jumioToken, jumioSecret);
    this.amlProvider = new ChainalysisAMLProvider(chainalysisKey);
  }

  /**
   * Full compliance check (KYC + AML)
   */
  async performComplianceCheck(
    submission: KYCSubmission
  ): Promise<{ kyc: KYCResult; aml: RiskAssessment }> {
    // Run KYC and AML in parallel
    const [kycUrl, amlResult] = await Promise.all([
      this.kycProvider.initiateVerification(submission),
      this.amlProvider.screenAddress(submission.walletAddress),
    ]);

    console.log('KYC verification URL:', kycUrl);

    // AML screening must pass
    if (amlResult.sanctioned || amlResult.riskLevel === 'severe') {
      throw new Error('AML screening failed: High risk or sanctioned address');
    }

    // Wait for KYC completion (in real implementation, use webhooks)
    // For now, return pending status
    const kycResult: KYCResult = {
      userId: submission.userId,
      status: 'pending',
      level: submission.level,
      verificationId: 'pending',
      documentsHash: '',
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    };

    return { kyc: kycResult, aml: amlResult };
  }
}

/**
 * Example usage
 */
export async function exampleKYCFlow() {
  const compliance = new ComplianceService(
    process.env.JUMIO_API_TOKEN!,
    process.env.JUMIO_API_SECRET!,
    process.env.CHAINALYSIS_API_KEY!
  );

  const submission: KYCSubmission = {
    userId: 'user-123',
    walletAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
    level: KYCLevel.INTERMEDIATE,
    documents: [
      {
        type: DocumentType.PASSPORT,
        frontImage: 'base64...',
        selfieImage: 'base64...',
      },
    ],
    personalInfo: {
      firstName: 'John',
      lastName: 'Doe',
      dateOfBirth: '1990-01-01',
      nationality: 'US',
      email: 'john@example.com',
      phone: '+1234567890',
      address: {
        street: '123 Main St',
        city: 'New York',
        state: 'NY',
        postalCode: '10001',
        country: 'US',
      },
    },
  };

  const result = await compliance.performComplianceCheck(submission);
  console.log('Compliance check result:', result);
}
