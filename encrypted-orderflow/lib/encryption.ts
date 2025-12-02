/**
 * Client-side order encryption library
 * Uses threshold BLS encryption for MEV protection
 */

import { ethers } from 'ethers';
import * as bls from '@noble/bls12-381';

export interface Order {
  trader: string;
  tokenIn: string;
  tokenOut: string;
  amountIn: bigint;
  minAmountOut: bigint;
  deadline: number;
  orderType: OrderType;
}

export enum OrderType {
  MARKET = 0,
  LIMIT = 1,
  STOP_LOSS = 2
}

export interface EncryptedOrderData {
  encryptedData: Uint8Array;
  commitmentHash: string;
  publicKey: Uint8Array;
}

/**
 * Threshold encryption client for order submission
 */
export class ThresholdEncryptionClient {
  private publicKey: Uint8Array;
  private sequencerEndpoint: string;

  constructor(sequencerEndpoint: string) {
    this.sequencerEndpoint = sequencerEndpoint;
  }

  /**
   * Fetch current threshold public key from sequencer network
   */
  async fetchPublicKey(): Promise<void> {
    const response = await fetch(`${this.sequencerEndpoint}/encryption/pubkey`);
    const { publicKey } = await response.json();
    this.publicKey = new Uint8Array(Buffer.from(publicKey, 'hex'));
  }

  /**
   * Encrypt order using threshold BLS encryption
   */
  async encryptOrder(order: Order): Promise<EncryptedOrderData> {
    if (!this.publicKey) {
      await this.fetchPublicKey();
    }

    // Encode order data
    const encodedOrder = this.encodeOrder(order);

    // Generate ephemeral key pair
    const ephemeralSecret = bls.utils.randomPrivateKey();
    const ephemeralPublic = bls.getPublicKey(ephemeralSecret);

    // Compute shared secret using BLS pairing
    const sharedSecret = await this.computeSharedSecret(
      ephemeralSecret,
      this.publicKey
    );

    // Encrypt using AES-GCM with shared secret
    const encryptedData = await this.aesGcmEncrypt(encodedOrder, sharedSecret);

    // Create commitment hash (for non-repudiation)
    const commitmentHash = ethers.keccak256(encodedOrder);

    return {
      encryptedData: new Uint8Array([
        ...ephemeralPublic,
        ...encryptedData
      ]),
      commitmentHash,
      publicKey: this.publicKey
    };
  }

  /**
   * Submit encrypted order to mempool
   */
  async submitOrder(
    contract: ethers.Contract,
    order: Order
  ): Promise<string> {
    const encrypted = await this.encryptOrder(order);

    // Submit to smart contract
    const tx = await contract.submitEncryptedOrder(
      encrypted.encryptedData,
      encrypted.commitmentHash
    );

    const receipt = await tx.wait();
    const event = receipt.events?.find((e: any) => e.event === 'OrderSubmitted');

    return event?.args?.orderId;
  }

  /**
   * Encode order to bytes
   */
  private encodeOrder(order: Order): Uint8Array {
    const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
      [
        'tuple(address trader, address tokenIn, address tokenOut, uint256 amountIn, uint256 minAmountOut, uint256 deadline, uint8 orderType)'
      ],
      [order]
    );

    return ethers.getBytes(encoded);
  }

  /**
   * Compute BLS shared secret
   */
  private async computeSharedSecret(
    privateKey: Uint8Array,
    publicKey: Uint8Array
  ): Promise<Uint8Array> {
    // Use BLS pairing for key exchange
    const point = bls.G1.ProjectivePoint.fromHex(publicKey);
    const shared = point.multiply(BigInt('0x' + Buffer.from(privateKey).toString('hex')));

    return shared.toRawBytes();
  }

  /**
   * AES-GCM encryption
   */
  private async aesGcmEncrypt(
    plaintext: Uint8Array,
    key: Uint8Array
  ): Promise<Uint8Array> {
    const crypto = globalThis.crypto || require('crypto').webcrypto;

    // Derive AES key from shared secret
    const aesKey = await crypto.subtle.importKey(
      'raw',
      key.slice(0, 32),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      plaintext
    );

    // Prepend IV to ciphertext
    return new Uint8Array([...iv, ...new Uint8Array(ciphertext)]);
  }
}

/**
 * Example usage
 */
export async function exampleOrderSubmission() {
  const provider = new ethers.JsonRpcProvider('http://localhost:8545');
  const signer = await provider.getSigner();

  const encryptionClient = new ThresholdEncryptionClient('http://localhost:3000');

  const order: Order = {
    trader: await signer.getAddress(),
    tokenIn: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC
    tokenOut: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', // WETH
    amountIn: ethers.parseUnits('1000', 6),
    minAmountOut: ethers.parseEther('0.5'),
    deadline: Math.floor(Date.now() / 1000) + 3600,
    orderType: OrderType.MARKET
  };

  const orderbookContract = new ethers.Contract(
    '0x...', // Contract address
    ['function submitEncryptedOrder(bytes,bytes32) returns (bytes32)'],
    signer
  );

  const orderId = await encryptionClient.submitOrder(orderbookContract, order);
  console.log(`Order submitted: ${orderId}`);

  return orderId;
}
