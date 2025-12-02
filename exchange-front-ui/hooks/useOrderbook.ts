/**
 * Orderbook React Hook
 *
 * Provides real-time orderbook data and trading functions
 */

import { useState, useEffect, useCallback } from 'react';
import { ethers } from 'ethers';
import { useWallet } from './useWallet';

interface OrderbookLevel {
  price: number;
  size: number;
  total: number;
}

interface Trade {
  id: string;
  price: number;
  size: number;
  side: 'buy' | 'sell';
  timestamp: number;
}

const ORDERBOOK_ABI = [
  'function placeLimitOrder(address,address,uint8,uint256,uint256) returns (bytes32)',
  'function placeMarketOrder(address,address,uint8,uint256) returns (bytes32)',
  'function cancelOrder(bytes32)',
  'function getOrderbook(address,address,uint256) view returns (uint256[],uint256[],uint256[],uint256[])',
  'event OrderPlaced(bytes32 indexed orderId, address indexed trader, uint8 side, uint256 price, uint256 amount)',
  'event TradeExecuted(bytes32 indexed tradeId, bytes32 makerOrderId, bytes32 takerOrderId, uint256 price, uint256 amount)',
  'event OrderCancelled(bytes32 indexed orderId)',
];

const ORDERBOOK_ADDRESS = process.env.NEXT_PUBLIC_ORDERBOOK_ADDRESS || '';
const USDC_ADDRESS = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const WETH_ADDRESS = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';

export function useOrderbook() {
  const { provider, signer } = useWallet();

  const [bids, setBids] = useState<OrderbookLevel[]>([]);
  const [asks, setAsks] = useState<OrderbookLevel[]>([]);
  const [trades, setTrades] = useState<Trade[]>([]);
  const [loading, setLoading] = useState(true);

  const orderbookContract = signer
    ? new ethers.Contract(ORDERBOOK_ADDRESS, ORDERBOOK_ABI, signer)
    : provider
    ? new ethers.Contract(ORDERBOOK_ADDRESS, ORDERBOOK_ABI, provider)
    : null;

  /**
   * Fetch orderbook data
   */
  const fetchOrderbook = useCallback(async () => {
    if (!orderbookContract) return;

    try {
      const [bidPrices, bidSizes, askPrices, askSizes] =
        await orderbookContract.getOrderbook(USDC_ADDRESS, WETH_ADDRESS, 20);

      // Convert to orderbook levels
      const bidLevels: OrderbookLevel[] = bidPrices.map((price: bigint, i: number) => ({
        price: parseFloat(ethers.formatEther(price)),
        size: parseFloat(ethers.formatUnits(bidSizes[i], 6)),
        total: parseFloat(ethers.formatEther(price)) * parseFloat(ethers.formatUnits(bidSizes[i], 6)),
      }));

      const askLevels: OrderbookLevel[] = askPrices.map((price: bigint, i: number) => ({
        price: parseFloat(ethers.formatEther(price)),
        size: parseFloat(ethers.formatUnits(askSizes[i], 6)),
        total: parseFloat(ethers.formatEther(price)) * parseFloat(ethers.formatUnits(askSizes[i], 6)),
      }));

      setBids(bidLevels);
      setAsks(askLevels);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch orderbook:', error);
    }
  }, [orderbookContract]);

  /**
   * Place limit order
   */
  const placeLimitOrder = useCallback(
    async (side: 'buy' | 'sell', price: number, amount: number) => {
      if (!orderbookContract || !signer) {
        throw new Error('Wallet not connected');
      }

      const priceWei = ethers.parseEther(price.toString());
      const amountWei = ethers.parseUnits(amount.toString(), 6);
      const sideEnum = side === 'buy' ? 0 : 1;

      const tx = await orderbookContract.placeLimitOrder(
        USDC_ADDRESS,
        WETH_ADDRESS,
        sideEnum,
        priceWei,
        amountWei
      );

      const receipt = await tx.wait();

      console.log('Order placed:', receipt.hash);

      // Refresh orderbook
      await fetchOrderbook();

      return receipt.hash;
    },
    [orderbookContract, signer, fetchOrderbook]
  );

  /**
   * Place market order
   */
  const placeMarketOrder = useCallback(
    async (side: 'buy' | 'sell', amount: number) => {
      if (!orderbookContract || !signer) {
        throw new Error('Wallet not connected');
      }

      const amountWei = ethers.parseUnits(amount.toString(), 6);
      const sideEnum = side === 'buy' ? 0 : 1;

      const tx = await orderbookContract.placeMarketOrder(
        USDC_ADDRESS,
        WETH_ADDRESS,
        sideEnum,
        amountWei
      );

      const receipt = await tx.wait();

      console.log('Market order placed:', receipt.hash);

      // Refresh orderbook
      await fetchOrderbook();

      return receipt.hash;
    },
    [orderbookContract, signer, fetchOrderbook]
  );

  /**
   * Cancel order
   */
  const cancelOrder = useCallback(
    async (orderId: string) => {
      if (!orderbookContract || !signer) {
        throw new Error('Wallet not connected');
      }

      const tx = await orderbookContract.cancelOrder(orderId);
      await tx.wait();

      // Refresh orderbook
      await fetchOrderbook();
    },
    [orderbookContract, signer, fetchOrderbook]
  );

  /**
   * Listen to trade events
   */
  useEffect(() => {
    if (!orderbookContract) return;

    const handleTradeEvent = (
      tradeId: string,
      makerOrderId: string,
      takerOrderId: string,
      price: bigint,
      amount: bigint
    ) => {
      const trade: Trade = {
        id: tradeId,
        price: parseFloat(ethers.formatEther(price)),
        size: parseFloat(ethers.formatUnits(amount, 6)),
        side: 'buy', // Would determine from event data
        timestamp: Date.now(),
      };

      setTrades((prev) => [trade, ...prev].slice(0, 100));

      // Refresh orderbook after trade
      fetchOrderbook();
    };

    orderbookContract.on('TradeExecuted', handleTradeEvent);

    return () => {
      orderbookContract.off('TradeExecuted', handleTradeEvent);
    };
  }, [orderbookContract, fetchOrderbook]);

  /**
   * Periodic orderbook refresh
   */
  useEffect(() => {
    fetchOrderbook();

    const interval = setInterval(() => {
      fetchOrderbook();
    }, 2000); // Refresh every 2 seconds

    return () => clearInterval(interval);
  }, [fetchOrderbook]);

  return {
    bids,
    asks,
    trades,
    loading,
    placeLimitOrder,
    placeMarketOrder,
    cancelOrder,
    refresh: fetchOrderbook,
  };
}
