/**
 * Main Trading Interface Component
 *
 * Features:
 * - Real-time orderbook display
 * - Order entry panel
 * - Trade history
 * - Position management
 * - Latency monitoring
 */

import React, { useState, useEffect, useCallback } from 'react';
import { ethers } from 'ethers';
import { useOrderbook } from '../hooks/useOrderbook';
import { useWallet } from '../hooks/useWallet';

interface Order {
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

export const TradingInterface: React.FC = () => {
  const { account, signer } = useWallet();
  const { bids, asks, trades, placeLimitOrder, placeMarketOrder } = useOrderbook();

  const [orderType, setOrderType] = useState<'limit' | 'market'>('limit');
  const [orderSide, setOrderSide] = useState<'buy' | 'sell'>('buy');
  const [price, setPrice] = useState<string>('');
  const [amount, setAmount] = useState<string>('');
  const [latency, setLatency] = useState<number>(0);

  /**
   * Submit order
   */
  const handleSubmitOrder = useCallback(async () => {
    if (!signer) {
      alert('Please connect wallet');
      return;
    }

    const start = performance.now();

    try {
      if (orderType === 'limit') {
        await placeLimitOrder(
          orderSide,
          parseFloat(price),
          parseFloat(amount)
        );
      } else {
        await placeMarketOrder(orderSide, parseFloat(amount));
      }

      const end = performance.now();
      setLatency(end - start);

      // Reset form
      setPrice('');
      setAmount('');
    } catch (error) {
      console.error('Order submission failed:', error);
      alert('Order failed: ' + (error as Error).message);
    }
  }, [signer, orderType, orderSide, price, amount, placeLimitOrder, placeMarketOrder]);

  return (
    <div className="trading-interface">
      {/* Header */}
      <div className="header">
        <h1>MEV-Resistant DEX</h1>
        <div className="stats">
          <div className="stat">
            <span className="label">Latency:</span>
            <span className={`value ${latency < 100 ? 'good' : latency < 500 ? 'medium' : 'poor'}`}>
              {latency.toFixed(0)}ms
            </span>
          </div>
          <div className="stat">
            <span className="label">Wallet:</span>
            <span className="value">{account ? `${account.slice(0, 6)}...${account.slice(-4)}` : 'Not connected'}</span>
          </div>
        </div>
      </div>

      {/* Main Layout */}
      <div className="main-layout">
        {/* Orderbook */}
        <div className="orderbook-panel">
          <h2>Orderbook</h2>
          <div className="orderbook">
            {/* Asks (sells) */}
            <div className="asks">
              {asks.slice(0, 15).reverse().map((ask, i) => (
                <OrderRow key={i} order={ask} side="sell" />
              ))}
            </div>

            {/* Spread */}
            <div className="spread">
              <span className="spread-value">
                {asks.length > 0 && bids.length > 0
                  ? `Spread: ${(asks[0].price - bids[0].price).toFixed(2)}`
                  : 'No market'}
              </span>
            </div>

            {/* Bids (buys) */}
            <div className="bids">
              {bids.slice(0, 15).map((bid, i) => (
                <OrderRow key={i} order={bid} side="buy" />
              ))}
            </div>
          </div>
        </div>

        {/* Order Entry */}
        <div className="order-panel">
          <h2>Place Order</h2>

          {/* Order Type Selector */}
          <div className="order-type-selector">
            <button
              className={orderType === 'limit' ? 'active' : ''}
              onClick={() => setOrderType('limit')}
            >
              Limit
            </button>
            <button
              className={orderType === 'market' ? 'active' : ''}
              onClick={() => setOrderType('market')}
            >
              Market
            </button>
          </div>

          {/* Side Selector */}
          <div className="side-selector">
            <button
              className={`buy ${orderSide === 'buy' ? 'active' : ''}`}
              onClick={() => setOrderSide('buy')}
            >
              Buy
            </button>
            <button
              className={`sell ${orderSide === 'sell' ? 'active' : ''}`}
              onClick={() => setOrderSide('sell')}
            >
              Sell
            </button>
          </div>

          {/* Order Form */}
          <div className="order-form">
            {orderType === 'limit' && (
              <div className="form-group">
                <label>Price (USDC)</label>
                <input
                  type="number"
                  value={price}
                  onChange={(e) => setPrice(e.target.value)}
                  placeholder="0.00"
                  step="0.01"
                />
              </div>
            )}

            <div className="form-group">
              <label>Amount</label>
              <input
                type="number"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder="0.00"
                step="0.01"
              />
            </div>

            {orderType === 'limit' && (
              <div className="form-group">
                <label>Total (USDC)</label>
                <input
                  type="number"
                  value={(parseFloat(price) * parseFloat(amount) || 0).toFixed(2)}
                  readOnly
                  disabled
                />
              </div>
            )}

            <button
              className={`submit-order ${orderSide}`}
              onClick={handleSubmitOrder}
              disabled={!account || (orderType === 'limit' && !price) || !amount}
            >
              {orderSide === 'buy' ? 'Buy' : 'Sell'}{' '}
              {orderType === 'market' ? 'Market' : 'Limit'}
            </button>
          </div>

          {/* MEV Protection Indicator */}
          <div className="mev-protection">
            <span className="shield-icon">🛡️</span>
            <span>MEV Protection: Active</span>
          </div>
        </div>

        {/* Trade History */}
        <div className="trades-panel">
          <h2>Recent Trades</h2>
          <div className="trades-list">
            {trades.slice(0, 20).map((trade) => (
              <TradeRow key={trade.id} trade={trade} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

/**
 * Orderbook row component
 */
const OrderRow: React.FC<{ order: Order; side: 'buy' | 'sell' }> = ({ order, side }) => {
  return (
    <div className={`order-row ${side}`}>
      <span className="price">{order.price.toFixed(2)}</span>
      <span className="size">{order.size.toFixed(4)}</span>
      <span className="total">{order.total.toFixed(2)}</span>
      <div
        className="depth-bar"
        style={{
          width: `${Math.min((order.total / 10000) * 100, 100)}%`,
        }}
      />
    </div>
  );
};

/**
 * Trade row component
 */
const TradeRow: React.FC<{ trade: Trade }> = ({ trade }) => {
  return (
    <div className={`trade-row ${trade.side}`}>
      <span className="price">{trade.price.toFixed(2)}</span>
      <span className="size">{trade.size.toFixed(4)}</span>
      <span className="time">
        {new Date(trade.timestamp).toLocaleTimeString()}
      </span>
    </div>
  );
};

export default TradingInterface;
