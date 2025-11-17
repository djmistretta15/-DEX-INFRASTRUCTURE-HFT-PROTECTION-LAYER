-- TIMESCALEDB SCHEMA FOR HISTORICAL MARKET DATA
-- Optimized for time-series queries with hypertables and compression

-- ═══════════════════════════════════════════════════════════════════
--                         DATABASE SETUP
-- ═══════════════════════════════════════════════════════════════════

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Enable additional helpful extensions
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- ═══════════════════════════════════════════════════════════════════
--                         CANDLES TABLE
-- ═══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS candles (
    pair VARCHAR(20) NOT NULL,
    timeframe VARCHAR(10) NOT NULL,
    timestamp BIGINT NOT NULL,
    open NUMERIC(24, 8) NOT NULL,
    high NUMERIC(24, 8) NOT NULL,
    low NUMERIC(24, 8) NOT NULL,
    close NUMERIC(24, 8) NOT NULL,
    volume NUMERIC(24, 8) NOT NULL,
    quote_volume NUMERIC(24, 8) NOT NULL,
    trades INTEGER NOT NULL,
    buy_volume NUMERIC(24, 8) NOT NULL,
    sell_volume NUMERIC(24, 8) NOT NULL,
    vwap NUMERIC(24, 8) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),

    PRIMARY KEY (pair, timeframe, timestamp)
);

-- Convert to TimescaleDB hypertable
SELECT create_hypertable(
    'candles',
    'timestamp',
    chunk_time_interval => 86400000, -- 1 day chunks in milliseconds
    if_not_exists => TRUE,
    migrate_data => TRUE
);

-- Create composite index for efficient queries
CREATE INDEX IF NOT EXISTS idx_candles_pair_timeframe_time
ON candles (pair, timeframe, timestamp DESC);

-- ═══════════════════════════════════════════════════════════════════
--                         TRADES TABLE
-- ═══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS trades (
    id VARCHAR(64) PRIMARY KEY,
    pair VARCHAR(20) NOT NULL,
    price NUMERIC(24, 8) NOT NULL,
    amount NUMERIC(24, 8) NOT NULL,
    side VARCHAR(4) NOT NULL CHECK (side IN ('buy', 'sell')),
    timestamp BIGINT NOT NULL,
    maker_order_id VARCHAR(64) NOT NULL,
    taker_order_id VARCHAR(64) NOT NULL,
    fee NUMERIC(24, 8) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Convert to hypertable
SELECT create_hypertable(
    'trades',
    'timestamp',
    chunk_time_interval => 3600000, -- 1 hour chunks
    if_not_exists => TRUE,
    migrate_data => TRUE
);

-- Indexes for trade queries
CREATE INDEX IF NOT EXISTS idx_trades_pair_time
ON trades (pair, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_trades_maker
ON trades (maker_order_id);

CREATE INDEX IF NOT EXISTS idx_trades_taker
ON trades (taker_order_id);

-- ═══════════════════════════════════════════════════════════════════
--                      MARKET STATISTICS TABLE
-- ═══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS market_stats (
    id SERIAL,
    pair VARCHAR(20) NOT NULL,
    timestamp BIGINT NOT NULL,
    price NUMERIC(24, 8) NOT NULL,
    price_change_24h NUMERIC(24, 8) NOT NULL,
    price_change_percent_24h NUMERIC(12, 4) NOT NULL,
    high_24h NUMERIC(24, 8) NOT NULL,
    low_24h NUMERIC(24, 8) NOT NULL,
    volume_24h NUMERIC(24, 8) NOT NULL,
    quote_volume_24h NUMERIC(24, 8) NOT NULL,
    trades_24h INTEGER NOT NULL,
    vwap_24h NUMERIC(24, 8) NOT NULL,
    volatility_24h NUMERIC(12, 6) NOT NULL,
    momentum NUMERIC(12, 6) NOT NULL,
    buy_pressure NUMERIC(8, 6) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),

    PRIMARY KEY (id, timestamp)
);

-- Convert to hypertable
SELECT create_hypertable(
    'market_stats',
    'timestamp',
    chunk_time_interval => 86400000,
    if_not_exists => TRUE,
    migrate_data => TRUE
);

CREATE INDEX IF NOT EXISTS idx_market_stats_pair_time
ON market_stats (pair, timestamp DESC);

-- ═══════════════════════════════════════════════════════════════════
--                      LIQUIDITY SNAPSHOTS
-- ═══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS orderbook_snapshots (
    id SERIAL,
    pair VARCHAR(20) NOT NULL,
    timestamp BIGINT NOT NULL,
    bid_depth_1 NUMERIC(24, 8),    -- Top bid volume
    bid_price_1 NUMERIC(24, 8),    -- Top bid price
    ask_depth_1 NUMERIC(24, 8),    -- Top ask volume
    ask_price_1 NUMERIC(24, 8),    -- Top ask price
    spread NUMERIC(24, 8) NOT NULL,
    mid_price NUMERIC(24, 8) NOT NULL,
    total_bid_volume NUMERIC(24, 8) NOT NULL,
    total_ask_volume NUMERIC(24, 8) NOT NULL,
    bid_levels INTEGER NOT NULL,
    ask_levels INTEGER NOT NULL,
    imbalance NUMERIC(12, 6) NOT NULL, -- (bid - ask) / (bid + ask)
    created_at TIMESTAMPTZ DEFAULT NOW(),

    PRIMARY KEY (id, timestamp)
);

SELECT create_hypertable(
    'orderbook_snapshots',
    'timestamp',
    chunk_time_interval => 3600000,
    if_not_exists => TRUE,
    migrate_data => TRUE
);

CREATE INDEX IF NOT EXISTS idx_orderbook_pair_time
ON orderbook_snapshots (pair, timestamp DESC);

-- ═══════════════════════════════════════════════════════════════════
--                      LIQUIDITY PROVIDER POSITIONS
-- ═══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS lp_positions (
    id SERIAL PRIMARY KEY,
    user_address VARCHAR(42) NOT NULL,
    pool_address VARCHAR(42) NOT NULL,
    pair VARCHAR(20) NOT NULL,
    lp_token_amount NUMERIC(24, 8) NOT NULL,
    token0_amount NUMERIC(24, 8) NOT NULL,
    token1_amount NUMERIC(24, 8) NOT NULL,
    entry_price NUMERIC(24, 8) NOT NULL,
    entry_timestamp BIGINT NOT NULL,
    current_value_usd NUMERIC(24, 8),
    impermanent_loss_percent NUMERIC(12, 6),
    fees_earned NUMERIC(24, 8) DEFAULT 0,
    rewards_earned NUMERIC(24, 8) DEFAULT 0,
    last_updated BIGINT NOT NULL,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'withdrawn', 'liquidated')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lp_user ON lp_positions (user_address);
CREATE INDEX IF NOT EXISTS idx_lp_pool ON lp_positions (pool_address);
CREATE INDEX IF NOT EXISTS idx_lp_status ON lp_positions (status);

-- ═══════════════════════════════════════════════════════════════════
--                      LP HISTORICAL SNAPSHOTS
-- ═══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS lp_snapshots (
    id SERIAL,
    position_id INTEGER NOT NULL REFERENCES lp_positions(id),
    timestamp BIGINT NOT NULL,
    lp_token_amount NUMERIC(24, 8) NOT NULL,
    token0_amount NUMERIC(24, 8) NOT NULL,
    token1_amount NUMERIC(24, 8) NOT NULL,
    total_value_usd NUMERIC(24, 8) NOT NULL,
    impermanent_loss_percent NUMERIC(12, 6) NOT NULL,
    fees_earned_cumulative NUMERIC(24, 8) NOT NULL,
    rewards_earned_cumulative NUMERIC(24, 8) NOT NULL,
    apy_estimate NUMERIC(12, 6),
    created_at TIMESTAMPTZ DEFAULT NOW(),

    PRIMARY KEY (id, timestamp)
);

SELECT create_hypertable(
    'lp_snapshots',
    'timestamp',
    chunk_time_interval => 86400000,
    if_not_exists => TRUE,
    migrate_data => TRUE
);

CREATE INDEX IF NOT EXISTS idx_lp_snapshots_position
ON lp_snapshots (position_id, timestamp DESC);

-- ═══════════════════════════════════════════════════════════════════
--                      MEV EVENTS TRACKING
-- ═══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS mev_events (
    id SERIAL,
    event_type VARCHAR(50) NOT NULL,
    pair VARCHAR(20) NOT NULL,
    timestamp BIGINT NOT NULL,
    attacker_address VARCHAR(42),
    victim_address VARCHAR(42),
    victim_tx_hash VARCHAR(66),
    frontrun_tx_hash VARCHAR(66),
    backrun_tx_hash VARCHAR(66),
    estimated_profit NUMERIC(24, 8),
    victim_loss NUMERIC(24, 8),
    confidence NUMERIC(8, 4),
    severity VARCHAR(20),
    mitigated BOOLEAN DEFAULT FALSE,
    mitigation_action VARCHAR(100),
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),

    PRIMARY KEY (id, timestamp)
);

SELECT create_hypertable(
    'mev_events',
    'timestamp',
    chunk_time_interval => 86400000,
    if_not_exists => TRUE,
    migrate_data => TRUE
);

CREATE INDEX IF NOT EXISTS idx_mev_type ON mev_events (event_type);
CREATE INDEX IF NOT EXISTS idx_mev_pair ON mev_events (pair);
CREATE INDEX IF NOT EXISTS idx_mev_attacker ON mev_events (attacker_address);

-- ═══════════════════════════════════════════════════════════════════
--                      COMPRESSION POLICIES
-- ═══════════════════════════════════════════════════════════════════

-- Enable compression on older data to save storage

-- Candles: compress after 30 days
ALTER TABLE candles SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'pair, timeframe',
    timescaledb.compress_orderby = 'timestamp DESC'
);

SELECT add_compression_policy('candles', INTERVAL '30 days');

-- Trades: compress after 7 days
ALTER TABLE trades SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'pair',
    timescaledb.compress_orderby = 'timestamp DESC'
);

SELECT add_compression_policy('trades', INTERVAL '7 days');

-- Market stats: compress after 60 days
ALTER TABLE market_stats SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'pair',
    timescaledb.compress_orderby = 'timestamp DESC'
);

SELECT add_compression_policy('market_stats', INTERVAL '60 days');

-- Orderbook snapshots: compress after 3 days
ALTER TABLE orderbook_snapshots SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'pair',
    timescaledb.compress_orderby = 'timestamp DESC'
);

SELECT add_compression_policy('orderbook_snapshots', INTERVAL '3 days');

-- MEV events: compress after 90 days
ALTER TABLE mev_events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'event_type, pair',
    timescaledb.compress_orderby = 'timestamp DESC'
);

SELECT add_compression_policy('mev_events', INTERVAL '90 days');

-- ═══════════════════════════════════════════════════════════════════
--                      RETENTION POLICIES
-- ═══════════════════════════════════════════════════════════════════

-- Automatically drop old data to manage storage

-- Keep 1s candles for 7 days only
SELECT add_retention_policy('candles', INTERVAL '7 days',
    if_not_exists => TRUE);

-- Keep trades for 90 days
SELECT add_retention_policy('trades', INTERVAL '90 days',
    if_not_exists => TRUE);

-- Keep orderbook snapshots for 30 days
SELECT add_retention_policy('orderbook_snapshots', INTERVAL '30 days',
    if_not_exists => TRUE);

-- Keep market stats for 1 year
SELECT add_retention_policy('market_stats', INTERVAL '365 days',
    if_not_exists => TRUE);

-- Keep MEV events for 2 years (for analysis)
SELECT add_retention_policy('mev_events', INTERVAL '730 days',
    if_not_exists => TRUE);

-- ═══════════════════════════════════════════════════════════════════
--                      CONTINUOUS AGGREGATES
-- ═══════════════════════════════════════════════════════════════════

-- Pre-compute hourly stats for faster queries
CREATE MATERIALIZED VIEW IF NOT EXISTS hourly_stats
WITH (timescaledb.continuous) AS
SELECT
    pair,
    time_bucket('1 hour', to_timestamp(timestamp / 1000)) AS bucket,
    first(open, timestamp) AS open,
    max(high) AS high,
    min(low) AS low,
    last(close, timestamp) AS close,
    sum(volume) AS volume,
    sum(quote_volume) AS quote_volume,
    sum(trades) AS trades,
    sum(buy_volume) AS buy_volume,
    sum(sell_volume) AS sell_volume
FROM candles
WHERE timeframe = '1m'
GROUP BY pair, bucket;

-- Add refresh policy
SELECT add_continuous_aggregate_policy('hourly_stats',
    start_offset => INTERVAL '3 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour');

-- Daily stats aggregate
CREATE MATERIALIZED VIEW IF NOT EXISTS daily_stats
WITH (timescaledb.continuous) AS
SELECT
    pair,
    time_bucket('1 day', to_timestamp(timestamp / 1000)) AS bucket,
    first(open, timestamp) AS open,
    max(high) AS high,
    min(low) AS low,
    last(close, timestamp) AS close,
    sum(volume) AS volume,
    sum(quote_volume) AS quote_volume,
    sum(trades) AS trades,
    avg(volatility_24h) AS avg_volatility,
    avg(buy_pressure) AS avg_buy_pressure
FROM market_stats
GROUP BY pair, bucket;

SELECT add_continuous_aggregate_policy('daily_stats',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 day');

-- ═══════════════════════════════════════════════════════════════════
--                      USEFUL FUNCTIONS
-- ═══════════════════════════════════════════════════════════════════

-- Get OHLCV for any custom timeframe
CREATE OR REPLACE FUNCTION get_custom_candles(
    p_pair VARCHAR,
    p_interval INTERVAL,
    p_start BIGINT,
    p_end BIGINT
)
RETURNS TABLE (
    bucket TIMESTAMPTZ,
    open NUMERIC,
    high NUMERIC,
    low NUMERIC,
    close NUMERIC,
    volume NUMERIC,
    trades BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        time_bucket(p_interval, to_timestamp(timestamp / 1000)) AS bucket,
        first(candles.open, timestamp),
        max(candles.high),
        min(candles.low),
        last(candles.close, timestamp),
        sum(candles.volume),
        sum(candles.trades)::BIGINT
    FROM candles
    WHERE pair = p_pair
      AND timeframe = '1m'
      AND timestamp >= p_start
      AND timestamp <= p_end
    GROUP BY bucket
    ORDER BY bucket;
END;
$$ LANGUAGE plpgsql;

-- Calculate impermanent loss
CREATE OR REPLACE FUNCTION calculate_impermanent_loss(
    initial_price NUMERIC,
    current_price NUMERIC
)
RETURNS NUMERIC AS $$
DECLARE
    price_ratio NUMERIC;
    il NUMERIC;
BEGIN
    price_ratio := current_price / initial_price;
    il := (2 * sqrt(price_ratio) / (1 + price_ratio)) - 1;
    RETURN il * 100; -- Return as percentage
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Get top MEV attackers
CREATE OR REPLACE FUNCTION get_top_mev_attackers(
    p_days INTEGER DEFAULT 30,
    p_limit INTEGER DEFAULT 10
)
RETURNS TABLE (
    attacker_address VARCHAR,
    total_profit NUMERIC,
    attack_count BIGINT,
    avg_profit NUMERIC,
    total_victims INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        mev.attacker_address,
        sum(estimated_profit) AS total_profit,
        count(*) AS attack_count,
        avg(estimated_profit) AS avg_profit,
        count(DISTINCT victim_address)::INTEGER AS total_victims
    FROM mev_events mev
    WHERE timestamp >= extract(epoch from now() - (p_days || ' days')::INTERVAL) * 1000
      AND attacker_address IS NOT NULL
    GROUP BY mev.attacker_address
    ORDER BY total_profit DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

-- ═══════════════════════════════════════════════════════════════════
--                      GRANT PERMISSIONS
-- ═══════════════════════════════════════════════════════════════════

-- Create roles for different access patterns
CREATE ROLE IF NOT EXISTS dex_readonly;
CREATE ROLE IF NOT EXISTS dex_readwrite;
CREATE ROLE IF NOT EXISTS dex_admin;

-- Grant read-only access
GRANT SELECT ON ALL TABLES IN SCHEMA public TO dex_readonly;
GRANT SELECT ON hourly_stats, daily_stats TO dex_readonly;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO dex_readonly;

-- Grant read-write access
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO dex_readwrite;
GRANT SELECT ON hourly_stats, daily_stats TO dex_readwrite;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO dex_readwrite;

-- Grant admin access
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO dex_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO dex_admin;
GRANT ALL PRIVILEGES ON hourly_stats, daily_stats TO dex_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO dex_admin;

-- ═══════════════════════════════════════════════════════════════════
--                      INITIAL DATA
-- ═══════════════════════════════════════════════════════════════════

-- Insert supported trading pairs
CREATE TABLE IF NOT EXISTS trading_pairs (
    id SERIAL PRIMARY KEY,
    symbol VARCHAR(20) UNIQUE NOT NULL,
    base_token VARCHAR(10) NOT NULL,
    quote_token VARCHAR(10) NOT NULL,
    base_decimals INTEGER NOT NULL,
    quote_decimals INTEGER NOT NULL,
    min_order_size NUMERIC(24, 8) NOT NULL,
    max_order_size NUMERIC(24, 8) NOT NULL,
    tick_size NUMERIC(24, 8) NOT NULL,
    maker_fee NUMERIC(8, 6) NOT NULL,
    taker_fee NUMERIC(8, 6) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO trading_pairs (
    symbol, base_token, quote_token, base_decimals, quote_decimals,
    min_order_size, max_order_size, tick_size, maker_fee, taker_fee
) VALUES
    ('WETH/USDC', 'WETH', 'USDC', 18, 6, 0.001, 10000, 0.01, 0.001, 0.003),
    ('WBTC/USDC', 'WBTC', 'USDC', 8, 6, 0.0001, 100, 1, 0.001, 0.003),
    ('LINK/USDC', 'LINK', 'USDC', 18, 6, 0.1, 100000, 0.001, 0.001, 0.003),
    ('UNI/USDC', 'UNI', 'USDC', 18, 6, 0.1, 50000, 0.001, 0.001, 0.003),
    ('AAVE/USDC', 'AAVE', 'USDC', 18, 6, 0.01, 5000, 0.1, 0.001, 0.003)
ON CONFLICT (symbol) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════════
--                      MONITORING VIEWS
-- ═══════════════════════════════════════════════════════════════════

-- Real-time database statistics
CREATE OR REPLACE VIEW database_stats AS
SELECT
    hypertable_name,
    total_chunks,
    compressed_chunks,
    pg_size_pretty(total_bytes) AS total_size,
    pg_size_pretty(compressed_bytes) AS compressed_size,
    CASE
        WHEN total_bytes > 0
        THEN round((1 - (compressed_bytes::numeric / total_bytes)) * 100, 2)
        ELSE 0
    END AS compression_ratio
FROM timescaledb_information.hypertables
JOIN (
    SELECT
        hypertable_name AS name,
        count(*) AS total_chunks,
        sum(CASE WHEN is_compressed THEN 1 ELSE 0 END) AS compressed_chunks
    FROM timescaledb_information.chunks
    GROUP BY hypertable_name
) chunks ON hypertables.hypertable_name = chunks.name
JOIN (
    SELECT
        hypertable_name AS name,
        hypertable_size(format('%I.%I', hypertable_schema, hypertable_name)::regclass) AS total_bytes,
        COALESCE(sum(after_compression_total_bytes), 0) AS compressed_bytes
    FROM timescaledb_information.hypertables
    LEFT JOIN timescaledb_information.compression_stats
        ON hypertables.hypertable_name = compression_stats.hypertable_name
    GROUP BY hypertables.hypertable_name, hypertables.hypertable_schema
) sizes ON hypertables.hypertable_name = sizes.name;

-- Success! TimescaleDB schema ready for production
