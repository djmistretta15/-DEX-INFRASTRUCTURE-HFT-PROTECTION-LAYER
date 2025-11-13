## 🐳 Docker Development Environment

Complete local development environment with all services containerized.

## Services

| Service | Port | Description |
|---------|------|-------------|
| PostgreSQL | 5432 | Order history database |
| Redis | 6379 | Cache and pub/sub |
| Hardhat Node | 8545 | Local Ethereum node |
| Sequencer | 8080 | Block production |
| REST API | 3000 | Order management API |
| WebSocket | 3001 | Real-time trading feed |
| Frontend | 3002 | Trading UI |
| Prometheus | 9090 | Metrics collection |
| Metrics Exporter | 9091 | Custom metrics |
| Grafana | 3003 | Metrics visualization |
| Alerting | N/A | Alert notifications |

## Quick Start

### 1. Start All Services

```bash
docker-compose up -d
```

### 2. Check Service Health

```bash
docker-compose ps
```

Expected output:
```
NAME                COMMAND                  SERVICE             STATUS
dex-alerting        "npm run dev:alerting"   alerting            running
dex-api             "npm run dev:api"        api                 running
dex-frontend        "npm run dev"            frontend            running
dex-grafana         "/run.sh"                grafana             running
dex-hardhat         "npx hardhat node --…"   hardhat             running
dex-metrics-expo…   "npm run dev:metrics"    metrics-exporter    running
dex-postgres        "docker-entrypoint.s…"   postgres            running
dex-prometheus      "/bin/prometheus --c…"   prometheus          running
dex-redis           "docker-entrypoint.s…"   redis               running
dex-sequencer       "cargo run --release"    sequencer           running
dex-websocket       "npm run dev:websocket"  websocket           running
```

### 3. Access Services

- **Trading UI:** http://localhost:3002
- **REST API:** http://localhost:3000/api/v1
- **WebSocket:** ws://localhost:3001
- **Grafana:** http://localhost:3003 (admin/admin)
- **Prometheus:** http://localhost:9090
- **Metrics:** http://localhost:9091/metrics

### 4. Deploy Contracts

```bash
# Deploy orderbook contract
docker-compose exec hardhat npx hardhat run scripts/deploy.ts --network localhost

# Set contract address in .env
echo "ORDERBOOK_ADDRESS=0x..." >> .env

# Restart services to pick up new address
docker-compose restart
```

## Development Workflow

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f api
docker-compose logs -f sequencer
docker-compose logs -f websocket
```

### Restart Service

```bash
docker-compose restart api
```

### Stop All Services

```bash
docker-compose down
```

### Stop and Remove Volumes

```bash
docker-compose down -v
```

## Service Configuration

### Environment Variables

Create `.env` file:

```bash
# Blockchain
ORDERBOOK_ADDRESS=0x...
RPC_URL=http://hardhat:8545

# Database
DATABASE_URL=postgresql://dex_user:dex_password@postgres:5432/dex_db

# Redis
REDIS_URL=redis://redis:6379

# API
JWT_SECRET=your-secret-key
CORS_ORIGIN=http://localhost:3002

# Monitoring
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
PAGERDUTY_API_KEY=...
PAGERDUTY_SERVICE_KEY=...
EMAIL_RECIPIENTS=dev@example.com
```

### Sequencer Configuration

Edit `zk-rollup-core/sequencer/config.toml`:

```toml
[sequencer]
block_time_ms = 800
max_tx_per_block = 10000
enable_co_location = true
latency_threshold_us = 50
```

## Monitoring

### Grafana Dashboards

Access Grafana at http://localhost:3003

Pre-configured dashboards:
- **DEX Overview:** High-level metrics
- **Trading Activity:** Orders, trades, volume
- **MEV Protection:** Attack detection and prevention
- **System Health:** Latency, memory, CPU

### Prometheus Queries

Access Prometheus at http://localhost:9090

Example queries:

```promql
# Order submission rate
rate(dex_orders_submitted_total[5m])

# p99 latency
histogram_quantile(0.99, rate(dex_order_processing_duration_seconds_bucket[5m]))

# MEV attacks blocked
rate(dex_mev_attacks_blocked_total[5m])

# Active connections
dex_active_connections
```

### Alerting

Alerts are sent to configured channels when:
- Sequencer down (>10s no blocks)
- High latency (p99 > 5s)
- MEV attack spike (>10/min)
- Low liquidity (<$100k)
- Memory leak (>1GB heap)
- Failed tx spike (>50/min)

## Testing

### API Endpoints

```bash
# Health check
curl http://localhost:3000/health

# Get orderbook
curl http://localhost:3000/api/v1/orderbook/WETH-USDC

# Submit order (requires auth)
curl -X POST http://localhost:3000/api/v1/orders \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "pair": "WETH/USDC",
    "side": "buy",
    "orderType": "limit",
    "price": 2000,
    "amount": 1
  }'
```

### WebSocket Connection

```javascript
const socket = io('http://localhost:3001');

// Subscribe to orderbook
socket.emit('subscribe', { pairs: ['WETH/USDC'] });

// Listen to updates
socket.on('orderbook', (data) => {
  console.log('Orderbook update:', data);
});

socket.on('trade', (data) => {
  console.log('Trade executed:', data);
});
```

## Troubleshooting

### Service Won't Start

Check logs:
```bash
docker-compose logs api
```

Common issues:
- Port already in use: Change port in `docker-compose.yml`
- Contract not deployed: Deploy contracts first
- Database connection: Ensure postgres is healthy

### Sequencer Not Producing Blocks

Check:
1. Hardhat node is running: `docker-compose ps hardhat`
2. Redis is accessible: `docker-compose logs redis`
3. Configuration is correct: `docker-compose logs sequencer`

### High Memory Usage

Monitor:
```bash
docker stats
```

Adjust memory limits in `docker-compose.yml`:
```yaml
services:
  api:
    mem_limit: 1g
    mem_reservation: 512m
```

### Database Issues

Reset database:
```bash
docker-compose down -v postgres
docker-compose up -d postgres
```

## Production Deployment

**⚠️ This setup is for development only!**

For production:
1. Use managed Postgres (RDS, Cloud SQL)
2. Use managed Redis (ElastiCache, Memorystore)
3. Use proper secrets management (Vault, AWS Secrets Manager)
4. Enable TLS/SSL for all services
5. Set up proper monitoring and alerting
6. Use container orchestration (Kubernetes, ECS)
7. Implement proper backup strategies
8. Use production-grade Ethereum nodes (Infura, Alchemy)

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                     Frontend (3002)                     │
│                    React + Next.js                      │
└──────────────┬────────────────────┬─────────────────────┘
               │                    │
               ▼                    ▼
        REST API (3000)      WebSocket (3001)
               │                    │
               ├────────────────────┤
               │                    │
               ▼                    ▼
        ┌─────────────────────────────────┐
        │         Redis (6379)            │
        │    Cache + Pub/Sub + Queue      │
        └─────────────────────────────────┘
               │
               ▼
        ┌─────────────────────────────────┐
        │      Hardhat Node (8545)        │
        │     Local Ethereum Network      │
        └─────────────────────────────────┘
               │
               ▼
        ┌─────────────────────────────────┐
        │      Sequencer (8080)           │
        │   Rust - Block Production       │
        └─────────────────────────────────┘
               │
               ▼
        ┌─────────────────────────────────┐
        │     PostgreSQL (5432)           │
        │    Order History + State        │
        └─────────────────────────────────┘
               │
               ▼
        ┌─────────────────────────────────┐
        │    Prometheus (9090)            │
        │  Metrics Collection + Storage   │
        └─────────────────────────────────┘
               │
               ▼
        ┌─────────────────────────────────┐
        │      Grafana (3003)             │
        │    Metrics Visualization        │
        └─────────────────────────────────┘
```

## Additional Resources

- [API Documentation](./API.md)
- [Architecture Overview](./ARCHITECTURE.md)
- [MEV Protection](./MEV_PROTECTION.md)
- [Deployment Guide](./DEPLOYMENT.md)
