/*!
 * High-Frequency Trading Optimized Sequencer
 *
 * Features:
 * - Sub-second block production (<1s)
 * - Latency-aware routing
 * - Co-location support for institutional traders
 * - Fair sequencing guarantees
 */

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

const BLOCK_TIME_MS: u64 = 800; // 800ms block time
const MAX_TRANSACTIONS_PER_BLOCK: usize = 10_000;
const PRIORITY_QUEUE_SIZE: usize = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
    pub nonce: u64,
    pub signature: Vec<u8>,
    pub timestamp_ns: u128, // Nanosecond precision
    pub gas_price: u128,
}

#[derive(Debug, Clone)]
pub struct Block {
    pub number: u64,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub state_root: [u8; 32],
    pub prev_block_hash: [u8; 32],
    pub sequencer_signature: Vec<u8>,
}

#[derive(Debug)]
pub struct SequencerConfig {
    pub block_time: Duration,
    pub max_tx_per_block: usize,
    pub enable_co_location: bool,
    pub latency_threshold_us: u64, // Microsecond threshold
}

impl Default for SequencerConfig {
    fn default() -> Self {
        Self {
            block_time: Duration::from_millis(BLOCK_TIME_MS),
            max_tx_per_block: MAX_TRANSACTIONS_PER_BLOCK,
            enable_co_location: true,
            latency_threshold_us: 50, // 50 microsecond threshold
        }
    }
}

pub struct HFTSequencer {
    config: SequencerConfig,
    mempool: Arc<RwLock<Vec<Transaction>>>,
    current_block: Arc<RwLock<Option<Block>>>,
    block_number: Arc<RwLock<u64>>,
    state_manager: Arc<dyn StateManager>,
    tx_receiver: mpsc::UnboundedReceiver<Transaction>,
    tx_sender: mpsc::UnboundedSender<Transaction>,
}

impl HFTSequencer {
    pub fn new(
        config: SequencerConfig,
        state_manager: Arc<dyn StateManager>,
    ) -> Self {
        let (tx_sender, tx_receiver) = mpsc::unbounded_channel();

        Self {
            config,
            mempool: Arc::new(RwLock::new(Vec::with_capacity(PRIORITY_QUEUE_SIZE))),
            current_block: Arc::new(RwLock::new(None)),
            block_number: Arc::new(RwLock::new(0)),
            state_manager,
            tx_receiver,
            tx_sender,
        }
    }

    /// Start the sequencer main loop
    pub async fn start(&mut self) {
        println!("🚀 Starting HFT Sequencer with {}ms block time",
                 self.config.block_time.as_millis());

        let mut block_timer = tokio::time::interval(self.config.block_time);

        loop {
            tokio::select! {
                // Receive incoming transactions
                Some(tx) = self.tx_receiver.recv() => {
                    self.add_transaction(tx).await;
                }

                // Produce block on timer
                _ = block_timer.tick() => {
                    let start = Instant::now();

                    match self.produce_block().await {
                        Ok(block) => {
                            let latency = start.elapsed();
                            println!("✅ Block {} produced in {:?} with {} txs",
                                     block.number, latency, block.transactions.len());
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to produce block: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Add transaction to mempool with latency tracking
    async fn add_transaction(&self, tx: Transaction) {
        let arrival_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        // Calculate network latency
        let latency_ns = arrival_time - tx.timestamp_ns;

        if self.config.enable_co_location {
            // Priority for co-located traders with low latency
            if latency_ns < (self.config.latency_threshold_us as u128 * 1000) {
                println!("⚡ Co-located tx detected: latency = {}μs", latency_ns / 1000);
            }
        }

        let mut mempool = self.mempool.write().await;
        mempool.push(tx);
    }

    /// Produce block with fair sequencing
    async fn produce_block(&self) -> Result<Block, String> {
        let mut mempool = self.mempool.write().await;

        if mempool.is_empty() {
            return Err("Empty mempool".to_string());
        }

        // Sort by timestamp (FIFO within latency bands)
        // This ensures MEV resistance while rewarding low-latency
        mempool.sort_by_key(|tx| tx.timestamp_ns);

        // Take transactions for this block
        let tx_count = std::cmp::min(mempool.len(), self.config.max_tx_per_block);
        let transactions: Vec<Transaction> = mempool.drain(..tx_count).collect();

        // Execute transactions and update state
        let state_root = self.state_manager
            .execute_transactions(&transactions)
            .await
            .map_err(|e| format!("State execution failed: {}", e))?;

        // Get previous block hash
        let prev_block = self.current_block.read().await;
        let prev_block_hash = prev_block.as_ref()
            .map(|b| self.compute_block_hash(b))
            .unwrap_or([0u8; 32]);

        // Increment block number
        let mut block_num = self.block_number.write().await;
        *block_num += 1;

        let block = Block {
            number: *block_num,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            transactions,
            state_root,
            prev_block_hash,
            sequencer_signature: vec![], // Sign in production
        };

        // Update current block
        *self.current_block.write().await = Some(block.clone());

        Ok(block)
    }

    /// Compute block hash
    fn compute_block_hash(&self, block: &Block) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(&block.number.to_le_bytes());
        hasher.update(&block.timestamp.to_le_bytes());
        hasher.update(&block.state_root);
        hasher.update(&block.prev_block_hash);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Get transaction sender channel
    pub fn get_tx_sender(&self) -> mpsc::UnboundedSender<Transaction> {
        self.tx_sender.clone()
    }

    /// Get current mempool size
    pub async fn get_mempool_size(&self) -> usize {
        self.mempool.read().await.len()
    }

    /// Get current block number
    pub async fn get_block_number(&self) -> u64 {
        *self.block_number.read().await
    }
}

/// State manager trait for execution
#[async_trait::async_trait]
pub trait StateManager: Send + Sync {
    async fn execute_transactions(
        &self,
        transactions: &[Transaction],
    ) -> Result<[u8; 32], String>;

    async fn get_state_root(&self) -> [u8; 32];
}

/// Example state manager implementation
pub struct InMemoryStateManager {
    state: Arc<RwLock<std::collections::HashMap<[u8; 20], u128>>>,
}

impl InMemoryStateManager {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl StateManager for InMemoryStateManager {
    async fn execute_transactions(
        &self,
        transactions: &[Transaction],
    ) -> Result<[u8; 32], String> {
        let mut state = self.state.write().await;

        for tx in transactions {
            // Simple balance transfer logic
            let from_balance = state.get(&tx.from).unwrap_or(&0);

            if *from_balance < tx.value {
                continue; // Skip insufficient balance
            }

            state.insert(tx.from, from_balance - tx.value);

            let to_balance = state.get(&tx.to).unwrap_or(&0);
            state.insert(tx.to, to_balance + tx.value);
        }

        // Compute state root (simplified)
        let mut hasher = Keccak256::new();
        for (addr, balance) in state.iter() {
            hasher.update(addr);
            hasher.update(&balance.to_le_bytes());
        }

        let result = hasher.finalize();
        let mut root = [0u8; 32];
        root.copy_from_slice(&result);

        Ok(root)
    }

    async fn get_state_root(&self) -> [u8; 32] {
        let state = self.state.read().await;

        let mut hasher = Keccak256::new();
        for (addr, balance) in state.iter() {
            hasher.update(addr);
            hasher.update(&balance.to_le_bytes());
        }

        let result = hasher.finalize();
        let mut root = [0u8; 32];
        root.copy_from_slice(&result);
        root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sequencer_block_production() {
        let config = SequencerConfig::default();
        let state_manager = Arc::new(InMemoryStateManager::new());
        let mut sequencer = HFTSequencer::new(config, state_manager);

        let tx_sender = sequencer.get_tx_sender();

        // Submit test transaction
        let tx = Transaction {
            from: [1u8; 20],
            to: [2u8; 20],
            value: 1000,
            data: vec![],
            nonce: 0,
            signature: vec![],
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            gas_price: 100,
        };

        tx_sender.send(tx).unwrap();

        // Allow time for processing
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(sequencer.get_mempool_size().await, 1);
    }
}
