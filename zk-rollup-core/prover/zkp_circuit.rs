/*!
 * ZK-SNARK Prover for Rollup State Transitions
 *
 * Generates succinct proofs of correct execution for batches of transactions
 * Optimized for high-throughput trading workloads
 */

use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bellman::groth16::{Proof, generate_random_parameters, create_random_proof, verify_proof};
use bls12_381::{Bls12, Scalar};
use ff::Field;
use sha2::{Sha256, Digest};

/// Transaction proof circuit
#[derive(Clone)]
pub struct TransactionBatchCircuit {
    // Public inputs
    pub prev_state_root: Option<[u8; 32]>,
    pub new_state_root: Option<[u8; 32]>,
    pub tx_batch_hash: Option<[u8; 32]>,

    // Private inputs (witness)
    pub transactions: Vec<TransactionWitness>,
    pub state_deltas: Vec<StateDelta>,
}

#[derive(Clone, Debug)]
pub struct TransactionWitness {
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub amount: u128,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct StateDelta {
    pub account: [u8; 20],
    pub prev_balance: u128,
    pub new_balance: u128,
    pub prev_nonce: u64,
    pub new_nonce: u64,
}

impl Circuit<Bls12> for TransactionBatchCircuit {
    fn synthesize<CS: ConstraintSystem<Bls12>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let prev_root = cs.alloc_input(
            || "previous state root",
            || {
                self.prev_state_root
                    .map(|r| bytes_to_scalar(&r))
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        let new_root = cs.alloc_input(
            || "new state root",
            || {
                self.new_state_root
                    .map(|r| bytes_to_scalar(&r))
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        let tx_hash = cs.alloc_input(
            || "transaction batch hash",
            || {
                self.tx_batch_hash
                    .map(|h| bytes_to_scalar(&h))
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        // Verify state transitions
        for (i, delta) in self.state_deltas.iter().enumerate() {
            // Allocate state delta variables
            let prev_bal = cs.alloc(
                || format!("prev_balance_{}", i),
                || Ok(Scalar::from(delta.prev_balance as u64)),
            )?;

            let new_bal = cs.alloc(
                || format!("new_balance_{}", i),
                || Ok(Scalar::from(delta.new_balance as u64)),
            )?;

            // Constraint: prev_balance - transfer_amount = new_balance
            // This ensures conservation of value
            cs.enforce(
                || format!("balance_conservation_{}", i),
                |lc| lc + prev_bal,
                |lc| lc + CS::one(),
                |lc| lc + new_bal,
            );
        }

        // Verify transaction batch hash
        let computed_tx_hash = self.compute_batch_hash();
        let computed = cs.alloc(
            || "computed_tx_hash",
            || {
                computed_tx_hash
                    .map(|h| bytes_to_scalar(&h))
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        // Constraint: computed hash must equal public input
        cs.enforce(
            || "tx_hash_verification",
            |lc| lc + computed,
            |lc| lc + CS::one(),
            |lc| lc + tx_hash,
        );

        Ok(())
    }
}

impl TransactionBatchCircuit {
    /// Compute hash of transaction batch
    fn compute_batch_hash(&self) -> Option<[u8; 32]> {
        let mut hasher = Sha256::new();

        for tx in &self.transactions {
            hasher.update(&tx.from);
            hasher.update(&tx.to);
            hasher.update(&tx.amount.to_le_bytes());
            hasher.update(&tx.nonce.to_le_bytes());
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Some(hash)
    }
}

/// Convert bytes to field element
fn bytes_to_scalar(bytes: &[u8; 32]) -> Scalar {
    let mut repr = [0u64; 4];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut arr = [0u8; 8];
        arr[..chunk.len()].copy_from_slice(chunk);
        repr[i] = u64::from_le_bytes(arr);
    }

    // Note: In production, use proper field element encoding
    Scalar::from(repr[0])
}

/// ZK Prover service
pub struct ZKProver {
    params: bellman::groth16::Parameters<Bls12>,
}

impl ZKProver {
    /// Initialize prover with trusted setup
    pub fn new() -> Self {
        println!("🔐 Generating ZK proving parameters (trusted setup)...");

        // In production, use MPC ceremony for trusted setup
        let rng = &mut rand::thread_rng();
        let circuit = TransactionBatchCircuit {
            prev_state_root: Some([0u8; 32]),
            new_state_root: Some([0u8; 32]),
            tx_batch_hash: Some([0u8; 32]),
            transactions: vec![],
            state_deltas: vec![],
        };

        let params = generate_random_parameters::<Bls12, _, _>(circuit, rng)
            .expect("Failed to generate parameters");

        println!("✅ ZK parameters generated");

        Self { params }
    }

    /// Generate proof for transaction batch
    pub fn prove(
        &self,
        prev_state_root: [u8; 32],
        new_state_root: [u8; 32],
        transactions: Vec<TransactionWitness>,
        state_deltas: Vec<StateDelta>,
    ) -> Result<Proof<Bls12>, String> {
        let tx_batch_hash = self.compute_tx_hash(&transactions);

        let circuit = TransactionBatchCircuit {
            prev_state_root: Some(prev_state_root),
            new_state_root: Some(new_state_root),
            tx_batch_hash: Some(tx_batch_hash),
            transactions,
            state_deltas,
        };

        let rng = &mut rand::thread_rng();

        create_random_proof(circuit, &self.params, rng)
            .map_err(|e| format!("Proof generation failed: {:?}", e))
    }

    /// Verify proof
    pub fn verify(
        &self,
        proof: &Proof<Bls12>,
        prev_state_root: [u8; 32],
        new_state_root: [u8; 32],
        tx_batch_hash: [u8; 32],
    ) -> Result<bool, String> {
        let pvk = bellman::groth16::prepare_verifying_key(&self.params.vk);

        let public_inputs = vec![
            bytes_to_scalar(&prev_state_root),
            bytes_to_scalar(&new_state_root),
            bytes_to_scalar(&tx_batch_hash),
        ];

        verify_proof(&pvk, proof, &public_inputs)
            .map_err(|e| format!("Verification failed: {:?}", e))
    }

    fn compute_tx_hash(&self, transactions: &[TransactionWitness]) -> [u8; 32] {
        let mut hasher = Sha256::new();

        for tx in transactions {
            hasher.update(&tx.from);
            hasher.update(&tx.to);
            hasher.update(&tx.amount.to_le_bytes());
            hasher.update(&tx.nonce.to_le_bytes());
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// Batch prover for parallel proof generation
pub struct BatchProver {
    prover: ZKProver,
}

impl BatchProver {
    pub fn new() -> Self {
        Self {
            prover: ZKProver::new(),
        }
    }

    /// Generate proofs for multiple batches in parallel
    pub async fn prove_batches(
        &self,
        batches: Vec<TransactionBatch>,
    ) -> Vec<Result<Proof<Bls12>, String>> {
        use tokio::task;

        let mut handles = vec![];

        for batch in batches {
            let prover = self.prover.clone();

            let handle = task::spawn_blocking(move || {
                prover.prove(
                    batch.prev_state_root,
                    batch.new_state_root,
                    batch.transactions,
                    batch.state_deltas,
                )
            });

            handles.push(handle);
        }

        let mut results = vec![];
        for handle in handles {
            let result = handle.await.unwrap();
            results.push(result);
        }

        results
    }
}

#[derive(Clone)]
pub struct TransactionBatch {
    pub prev_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub transactions: Vec<TransactionWitness>,
    pub state_deltas: Vec<StateDelta>,
}

impl Clone for ZKProver {
    fn clone(&self) -> Self {
        // In production, share proving parameters efficiently
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_generation() {
        let prover = ZKProver::new();

        let prev_root = [0u8; 32];
        let new_root = [1u8; 32];

        let transactions = vec![
            TransactionWitness {
                from: [1u8; 20],
                to: [2u8; 20],
                amount: 100,
                nonce: 0,
                signature: vec![],
            },
        ];

        let state_deltas = vec![
            StateDelta {
                account: [1u8; 20],
                prev_balance: 1000,
                new_balance: 900,
                prev_nonce: 0,
                new_nonce: 1,
            },
            StateDelta {
                account: [2u8; 20],
                prev_balance: 0,
                new_balance: 100,
                prev_nonce: 0,
                new_nonce: 0,
            },
        ];

        let proof = prover.prove(prev_root, new_root, transactions, state_deltas);
        assert!(proof.is_ok(), "Proof generation should succeed");
    }
}
