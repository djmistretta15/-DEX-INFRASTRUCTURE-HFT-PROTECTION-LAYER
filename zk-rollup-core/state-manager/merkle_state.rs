/*!
 * Merkle State Tree for Rollup
 *
 * Efficient state management with Merkle proofs
 * Optimized for high-throughput trading operations
 */

use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

const TREE_DEPTH: usize = 20; // Supports 2^20 accounts

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub balance: u128,
    pub nonce: u64,
    pub code_hash: [u8; 32],
    pub storage_root: [u8; 32],
}

impl Account {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(&self.balance.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.code_hash);
        hasher.update(&self.storage_root);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

pub struct MerkleStateTree {
    accounts: HashMap<[u8; 20], Account>,
    tree_cache: HashMap<usize, HashMap<usize, [u8; 32]>>,
}

impl MerkleStateTree {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            tree_cache: HashMap::new(),
        }
    }

    /// Get account by address
    pub fn get_account(&self, address: &[u8; 20]) -> Option<&Account> {
        self.accounts.get(address)
    }

    /// Update account
    pub fn update_account(&mut self, address: [u8; 20], account: Account) {
        self.accounts.insert(address, account);
        self.invalidate_cache();
    }

    /// Compute Merkle root
    pub fn compute_root(&mut self) -> [u8; 32] {
        if self.accounts.is_empty() {
            return [0u8; 32];
        }

        // Build leaf nodes
        let mut leaves: Vec<([u8; 20], [u8; 32])> = self.accounts
            .iter()
            .map(|(addr, acc)| (*addr, acc.hash()))
            .collect();

        leaves.sort_by_key(|(addr, _)| *addr);

        // Build Merkle tree bottom-up
        let mut current_level: Vec<[u8; 32]> = leaves
            .iter()
            .map(|(_, hash)| *hash)
            .collect();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    [0u8; 32]
                };

                let parent = hash_pair(&left, &right);
                next_level.push(parent);
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Generate Merkle proof for account
    pub fn generate_proof(&self, address: &[u8; 20]) -> Option<MerkleProof> {
        let account = self.accounts.get(address)?;

        let mut leaves: Vec<([u8; 20], [u8; 32])> = self.accounts
            .iter()
            .map(|(addr, acc)| (*addr, acc.hash()))
            .collect();

        leaves.sort_by_key(|(addr, _)| *addr);

        // Find index of target account
        let index = leaves.iter().position(|(addr, _)| addr == address)?;

        // Build proof path
        let mut proof_siblings = Vec::new();
        let mut current_level: Vec<[u8; 32]> = leaves
            .iter()
            .map(|(_, hash)| *hash)
            .collect();

        let mut current_index = index;

        while current_level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling = if sibling_index < current_level.len() {
                current_level[sibling_index]
            } else {
                [0u8; 32]
            };

            proof_siblings.push(sibling);

            // Move to parent level
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    [0u8; 32]
                };
                next_level.push(hash_pair(&left, &right));
            }

            current_level = next_level;
            current_index /= 2;
        }

        Some(MerkleProof {
            address: *address,
            account: account.clone(),
            siblings: proof_siblings,
            index,
        })
    }

    /// Verify Merkle proof
    pub fn verify_proof(&self, proof: &MerkleProof, root: &[u8; 32]) -> bool {
        let mut current_hash = proof.account.hash();
        let mut index = proof.index;

        for sibling in &proof.siblings {
            if index % 2 == 0 {
                current_hash = hash_pair(&current_hash, sibling);
            } else {
                current_hash = hash_pair(sibling, &current_hash);
            }
            index /= 2;
        }

        &current_hash == root
    }

    fn invalidate_cache(&mut self) {
        self.tree_cache.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub address: [u8; 20],
    pub account: Account,
    pub siblings: Vec<[u8; 32]>,
    pub index: usize,
}

/// Hash two nodes together
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(left);
    hasher.update(right);

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree() {
        let mut tree = MerkleStateTree::new();

        let account1 = Account {
            balance: 1000,
            nonce: 0,
            code_hash: [0u8; 32],
            storage_root: [0u8; 32],
        };

        let addr1 = [1u8; 20];
        tree.update_account(addr1, account1.clone());

        let root1 = tree.compute_root();

        let account2 = Account {
            balance: 2000,
            nonce: 1,
            code_hash: [0u8; 32],
            storage_root: [0u8; 32],
        };

        let addr2 = [2u8; 20];
        tree.update_account(addr2, account2);

        let root2 = tree.compute_root();

        assert_ne!(root1, root2, "Roots should differ after update");

        // Test proof generation and verification
        let proof = tree.generate_proof(&addr1).unwrap();
        assert!(tree.verify_proof(&proof, &root2));
    }
}
