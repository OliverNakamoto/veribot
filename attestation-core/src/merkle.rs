//! Incremental Merkle tree for log entries.
//!
//! ## Key Properties
//! - Sorted by (timestamp, nonce) for deterministic ordering
//! - Incremental updates (efficient for streaming logs)
//! - Proof generation for selective disclosure

use crate::crypto::sha256;
use crate::types::Hash256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A Merkle tree entry (timestamp + nonce ensures deterministic ordering).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Entry {
    /// Timestamp (microseconds since Unix epoch)
    pub timestamp_us: u64,
    /// Nonce for deterministic ordering when timestamps collide
    pub nonce: u64,
    /// Entry data hash
    pub data_hash: Hash256,
}

impl Entry {
    /// Create a new entry.
    pub fn new(timestamp_us: u64, nonce: u64, data: &[u8]) -> Self {
        Self {
            timestamp_us,
            nonce,
            data_hash: sha256(data),
        }
    }

    /// Compute the hash of this entry (for Merkle tree leaf).
    pub fn hash(&self) -> Hash256 {
        // Deterministic serialization of (timestamp, nonce, data_hash)
        let mut buf = Vec::with_capacity(8 + 8 + 32);
        buf.extend_from_slice(&self.timestamp_us.to_be_bytes());
        buf.extend_from_slice(&self.nonce.to_be_bytes());
        buf.extend_from_slice(&self.data_hash);
        sha256(&buf)
    }
}

/// Incremental Merkle tree.
///
/// Uses BTreeMap to maintain sorted order by (timestamp, nonce).
pub struct MerkleTree {
    entries: BTreeMap<(u64, u64), Entry>,
}

impl MerkleTree {
    /// Create a new empty Merkle tree.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Insert an entry into the tree.
    pub fn insert(&mut self, entry: Entry) {
        self.entries.insert((entry.timestamp_us, entry.nonce), entry);
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the Merkle root.
    ///
    /// For an empty tree, returns a zero hash.
    pub fn root(&self) -> Hash256 {
        if self.entries.is_empty() {
            return [0u8; 32];
        }

        let leaves: Vec<Hash256> = self.entries.values().map(|e| e.hash()).collect();
        compute_merkle_root(&leaves)
    }

    /// Generate a Merkle proof for a specific entry.
    ///
    /// Returns the sibling hashes needed to reconstruct the root.
    pub fn generate_proof(&self, timestamp_us: u64, nonce: u64) -> Option<MerkleProof> {
        let leaves: Vec<Entry> = self.entries.values().cloned().collect();
        let index = leaves.iter().position(|e| e.timestamp_us == timestamp_us && e.nonce == nonce)?;

        let leaf_hashes: Vec<Hash256> = leaves.iter().map(|e| e.hash()).collect();
        let siblings = compute_proof_siblings(&leaf_hashes, index);

        Some(MerkleProof {
            leaf: leaves[index].clone(),
            leaf_index: index,
            siblings,
            root: self.root(),
        })
    }

    /// Clear all entries (for checkpoint reset).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get all entries in sorted order.
    pub fn entries(&self) -> Vec<&Entry> {
        self.entries.values().collect()
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// A Merkle proof for a specific entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf: Entry,
    pub leaf_index: usize,
    pub siblings: Vec<Hash256>,
    pub root: Hash256,
}

impl MerkleProof {
    /// Verify this proof against a known root.
    pub fn verify(&self, expected_root: &Hash256) -> bool {
        if &self.root != expected_root {
            return false;
        }

        let computed_root = reconstruct_root(self.leaf.hash(), self.leaf_index, &self.siblings);
        &computed_root == expected_root
    }
}

/// Compute the Merkle root from leaf hashes.
fn compute_merkle_root(leaves: &[Hash256]) -> Hash256 {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level = leaves.to_vec();

    while level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in level.chunks(2) {
            let hash = if chunk.len() == 2 {
                hash_pair(&chunk[0], &chunk[1])
            } else {
                // Odd number of nodes - hash with itself
                hash_pair(&chunk[0], &chunk[0])
            };
            next_level.push(hash);
        }

        level = next_level;
    }

    level[0]
}

/// Compute sibling hashes for a Merkle proof.
fn compute_proof_siblings(leaves: &[Hash256], index: usize) -> Vec<Hash256> {
    if leaves.len() <= 1 {
        return Vec::new();
    }

    let mut siblings = Vec::new();
    let mut level = leaves.to_vec();
    let mut current_index = index;

    while level.len() > 1 {
        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };

        let sibling = if sibling_index < level.len() {
            level[sibling_index]
        } else {
            level[current_index] // Duplicate if odd
        };

        siblings.push(sibling);

        let mut next_level = Vec::new();
        for chunk in level.chunks(2) {
            let hash = if chunk.len() == 2 {
                hash_pair(&chunk[0], &chunk[1])
            } else {
                hash_pair(&chunk[0], &chunk[0])
            };
            next_level.push(hash);
        }

        level = next_level;
        current_index /= 2;
    }

    siblings
}

/// Reconstruct Merkle root from leaf and sibling hashes.
fn reconstruct_root(leaf_hash: Hash256, mut index: usize, siblings: &[Hash256]) -> Hash256 {
    let mut current_hash = leaf_hash;

    for sibling in siblings {
        current_hash = if index % 2 == 0 {
            hash_pair(&current_hash, sibling)
        } else {
            hash_pair(sibling, &current_hash)
        };
        index /= 2;
    }

    current_hash
}

/// Hash two nodes together.
fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    sha256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new();
        assert_eq!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_single_entry() {
        let mut tree = MerkleTree::new();
        let entry = Entry::new(1000, 0, b"data1");
        tree.insert(entry.clone());

        assert_eq!(tree.len(), 1);
        assert_eq!(tree.root(), entry.hash());
    }

    #[test]
    fn test_multiple_entries_sorted() {
        let mut tree = MerkleTree::new();

        tree.insert(Entry::new(3000, 0, b"data3"));
        tree.insert(Entry::new(1000, 0, b"data1"));
        tree.insert(Entry::new(2000, 0, b"data2"));

        let entries = tree.entries();
        assert_eq!(entries[0].timestamp_us, 1000);
        assert_eq!(entries[1].timestamp_us, 2000);
        assert_eq!(entries[2].timestamp_us, 3000);
    }

    #[test]
    fn test_merkle_proof() {
        let mut tree = MerkleTree::new();

        tree.insert(Entry::new(1000, 0, b"data1"));
        tree.insert(Entry::new(2000, 0, b"data2"));
        tree.insert(Entry::new(3000, 0, b"data3"));
        tree.insert(Entry::new(4000, 0, b"data4"));

        let root = tree.root();
        let proof = tree.generate_proof(2000, 0).unwrap();

        assert!(proof.verify(&root));
    }

    #[test]
    fn test_merkle_proof_invalid() {
        let mut tree = MerkleTree::new();

        tree.insert(Entry::new(1000, 0, b"data1"));
        tree.insert(Entry::new(2000, 0, b"data2"));

        let root = tree.root();
        let mut proof = tree.generate_proof(1000, 0).unwrap();

        // Tamper with proof
        proof.siblings[0][0] ^= 0xFF;

        assert!(!proof.verify(&root));
    }

    #[test]
    fn test_deterministic_root() {
        let mut tree1 = MerkleTree::new();
        tree1.insert(Entry::new(1000, 0, b"data1"));
        tree1.insert(Entry::new(2000, 0, b"data2"));

        let mut tree2 = MerkleTree::new();
        tree2.insert(Entry::new(2000, 0, b"data2"));
        tree2.insert(Entry::new(1000, 0, b"data1"));

        assert_eq!(tree1.root(), tree2.root(), "Root should be deterministic regardless of insertion order");
    }
}
