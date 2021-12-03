/*
    This module implements methods relating to Taproot key and address computing.

    Todo:
        - Rework huffman coding implementation
        - Seperate tree creation and tree application:
            > Existing huffman and most-balanced MAST tree creation methods should be migrated to the builder struct.
            > SpendInfo struct
                - Organise logic for key path spending and script path spending.
                - Extracting tweak values
                - Unit tests
        - Control block creation
            > Given the spend info struct, create a control block by either using key path spending or script path
              spending. If script path spending is used, the code needs to extract the markle path of the selected
              leaf.

*/
use std::collections::{
    HashMap, HashSet
};
use crate::{
    hash::{
        tagged_hash
    }, 
    key::{
        SchnorrPublicKey,
        Key,
        TapTweak
    },
    script::RedeemScript
};

#[derive(Debug)]
pub enum TaprootErr {
    BadLeaves,
    InvalidNode,
    MaxDepthExceeded,
    InvalidInsertionDepth,
    IncompleteTree,
    NoTree,
    OverCompleteTree,
    MissingMerkleRoot,
    MissingScriptMap,
    InvalidMerkleProof,
    NoLeaf
}

pub trait TaprootTaggedHash {
    fn from_slice(slice: &[u8]) -> [u8; 32];
}

/// Macro to create tagged hash types
macro_rules! taproot_tagged_hashes {
    ($name: ident, $tag: expr) => {
        pub struct $name;

        impl TaprootTaggedHash for $name {
            fn from_slice(slice: &[u8]) -> [u8; 32] {
                tagged_hash($tag, slice)
            }
        }
    }
}

// Define the three taproot tagged hashes
taproot_tagged_hashes!(TapTweakHash, "TapTweak");   // Used for the final key tweak
taproot_tagged_hashes!(TapBranchHash, "TapBranch"); // Used to hash script tree nodes together into a single branch node
taproot_tagged_hashes!(TapLeafHash, "TapLeaf");     // Used to hash script tree leaf nodes

impl TapTweakHash {
    /// Create the TapTweakHash from a schnorr public key and tweak value.
    /// Tweak value is either the merkle root of a script tree or nothing.
    pub fn from_key_and_tweak(key: &SchnorrPublicKey, tweak: Vec<u8>) -> [u8; 32] {
        let mut data = key.as_bytes::<32>().to_vec();
        data.extend_from_slice(&tweak);
        TapTweakHash::from_slice(&data)
    }
}

impl TapBranchHash {
    /// Return the hash of a branch node given two child nodes
    pub fn from_nodes(a: Node, b: Node) -> [u8; 32] {
        Self::combined_hash(a.hash, b.hash)
    }

    pub fn combined_hash(hash_1: [u8; 32], hash_2: [u8; 32]) -> [u8; 32] {
        let mut hash_1 = hash_1;
        let mut hash_2 = hash_2;
        
        //Swap the hashes by value if needed
        if hash_2 < hash_1 {
            let temp = hash_1;
            hash_1 = hash_2;
            hash_2 = temp;
        }

        //Concatenate the hashes starting with the smaller one and TapBranchHash it
        let mut hash_preimage = hash_1.to_vec();
        hash_preimage.extend_from_slice(&hash_2);
        TapBranchHash::from_slice(&hash_preimage)
    }
}

impl TapLeafHash {
    /// Return the hash of a leaf node given it's info
    pub fn from_leaf(leaf: &Leaf) -> [u8; 32] {
        let mut data = vec![leaf.version];
        data.extend_from_slice(&leaf.script.prefix_compactsize());

        TapLeafHash::from_slice(&data)
    }
}


#[derive(Debug, Clone, PartialEq)]
/// Builder to create taproot script trees.
// This tree builder provides t an API that lets users add leaves to the tree when
// given a leaf and desired depth. The leaf is then stored in a vector reflecting it's depth
// and when a new leaf or node is added at the same depth, it is combined and placed at the
// current depth - 1. This can be done recursively each time there are two nodes at a specific
// depth.
// The only limitation to this is that a leaves cannot be added when there are nodes at a lower
// level that are not yet combined. If this happens, there could be a rogue node stuck deep in
// the tree which makes MAST creation not possible until it gets combined upto to where it connects
// with the root.
//
// Nodes will have to store an array of leaves which they are composed of. Each leaf will 
// store the hashes required to construct the merkle path to the root from itself. This can be done
// by having the leaf store a vector of hashes and then when two nodes are combined, store the hash
// of the node being combined to self in each leaf in self.
// Eg.
//       For the tree:
//                           ROOT
//                        /        \
//                       B1        B2
//                      /  \      /  \
//                     A    B    C    B3
//                                   /  \
//                                  D    E
//
//      Leaf A would store:
//       - The hash of leaf B
//       - The hash of branch B2
//      Leaf B would store:
//       - The hash of leaf A
//       - The hash of branch B2
//      Leaf C would store:
//       - The hash of branch B3
//       - The hash of branch B1
//      Leaf D would store:
//       - The hash of leaf E
//       - The hash of leaf C
//       - The hash of branch B1
//      Leaf E would store:
//       - The hash of leaf D
//       - The hash of leaf C
//       - The hash of branch B1
//    
//      So when the tree is complete and exported as SpendInfo, the merkle path using A can is already pre
//      stored as a vector of hashes. This removes the need to compute merkle paths every time it is
//      requested as well as the need to store a script tree as a "tree".
//     
//      From the ROOT node containing every leaf (which contains the merkle proof of it self), the spend info
//      struct can be constructed by creating a hash map containing the leaf as key and merkle path as value.
//
//      When creating the above tree, it would have to be done in the order:
//       Leaf A, depth 2
//       Leaf B, depth 2
//       Leaf C, depth 2
//       Leaf D, depth 3
//       Leaf E, depth 3
//     
//      If depth 3 is created prior to depth 2, it will instead look like this:
//                           ROOT
//                        /        \
//                       B1        B2
//                      /  \      /  \
//                     B2   A    B    C
//                    /  \
//                   D    E
//
//       What cannot be done is to start creating depth 2 while depth 3 is still incomplete.
//       It technically will still work for this case, but if this is allowed it can lead to
//       bugs in other cases.
pub struct TaprootScriptTreeBuilder {
    // The binary tree is represented as an array in the builder for ease of use and traversal.
    nodes: Vec<Option<Node>>
}

impl TaprootScriptTreeBuilder {
    /// Return a new instance of the builder
    pub fn new() -> Self {
        Self { nodes: vec![] }
    }

    /// Insert a leaf at a given depth
    pub fn insert_leaf(&mut self, leaf: Leaf, depth: usize) -> Result<(), TaprootErr> {
        let node = Node::new_leaf(leaf);
        self.insert(node, depth)
    }

    /// Insert a new leaf node to the script tree at a given depth
    pub fn insert(&mut self, node: Node, depth: usize) -> Result<(), TaprootErr> {
        // Return an error if a node is attempted to be inserted at an invalid depth.
        if depth > 127 { return Err(TaprootErr::MaxDepthExceeded) }
        // if depth < self.nodes.len() { return Err(TaprootErr::InvalidInsertionDepth) }

        // If the nodes vector is not long enough, extend it.
        if self.nodes.len() < depth + 1 {
            while self.nodes.len() < depth + 1 { self.nodes.push(None) }
        }

        // Match the value at a certain depth...
        match &self.nodes[depth] {
            Some(existing_node) => {
                // Return an error when we try to combine two nodes at the root level.
                if depth == 0 {
                    return Err(TaprootErr::OverCompleteTree)
                }

                // If we are not at the root and if a node at a depth exists, combine it
                //and propagate it to the depth above.
                let combined_node = Node::combine(node, existing_node.to_owned());
                self.nodes[depth] = None;
                self.insert(combined_node, depth-1)?;
            },
            None => {
                // If there is no node at this depth, store the current node at the depth so it 
                // can be combined later if needed.
                self.nodes[depth] = Some(node)
            }
        }

        Ok(())
    }

    /// Turn a complete tree into spend info
    pub fn complete(self, internal_key: &SchnorrPublicKey) -> Result<SpendInfo, TaprootErr> {
        // The tree needs to consist of a single node to be considered complete.
        // In this case, the first node needs to be some and the rest of the nodes array needs to be none.
        if self.nodes[0].is_none() && self.nodes.iter().skip(1).any(|x| x.is_some()) {
            return Err(TaprootErr::IncompleteTree)
        }

        let node = self.nodes[0].clone();
        Ok(
            SpendInfo::new(internal_key, node)
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    // The hash of this node.
    // For leaf nodes, the hash is the TapLeaf hash of the single leaf.
    // For branch nodes, the hash is the TapBranch hash of the child node hashes.
    hash: [u8; 32],

    // The leaves contained in this node.
    leaves: Vec<Leaf>
}

impl Node {
    /// New leaf node
    pub fn new_leaf(leaf: Leaf) -> Self {
        Self {
            hash: leaf.tapleaf_hash(),
            leaves: vec![leaf]
        }
    }

    /// Combine two nodes together, adding a new merkle proof hash to every leaf that is part
    /// of the merger.
    pub fn combine(a: Self, b: Self) -> Self {
        // The new node will contain a vector of all the leaves in it's children.
        // Each leaf will have a new merkle proof added being the other node they are being
        // combined with.
        let mut combined_leaves: Vec<Leaf> = vec![];
        for mut leaf in a.leaves.clone() {
            leaf.merkle_proof.push(b.hash);
            combined_leaves.push(leaf);
        }
        for mut leaf in b.leaves.clone() {
            leaf.merkle_proof.push(a.hash);
            combined_leaves.push(leaf);
        }


        Self {
            hash: TapBranchHash::from_nodes(a, b),
            leaves: combined_leaves
        }
    }
}

#[derive(Hash, Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    version: u8,
    script: RedeemScript,
    merkle_proof: MerkleProof
}

impl Leaf {
    /// New leaf with a specified version and script
    pub fn new_with_version(version: u8, script: &RedeemScript) -> Self {
        Self {
            version,
            script: script.clone(),
            merkle_proof: MerkleProof(vec![])
        }
    }

    /// New leaf with default version of 0xc0 and provided script
    pub fn new(script: &RedeemScript) -> Self {
        Self::new_with_version(0xc0, script)
    }

    /// TapLeafHash of the leaf
    pub fn tapleaf_hash(&self) -> [u8; 32] {
        TapLeafHash::from_leaf(self)
    }
}

#[derive(Hash, Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof(Vec<[u8; 32]>);


impl MerkleProof {
    // Methods required:
    pub fn new() -> Self {
        Self(vec![])
    }

    /// Push a new hash in
    pub fn push(&mut self, hash: [u8; 32]) {
        self.0.push(hash)
    }

    /// Return the underlying hash vector
    pub fn into_inner(&self) -> Vec<[u8; 32]> {
        self.0.clone()
    }

    /// Return the length of the peth in self.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, Clone)]
pub struct ScriptMap(HashMap<Leaf, HashSet<MerkleProof>>);

impl ScriptMap {
    // Methods required:
    //  - Merkle proof verification given a merkle root and script map.

    /// Create a new script map from a vector of leaves where each leaf 
    /// contains the merkle proof for itself.
    pub fn from_leaves(leaves: Vec<Leaf>) -> Self {
        let mut map: HashMap<Leaf, HashSet<MerkleProof>> = HashMap::new();
        for mut leaf in leaves {
            match map.get_mut(&leaf) {
                Some(set) => {
                    // Leaf already exists in the map.
                    // Push in the measured merkle proof for this script and go to the next leaf.
                    set.insert(leaf.merkle_proof);
                    continue;
                },
                None => {
                    // Leaf does not exist in the map.
                    // Create a new entry in the map for this leaf.
                    let mut set: HashSet<MerkleProof> = HashSet::new();
                    set.insert(leaf.merkle_proof.clone());
                    leaf.merkle_proof = MerkleProof(vec![]); //Set the merkle proof inside the leaf to empty since it is already stored in the HashSet.
                    map.insert(leaf, set);
                }
            }
        }

        Self(map)
    }

    /// Check if a script map's items all match up to a given merkle root hash.
    pub fn verify_merkle_proof(&self, merkle_root: [u8; 32]) -> bool {
        // For each leaf...
        self.0.iter().all(|item| {
            // for each proof...
            let (leaf, merkle_proofs) = (item.0, item.1);
            merkle_proofs.iter().all(|proof| {
                // recursively check if each proof reduces to the merkle root.
                let mut hashes = vec![leaf.tapleaf_hash()]; 
                hashes.extend_from_slice(&proof.into_inner());
                
                while hashes.len() != 1 {
                    let combined_hash = TapBranchHash::combined_hash(hashes[0], hashes[1]);

                    // Remove the two used hashes and insert the newly combined hash
                    hashes.remove(0);
                    hashes.remove(0);
                    hashes.insert(0, combined_hash);
                }

                hashes[0] == merkle_root
            })

        })
    }

    /// Get the shortest merkle proof for a leaf in a script map.
    /// If the leaf does not exist, return an error.
    /// 
    /// get() is not working given a random leaf becase the leaf stored in here contains the merkle proof which we do not know.
    pub fn merkle_proof_for_leaf(&self, leaf: Leaf) -> Result<MerkleProof, TaprootErr> {
        return match self.0.get(&leaf) {
            Some(set) => {
                // Return the shortest merkle proof by comparing the length of every merkle proof the leaf has.
                Ok(
                    set
                        .iter()
                        .min_by(
                            |a, b| 
                            a.len().cmp(&b.len())
                        )
                        .expect("Merkle proof missing")
                        .clone()
                )
            },
            None => Err(TaprootErr::NoLeaf)
        }
    }
}


#[derive(Debug, Clone)]
pub struct SpendInfo {
    pub internal_key: SchnorrPublicKey,
    pub parity: bool,
    pub merkle_root: Option<MerkleRoot>,  // Only exists if there is a script tree
    pub script_map: Option<ScriptMap>     // Only exists if there is a script tree
}

pub type MerkleRoot = [u8; 32];

impl SpendInfo {
    // Create a new spend info struct from a given internal key and optional script tree.
    pub fn new(key: &SchnorrPublicKey, node: Option<Node>) -> Self {
        let (merkle_root, script_map) = match node {
            Some(x) => (Some(x.hash), Some(ScriptMap::from_leaves(x.leaves))),
            None => (None, None)
        };

        let parity = key.tweaked_parity(merkle_root).expect("TapTweak failed");
        
        
        Self {
            internal_key: key.clone(),
            merkle_root,
            parity,
            script_map
        }
    }

    /// Verify the merkle proof stored in self using the merkle root stored in self.
    /// If a script map, merkle root or both are missing, an error is returned.
    pub fn verify_merkle_proof(&self) -> Result<bool, TaprootErr> {
        match &self.script_map {
            Some(map) => {
                match self.merkle_root {
                    Some(root) => return Ok(map.verify_merkle_proof(root)),
                    None => return Err(TaprootErr::MissingMerkleRoot)
                }
            },
            None => {
                match self.merkle_root {
                    Some(_) => return Err(TaprootErr::MissingScriptMap),
                    None => return Err(TaprootErr::NoTree)
                }
            }
        }
    }

    /// Creates a taproot control block that must be present in the witness stack when spending using the
    /// script path.
    pub fn control_block(&self) -> ControlBlock {
        todo!();
    }
}



#[derive(Debug, Clone)]
pub struct ControlBlock {
    revealed_leaf: Leaf,
    parity_bit: bool,
    internal_key: SchnorrPublicKey,
    merkle_path: MerkleProof
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        key::*
    };

    #[test]
    /**
        Implementing a two leaf script tree example from 
        https://github.com/bitcoin-core/btcdeb/blob/master/doc/tapscript-example.md
    */
    fn btcdeb_twoleaf_test() {
        // Keys and scripts used in the test
        let internal_key = SchnorrPublicKey::from_str("5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5").unwrap();
        let script_1 = RedeemScript::new(crate::util::decode_02x("029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac"));
        let script_2 = RedeemScript::new(crate::util::decode_02x("a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac"));

        // Build the script tree
        let mut builder = TaprootScriptTreeBuilder::new();
        builder.insert_leaf(Leaf::new(&script_1), 1).unwrap();
        builder.insert_leaf(Leaf::new(&script_2), 1).unwrap();
        let spend_info = builder.complete(&internal_key).unwrap();

        // Verify merkle root and merkle paths
        let merkle_root = crate::util::decode_02x("41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b"); 
        assert_eq!(spend_info.merkle_root.unwrap().to_vec(), merkle_root);
        assert!(spend_info.verify_merkle_proof().unwrap());

        // Tweak the internal key by the merkle root
        let tweaked_key = spend_info.internal_key.tap_tweak(spend_info.merkle_root).unwrap();
        let expected_tweaked_key = "f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c";
        assert_eq!(tweaked_key.to_string(), expected_tweaked_key);
    }

    #[test]
    /**
        Tests if key tweaking logic is working correctly by creating a random key pair, seperating the public key from
        it, and tweaking the keypair as a secret key and the public key as a public key and comparing the resulting tweaked
        public keys to each other. 
    */
    fn key_tweaking_test() {
        let key_pair = SchnorrKeyPair::from_priv_key(&PrivKey::new_rand()).unwrap();
        let pub_key = key_pair.get_pub();
        let mut builder  = TaprootScriptTreeBuilder::new();
        builder.insert_leaf(
            Leaf::new(&RedeemScript::new(vec![5, 29, 03])),
            0
        ).unwrap();
        let spend_info = builder.complete(&pub_key).unwrap();

        let tweaked_keypair = key_pair.tap_tweak(spend_info.merkle_root).unwrap();
        let tweaked_pub_key = pub_key.tap_tweak(spend_info.merkle_root).unwrap();

        assert_eq!(tweaked_keypair.get_pub(), tweaked_pub_key);
    }
}
