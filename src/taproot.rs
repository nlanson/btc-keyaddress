/*
    This module implements methods relating to Taproot key and address computing.

    Todo:
        - SpendInfo struct:
            > Extracting tweak values
        - Tree builder
            > Huffman coding reimplementation using the tree builder
            > Unit tests!

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
        let non_root_nodes = &self.nodes[1..];
        if self.nodes[0].is_none() || !non_root_nodes.iter().all(|x| x.is_none()) {
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
    /// Create a new empty merkle proof vector
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
    /// Returns a new empty script map
    pub fn new() -> ScriptMap {
        ScriptMap(HashMap::new())
    }

    /// Checks if the script map contains any elements.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

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
    pub fn merkle_proof(&self, leaf: Leaf) -> Result<MerkleProof, TaprootErr> {
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
    pub script_map: ScriptMap             // Will be empty if no script tree is present.
}

pub type MerkleRoot = [u8; 32];

impl SpendInfo {
    // Create a new spend info struct from a given internal key and optional script tree.
    pub fn new(key: &SchnorrPublicKey, node: Option<Node>) -> Self {
        let (merkle_root, script_map) = match node {
            Some(x) => (Some(x.hash), ScriptMap::from_leaves(x.leaves)),
            None => (None, ScriptMap::new())
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
        match self.merkle_root {
            Some(hash) => {
                if !self.script_map.is_empty() {
                    return Ok(self.script_map.verify_merkle_proof(hash))
                } else {
                    return Err(TaprootErr::MissingScriptMap)
                }
            },
            None => {
                if !self.script_map.is_empty() {
                    return Err(TaprootErr::MissingMerkleRoot)
                } else {
                    return Err(TaprootErr::NoTree)
                }
            }
        }
    }

    /// Creates a taproot control block that must be present in the witness stack when spending using the
    /// script path.
    pub fn control_block(&self, leaf: Leaf) -> Result<ControlBlock, TaprootErr> {
        Ok(
            ControlBlock::new(
                leaf.version,
                self.parity,
                self.internal_key,
                self.script_map.merkle_proof(leaf)?  // If the script map fails to find a merkle proof for the given leaf, it will return an error.
            )
        )
    }

    /// Return the value of the tweak that should be applied to get from the internal key to the output key
    pub fn tweak_value(&self) -> [u8; 32] {
        SchnorrPublicKey::tweak_value(&self.internal_key, self.merkle_root)
    }
}


/// The control block contains information required when spending a Taproot UTXO using the script path.
/// It resides on the witness stack as the final element for a taproot script spend.
/// The witness stack for a taproot script path spend consists of:
///     1. The inputs required to satisfy the script conditions
///     2. The revealed script itself
///     3. The control block which consists of all other information requried.
/// 
/// The block provides necesary information for validators to recompute the tweak applied to the internal key.
/// This is done hashing the provided merkle path until the merkle root is reached and then using the root to 
/// compute the tweak which is then applied to the internal key.
#[derive(Debug, Clone)]
pub struct ControlBlock {
    leaf_version: u8,
    parity: bool,
    internal_key: SchnorrPublicKey,
    merkle_proof: MerkleProof
}

impl ControlBlock {
    /// Return a control block struct from provided information.
    pub fn new(
        leaf_version: u8,
        parity: bool,
        internal_key: SchnorrPublicKey,
        merkle_proof: MerkleProof
    ) -> Self {
        ControlBlock {
            leaf_version,
            parity,
            internal_key,
            merkle_proof
        }
    }


    /// Serialize the control block.
    pub fn serialize(&self) -> Vec<u8> {
        unimplemented!("Serialization for transactions is outside the scope of this library.")
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        key::*,
        address::Address,
        util::{Network, decode_02x}
    };

    #[test]
    /**
        Implementing a two leaf script tree example from 
        https://github.com/bitcoin-core/btcdeb/blob/master/doc/tapscript-example.md
    */
    fn btcdeb_twoleaf_test() {
        // Keys and scripts used in the test
        let internal_key = SchnorrPublicKey::from_str("5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5").unwrap();
        let script_1 = RedeemScript::from_str("029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac");
        let script_2 = RedeemScript::from_str("a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac");

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
    fn bip_341_test_vectors() -> Result<(), TaprootErr> {
        // This tests is composed of 7 seperate test cases from the BIP-341 test vectors.
        // Each case starts with an internal key and optional script tree and tests whether
        // the code can reach the final script pub key using the given information.
        //
        // Test keys:
        let internal_keys = [
            SchnorrPublicKey::from_str("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d").unwrap(),
            SchnorrPublicKey::from_str("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27").unwrap(),
            SchnorrPublicKey::from_str("93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820").unwrap(),
            SchnorrPublicKey::from_str("ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592").unwrap(),
            SchnorrPublicKey::from_str("f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8").unwrap(),
            SchnorrPublicKey::from_str("e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f").unwrap(),
            SchnorrPublicKey::from_str("55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d").unwrap()
        ];

        // Test cases:
        // #1
        let spend_info = SpendInfo::new(&internal_keys[0], None);
        let tweaked_key = spend_info.internal_key.tap_tweak(None).unwrap();
        assert_eq!(tweaked_key, SchnorrPublicKey::from_str("53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343").unwrap());
        assert_eq!(Address::P2TR(tweaked_key, Network::Bitcoin).to_string().unwrap(), "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5");

        // #2
        let mut builder = TaprootScriptTreeBuilder::new();
        builder.insert_leaf(Leaf::new(&RedeemScript::from_str("20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac")), 0).unwrap();
        let spend_info = builder.complete(&internal_keys[1]).unwrap();
        assert_eq!(spend_info.merkle_root.unwrap().to_vec(), decode_02x("5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21"));
        let tweaked_key = spend_info.internal_key.tap_tweak(spend_info.merkle_root).unwrap();
        assert_eq!(Address::P2TR(tweaked_key, Network::Bitcoin).to_string().unwrap(), "bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586");
        
        // #3
        let mut builder = TaprootScriptTreeBuilder::new();
        builder.insert_leaf(Leaf::new(&RedeemScript::from_str("20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac")), 0).unwrap();
        let spend_info = builder.complete(&internal_keys[2]).unwrap();
        assert_eq!(spend_info.merkle_root.unwrap().to_vec(), decode_02x("c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b"));
        let tweaked_key = spend_info.internal_key.tap_tweak(spend_info.merkle_root).unwrap();
        assert_eq!(Address::P2TR(tweaked_key, Network::Bitcoin).to_string().unwrap(), "bc1punvppl2stp38f7kwv2u2spltjuvuaayuqsthe34hd2dyy5w4g58qqfuag5");

        // #4
        let mut builder = TaprootScriptTreeBuilder::new();
        builder.insert_leaf(Leaf::new(&RedeemScript::from_str("20387671353e273264c495656e27e39ba899ea8fee3bb69fb2a680e22093447d48ac")), 1).unwrap();
        builder.insert_leaf(Leaf::new_with_version(250, &RedeemScript::from_str("06424950333431")), 1).unwrap();
        let spend_info = builder.complete(&internal_keys[3]).unwrap();
        assert_eq!(spend_info.merkle_root.unwrap().to_vec(), decode_02x("6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef"));
        let tweaked_key = spend_info.internal_key.tap_tweak(spend_info.merkle_root).unwrap();
        assert_eq!(Address::P2TR(tweaked_key, Network::Bitcoin).to_string().unwrap(), "bc1pwyjywgrd0ffr3tx8laflh6228dj98xkjj8rum0zfpd6h0e930h6saqxrrm");

        // #5
        let mut builder = TaprootScriptTreeBuilder::new();
        builder.insert_leaf(Leaf::new(&RedeemScript::from_str("2044b178d64c32c4a05cc4f4d1407268f764c940d20ce97abfd44db5c3592b72fdac")), 1).unwrap();
        builder.insert_leaf(Leaf::new(&RedeemScript::from_str("07546170726f6f74")), 1).unwrap();
        let spend_info = builder.complete(&internal_keys[4]).unwrap();
        assert_eq!(spend_info.merkle_root.unwrap().to_vec(), decode_02x("ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc"));
        let tweaked_key = spend_info.internal_key.tap_tweak(spend_info.merkle_root).unwrap();
        assert_eq!(Address::P2TR(tweaked_key, Network::Bitcoin).to_string().unwrap(), "bc1pwl3s54fzmk0cjnpl3w9af39je7pv5ldg504x5guk2hpecpg2kgsqaqstjq");

        // #6
        let mut builder = TaprootScriptTreeBuilder::new();
        builder.insert_leaf(Leaf::new(&RedeemScript::from_str("2072ea6adcf1d371dea8fba1035a09f3d24ed5a059799bae114084130ee5898e69ac")), 1).unwrap();
        builder.insert_leaf(Leaf::new(&RedeemScript::from_str("202352d137f2f3ab38d1eaa976758873377fa5ebb817372c71e2c542313d4abda8ac")), 2).unwrap();
        builder.insert_leaf(Leaf::new(&RedeemScript::from_str("207337c0dd4253cb86f2c43a2351aadd82cccb12a172cd120452b9bb8324f2186aac")), 2).unwrap();
        let spend_info = builder.complete(&internal_keys[5]).unwrap();
        assert_eq!(spend_info.merkle_root.unwrap().to_vec(), decode_02x("ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2"));
        let tweaked_key = spend_info.internal_key.tap_tweak(spend_info.merkle_root).unwrap();
        assert_eq!(Address::P2TR(tweaked_key, Network::Bitcoin).to_string().unwrap(), "bc1pjxmy65eywgafs5tsunw95ruycpqcqnev6ynxp7jaasylcgtcxczs6n332e");

        // #7
        let mut builder = TaprootScriptTreeBuilder::new();
        builder.insert_leaf(Leaf::new(&RedeemScript::from_str("2071981521ad9fc9036687364118fb6ccd2035b96a423c59c5430e98310a11abe2ac")), 1).unwrap();
        builder.insert_leaf(Leaf::new(&RedeemScript::from_str("20d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748ac")), 2).unwrap();
        builder.insert_leaf(Leaf::new(&RedeemScript::from_str("20c440b462ad48c7a77f94cd4532d8f2119dcebbd7c9764557e62726419b08ad4cac")), 2).unwrap();
        let spend_info = builder.complete(&internal_keys[6]).unwrap();
        assert_eq!(spend_info.merkle_root.unwrap().to_vec(), decode_02x("2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def"));
        let tweaked_key = spend_info.internal_key.tap_tweak(spend_info.merkle_root).unwrap();
        assert_eq!(Address::P2TR(tweaked_key, Network::Bitcoin).to_string().unwrap(), "bc1pw5tf7sqp4f50zka7629jrr036znzew70zxyvvej3zrpf8jg8hqcssyuewe");

        Ok(())
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

    #[test]
    fn tree_builder_should_fail() {
        // This tree fails when inserting the fourth leaf at depth 1 beacuse it tries to combine the third 
        // and fourth leaf together and propagate it to a level above but the level above (root) is already
        // full.
        let mut builder = TaprootScriptTreeBuilder::new();
        let leaf = Leaf::new(&RedeemScript::new(vec![0]));
        builder.insert_leaf(leaf.clone(), 1).unwrap();
        builder.insert_leaf(leaf.clone(), 1).unwrap();
        builder.insert_leaf(leaf.clone(), 1).unwrap();
        assert!(match builder.insert_leaf(leaf.clone(), 1) {
            Ok(_) => false,
            Err(x) => match x {
                TaprootErr::OverCompleteTree => true,
                _ => false
            }
        });

        
        // This tree fails because there is a dangling leaf. It is incomplete.
        let mut builder = TaprootScriptTreeBuilder::new();
        builder.insert_leaf(leaf.clone(), 1).unwrap();
        builder.insert_leaf(leaf.clone(), 1).unwrap();
        builder.insert_leaf(leaf.clone(), 2).unwrap();
        let key = SchnorrPublicKey::from_str("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d").unwrap();
        assert!(match builder.complete(&key) {
            Ok(_) => false,
            Err(x) => match x {
                TaprootErr::IncompleteTree => true,
                _ => false
            }
        })
    }
}
