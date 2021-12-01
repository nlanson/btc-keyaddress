/*
    This module implements methods relating to Taproot key and address computing.

    Todo:
        - Rework huffman coding implementation
        - Seperate tree creation and tree application:
            > Tree creation/builder struct
                - As a potential approach to the builder, an API could be provided to add leaves to the tree
                  given the leaf and desired depth, then store the leaf at a position in the array reflecting
                  the specified depth. When another leaf is added at the same depth, combine the existing leaf
                  with the new leaf and place the new combined node at the current depth - 1. This can be done
                  recursively each time there are two nodes at a specific depth.
                  The only limitation to this is that a leaves cannot be added when there are nodes at a lower
                  level that are not yet combined. If this happens, there could be a rogue node stuck deep in
                  the tree which makes MAST creation not possible until it gets combined upto to where it connects
                  with the root.

                  Nodes will have to store an array of leaves which they are composed of. Each leaf will 
                  store the hashes required to construct the merkle path to the root from itself. This can be done
                  by having the leaf store a vector of hashes and then when two nodes are combined, store the hash
                  of the node being combined to self in each leaf in self.
                  Eg.
                        For the tree:
                                            ROOT
                                         /        \
                                        B1        B2
                                       /  \      /  \
                                      A    B    C    B3
                                                    /  \
                                                   D    E

                       Leaf A would store:
                        - The hash of leaf B
                        - The hash of branch B2
                       Leaf B would store:
                        - The hash of leaf A
                        - The hash of branch B2
                       Leaf C would store:
                        - The hash of branch B3
                        - The hash of branch B1
                       Leaf D would store:
                        - The hash of leaf E
                        - The hash of leaf C
                        - The hash of branch B1
                       Leaf E would store:
                        - The hash of leaf D
                        - The hash of leaf C
                        - The hash of branch B1
                      
                       So when the tree is complete and exported as SpendInfo, the merkle path using A can is already pre
                       stored as a vector of hashes. This removes the need to compute merkle paths every time it is
                       requested as well as the need to store a script tree as a "tree".
                       
                       From the ROOT node containing every leaf (which contains the merkle proof of it self), the spend info
                       struct can be constructed by creating a hash map containing the leaf as key and merkle path as value.

                       When creating this tree, it would have to be done in the order:
                        Leaf A, depth 2
                        Leaf B, depth 2
                        Leaf C, depth 2
                        Leaf D, depth 3
                        Leaf E, depth 3
                       
                       If depth 3 is created prior to depth 2, it will instead look like this:
                                            ROOT
                                         /        \
                                        B1        B2
                                       /  \      /  \
                                      B2   A    B    C
                                     /  \
                                    D    E

                        What cannot be done is to start creating depth 2 while depth 3 is still incomplete.
                        It technically will still work for this case, but if this is allowed it can lead to
                        bugs in other cases.
                       
                
                - Existing huffman and most-balanced MAST tree creation methods should be migrated to the builder struct.

            > Tree application struct
                - Extracting hashes (merkle root)
                - Merkle path computation (given a leaf, returns a vector of hashes)
        - Control block creation
            > Given an internal key, script tree and selected leaf (script), create the control block by:
                - Finding the parity bit by tweaking the internal key by the merkle root.
                - Computing the merkle path by using depth first search.

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
    },
    script::RedeemScript
};

#[derive(Debug)]
pub enum TaprootErr {
    BadLeaves,
    InvalidNode,
    MaxDepthExceeded,
    InvalidInsertionDepth
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
    pub fn from_nodes(left: &TreeNode, right: &TreeNode) -> [u8; 32] {
        //Extract the hashes of the child nodes.
        let (left_hash, right_hash) = (left.value.as_hash(), right.value.as_hash());

        Self::combined_hash(left_hash, right_hash)
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

    pub fn from_builder_leaf(leaf: &Leaf) -> [u8; 32] {
        let mut data = vec![leaf.version];
        data.extend_from_slice(&leaf.script.prefix_compactsize());

        TapLeafHash::from_slice(&data)
    }
}


#[derive(Debug, Clone, PartialEq)]
/// Builder to create taproot script trees.
pub struct TaprootScriptTreeBuilder {
    // The binary tree is represented as an array in the builder for ease of use and traversal.
    nodes: Vec<Option<Node>>
}

impl TaprootScriptTreeBuilder {
    /// Return a new instance of the builder
    pub fn new() -> Self {
        Self { nodes: vec![] }
    }

    /// Insert a new leaf node to the script tree at a given depth
    pub fn insert(mut self, leaf: Leaf, depth: usize) -> Result<Self, TaprootErr> {
        todo!();
    }

    /// Turn a complete tree into spend info
    pub fn complete(self) -> Result<SpendInfo, TaprootErr> {
        todo!();
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
        for mut leaf in a.leaves {
            leaf.merkle_proof.push(b.hash);
            combined_leaves.push(leaf);
        }
        for mut leaf in b.leaves {
            leaf.merkle_proof.push(a.hash);
            combined_leaves.push(leaf);
        }


        Self {
            hash: TapBranchHash::combined_hash(a.hash, b.hash),
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
        TapLeafHash::from_builder_leaf(self)
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
        for leaf in leaves {
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
                // Recursively check if each proof reduces to the merkle root.
                let mut hashes = vec![leaf.tapleaf_hash()]; 
                hashes.extend_from_slice(&proof.into_inner());
                
                while hashes.len() != 1 {
                    let combined_hash = TapBranchHash::combined_hash(hashes[0], hashes[1]);
                    
                    hashes.remove(0);
                    hashes.remove(1);
                    hashes.insert(0, combined_hash);
                }

                hashes[0] == merkle_root
            })

        })
    }
}


#[derive(Debug, Clone)]
pub struct SpendInfo {
    internal_key: SchnorrPublicKey,
    merkle_root: Option<[u8; 32]>,
    parity: bool,
    script_map: ScriptMap
}

impl SpendInfo {
    // Methods required:
    //  - Create new spend info struct from key and NodeInfo
    //  - Control block creation from spend info
}




/**
    TreeNode struct for taproot application.
*/
#[derive(Debug, Clone, PartialEq)]
pub struct TreeNode {
    pub left: Option<Box<TreeNode>>,
    pub right: Option<Box<TreeNode>>,

    //This value here could be an enum `TreeNodeInfo` which contains either a (leaf version, script) tuple or hash of children
    //By doing this, each node will contain a value whether it is a leaf or branch and removes the need for an Option
    pub value: NodeValue  
}

#[derive(Debug, Clone, PartialEq)]
/// NodeValue struct stores the hash of a value in a tree.
pub enum NodeValue {
    Branch([u8; 32]),
    Leaf([u8; 32])
}

impl NodeValue {
    /// Return the hash of the node's value.
    pub fn as_hash(&self) -> [u8; 32] {
        match self {
            NodeValue::Branch(hash) => *hash,
            NodeValue::Leaf(leaf) => *leaf
        }
    }
}


#[derive(Debug, Clone)]
pub struct HuffmanCoding<T> {
    freq: usize,
    val: T
}

impl HuffmanCoding<RedeemScript> {
    /// New item to add to huffman tree given it's frequency and script
    pub fn new_item(freq: usize, script: &RedeemScript) -> Self {
        Self {
            freq,
            val: script.clone()
        }
    }
    
    /**
        Creates a huffman tree given a vector of frequencies and items.
        
        Currently, the tree gets cconstructed by repeatedly combining the two least frequent items
        into a single node. This node is placed back into list with it's frequency being the sum of
        the combined items. 
        When combining nodes, the least frequent (or the item at the end of the array) is placed into
        the right hand side of the combined node.

        When the nodes are combined and inserted back into the table, it is simply pushed into
        the table vector and the table vector is sorted again. The sorting method, vec::sort_by()
        DOES NOT reorder equal elements meaning the combined node stays at the end if there are any
        other equally weighted elements.

        Needs more test cases to check for stability and consistency.
    */
    pub fn new_script_tree(items: &Vec<Self>) -> TreeNode {
        //Create a (frequency, leaf node) table from each item
        let mut table = items.iter().map(|x| {
            let node = TreeNode::new(None, None, Some(Leaf::new(&x.val))).unwrap();
            
            (x.freq, node)
        }).collect::<Vec<(usize, TreeNode)>>();

        //Sort the table in decending order of frequency
        table.sort_by(|a, b| b.0.cmp(&a.0));
        
        //While the table does not consist of a single root node
        while table.len() != 1 {
            //Get the last two rows of the table
            let l2i: Vec<(usize, TreeNode)> = table.iter().rev().take(2).map(|x|(x.0, x.1.clone())).collect();
            //table[table.len()-2..table.len()-1].to_vec();

            //Sum the frequencies
            let sum: usize = l2i[0].0 + l2i[1].0;

            //Combine the two nodes into a single Node with each as a branch
            let right = l2i[0].1.clone();  //smaller
            let left = l2i[1].1.clone();   //larger
            let combined_node: TreeNode = TreeNode::construct_tree(vec![left, right]);

            //Remove the last two items
            table.remove(table.len()-1);
            table.remove(table.len()-1);

            //Push the combined node and sum of frequencies into the table and sort again.
            //This method of inserting the combined node might not be consistent. Later, a custom insertion method should
            //be written for consistency. 
            //But for now, it stays.
            table.push((sum, combined_node));
            table.sort_by(|a, b| b.0.cmp(&a.0)); 
        }

        table[0].1.clone()
    }
}


impl TreeNode {
    /// Create a new tree node given either a left and right child or a leaf value.
    /// If left and right children are given, the node is interpreted to be a branch node.
    /// If a leaf value is given, the node is interpreted to be a leaf node.
    pub fn new(left: Option<Self>, right: Option<Self>, value: Option<Leaf>) -> Result<Self, TaprootErr> {
        //Branch node | Has both branches and no value
        if left.is_some() && right.is_some() && value.is_none() {
            // Get the hash of the two children
            let branch_hash = TapBranchHash::from_nodes(&left.as_ref().unwrap(), &right.as_ref().unwrap());
            
            Ok(
                Self {
                    left: Some(Box::new(left.unwrap())),
                    right: Some(Box::new(right.unwrap())),
                    value: NodeValue::Branch(branch_hash)
                }
            )
        }

        //Leaf node | Has no branches but has a value
        else if left.is_none() && right.is_none() && value.is_some(){
            Ok(
                Self {
                    left: None,
                    right: None,
                    value: NodeValue::Leaf(value.unwrap().tapleaf_hash())
                }
            )
        }

        //Invalid node | Other combinations
        else {
            Err(TaprootErr::InvalidNode)
        }
    }
    
    /// Create a new tree from a list of scripts
    pub fn new_script_tree(scripts: &Vec<RedeemScript>) -> Self {
        //Create leaves from scripts
        let leaves: Vec<TreeNode> = scripts.iter().map(|x| {
            TreeNode::new(None, None, Some(Leaf::new(x))).unwrap()
        }).collect::<Vec<TreeNode>>();

        Self::construct_tree(leaves)
    }

    /**
        Tries to create the most balanced tree from any amount of leaves.
        Does this by combining left over leaves with the last parent.
    */
    pub fn construct_tree(leaves: Vec<TreeNode>) -> Self {
        //If there is only one leaf left, return it
        if leaves.len() == 1 { return leaves[0].clone() }

        //Create new parent nodes by grouping two leaves together
        let mut parent_level: Vec<TreeNode> = vec![];
        for i in (0..leaves.len()).step_by(2) { //bug: loop fucks up with odd numbers
            //If there is a left over node, push a parent combining the left over node and the last parent created.
            if i+1 == leaves.len() { 
                let last_parent = parent_level[parent_level.len() - 1].clone();
                let left_over_child = leaves[leaves.len() - 1].clone();
    
                parent_level.remove(parent_level.len() - 1);
                parent_level.push(Self::construct_tree(vec![last_parent, left_over_child]));    
                
                continue;
            }
            
            //Push a parent node combining two child nodes
            parent_level.push( 
                TreeNode::new(Some(leaves[i].clone()), Some(leaves[i+1].clone()), None).unwrap()
            )
        }

        //Call self again using parent level
        Self::construct_tree(parent_level)
    }

    /// Returns the root hash of a given tree node.
    pub fn merkle_root(&self) -> [u8; 32] {
        self.value.as_hash()
    }

    /// Determine whether the current node is a leaf node or not.
    pub fn is_leaf(&self) -> bool {
        match self.value {
            NodeValue::Leaf(_) => {
                // If the node value stores a leaf and there are no children, then the node is a leaf node.
                self.right.is_none() && self.left.is_none()
            },
            _ => false
        }
    }

    /// Determine whether the current node is a branch node or not.
    pub fn is_branch(&self) -> bool {
        match self.value {
            NodeValue::Branch(_) => {
                // If the node value stores a branch hash and there are two children, it is a branch node.
                self.left.is_some() && self.right.is_some()
            },
            _ => false
        }
    }

    /// Update the hash stored in a branch node
    pub fn update_hash(&mut self) -> Result<(), TaprootErr> {
        if self.is_branch() {
            self.value = NodeValue::Branch(
                TapBranchHash::from_nodes(self.left.as_ref().unwrap(), self.right.as_ref().unwrap())
            )
        }

        Ok(())
    }

    /// Update the leaf value in a leaf node
    pub fn update_leaf(&mut self, new_value: &Leaf) {
        if self.is_leaf() {
            self.value = NodeValue::Leaf(new_value.tapleaf_hash())
        }
    }
}


#[derive(Debug, Clone)]
pub struct ControlBlock {
    revealed_leaf: Leaf,
    parity_bit: bool,
    internal_key: SchnorrPublicKey,
    merkle_path: Vec<[u8; 32]>
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
        //The public keys involved in the test scenario
        let internal_pk = SchnorrPublicKey::from_str("5bf08d58a430f8c222bffaf9127249c5cdff70a2d68b2b45637eb662b6b88eb5").unwrap();

        //The scripts involved.
        let scripts = vec![
            RedeemScript::new(crate::util::decode_02x("029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac")),
            RedeemScript::new(crate::util::decode_02x("a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac"))
        ];

        //Calculate the merkle root of the script tree for testing purposes
        let tree = TreeNode::new_script_tree(&scripts);
        let h = tree.merkle_root();
        let expected_h = "41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b"; 
        assert_eq!(crate::util::encode_02x(&h), expected_h);

        //Tweak the internal key with the script tree
        let tweaked_key = internal_pk.tap_tweak(Some(tree)).unwrap();
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
        let script_tree = TreeNode::new_script_tree(&vec![RedeemScript::new(vec![5, 29, 03])]);

        let tweaked_keypair = key_pair.tap_tweak(Some(script_tree.clone())).unwrap();
        let tweaked_pub_key = pub_key.tap_tweak(Some(script_tree)).unwrap();

        assert_eq!(tweaked_keypair.get_pub(), tweaked_pub_key);
    }
}
