/*
    This module implements methods relating to Taproot key and address computing.

    Most functions here are translated from the reference python code in BIP-340 and BIP-341.
    The code works but is very spaghetti and needs a rework to be more readable and maintainable.

    Todo:
        - Huffman tree testing
        - Organise information as taproot spending conditions
*/

use crate::{
    hash::{
        tagged_hash
    }, 
    key::{
        SchnorrKeyPair,
        SchnorrPublicKey,
        Key,
        KeyError
    },
    script::RedeemScript
};

#[derive(Debug)]
pub enum TaprootErr {
    BadLeaves,
    InvalidNode
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

taproot_tagged_hashes!(TapTweakHash, "TapTweak");
taproot_tagged_hashes!(TapBranchHash, "TapBranch");
taproot_tagged_hashes!(TapLeafHash, "TapLeaf");



/**
    TreeNode struct to create binary trees
*/
#[derive(Debug, Clone, PartialEq)]
pub struct TreeNode {
    pub left: Option<Box<TreeNode>>,
    pub right: Option<Box<TreeNode>>,

    //This value here could be an enum `TreeNodeInfo` which contains either a (leaf version, script) tuple or hash of children
    //By doing this, each node will contain a value whether it is a leaf or branch and removes the need for an Option
    pub value: Option<LeafInfo>   
}

pub enum TreeNodeValue {
    Hash([u8; 32]),
    Leaf(LeafInfo)
}


/**
    LeafInfo struct that stores the leaf version and script in a script tree leaf.
*/
#[derive(Debug, Clone, PartialEq)]
pub struct LeafInfo {
    version: u8,
    script: RedeemScript
}

impl LeafInfo {
    /**
        Creates a new leaf given a version and script
    */
    pub fn new_with_version(version: u8, script: &RedeemScript) -> Self {
        Self {
            version,
            script: script.clone()
        }
    }

    /**
        Creates a new leaf with default version 
    */
    pub fn new(script: &RedeemScript) -> Self {
        Self::new_with_version(0xc0, script)
    }
}

#[derive(Debug, Clone)]
pub struct HuffmanCoding<T> {
    freq: usize,
    val: T
}

impl HuffmanCoding<RedeemScript> {
    /**
        Create a new item to add to a huffman tree
    */
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
            let node = TreeNode::new(None, None, Some(LeafInfo::new(&x.val))).unwrap();
            
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
            println!("{:?}\n", combined_node);
            table.push((sum, combined_node));
            table.sort_by(|a, b| b.0.cmp(&a.0)); 
        }

        table[0].1.clone()
    }
}


impl TreeNode {
    /**
        Create a new node 
    */
    pub fn new(left: Option<Self>, right: Option<Self>, value: Option<LeafInfo>) -> Result<Self, TaprootErr> {
        //Branch node | Has both branches and no value
        if left.is_some() && right.is_some() && value.is_none() {
            Ok(
                Self {
                    left: Some(Box::new(left.unwrap())),
                    right: Some(Box::new(right.unwrap())),
                    value
                }
            )
        }

        //Leaf node | Has no branches but has a value
        else if left.is_none() && right.is_none() && value.is_some() {
            Ok(
                Self {
                    left: None,
                    right: None,
                    value
                }
            )
        }

        //Invalid node | Other combinations
        else {
            Err(TaprootErr::InvalidNode)
        }
    } 
    
    /**
        Create a new tree from a list of scripts 
    */
    pub fn new_script_tree(scripts: &Vec<RedeemScript>) -> Self {
        //Create leaves from scripts
        let leaves: Vec<TreeNode> = scripts.iter().map(|x| {
            TreeNode::new(None, None, Some(LeafInfo::new(x))).unwrap()
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
}


/**
    Takes in a public key and tweak

    Q = P + H(P|c)G
    
    where
    Q is the tweaked key
    P is the original public key
    H is the hash function
    c is the commitment data
    G is the generator point

    From BIP-341
*/
pub fn taproot_tweak_pubkey(pubkey: &SchnorrPublicKey, h: &[u8]) -> Result<(bool, SchnorrPublicKey), KeyError> {
    //Extend pubkey by commitment
    let mut pc = pubkey.as_bytes::<32>().to_vec();
    pc.extend_from_slice(h);
    

    //Compute tweak which is the HashTapTweak of the committed puvkey
    let tweak = TapTweakHash::from_slice(&pc);
    
    //Compute the tweaked key
    let (parity, tweaked_key) = pubkey.tweak(&tweak)?;
    Ok((parity, tweaked_key))
}

/**
    Tweak a private key with a hash

    T = k + H(x(kG) | c)

    where
    T is the tweaked secret key
    k is the original secret key
    H is the hash function
    G is the generator point
    c is the commitment data
*/
pub fn taproot_tweak_seckey(kp: &SchnorrKeyPair, h: &[u8]) -> Result<SchnorrKeyPair, KeyError> {
    //The tweak is the HashTapTweak of the secret_key multiplied by generator point G concatenated by the commitment data
    let p = kp.get_pub();
    let mut data = p.as_bytes::<32>().to_vec();
    data.extend_from_slice(h);

    let t = TapTweakHash::from_slice(&data);
    kp.tweak(&t)
}

/**
  Script tree traversal method that obtains the merkle root of the script tree.

  BIP-341 method
*/
pub fn taproot_tree_helper(script_tree: &TreeNode) -> (Vec<(LeafInfo, Vec<u8>)>, [u8; 32]) {
    //If the current node is a leaf
    if script_tree.value.is_some() {
        let leaf_info = script_tree.value.clone().unwrap();

        let mut h_data = vec![leaf_info.version];
        h_data.extend_from_slice(&ser_script(&leaf_info.script));
        let h = TapLeafHash::from_slice(&h_data);
        return (vec![(leaf_info, vec![])], h)
    }

    //Recursion
    let (left, mut left_h) = taproot_tree_helper(script_tree.left.as_ref().unwrap());
    let (right, mut right_h) = taproot_tree_helper(script_tree.right.as_ref().unwrap());
    
    //Python reference:
    //ret = [(l, c + right_h) for l, c in left] + [(l, c + left_h) for l, c in right]
    let mut ret: Vec<(LeafInfo, Vec<u8>)> = vec![];
    for (l, c) in left {
        let mut c = c;
        c.extend_from_slice(&right_h);
        ret.push((l, c));
    }
    for (l, c) in right {
        let mut c = c;
        c.extend_from_slice(&left_h);
        ret.push((l, c));
    }
    
    //Swap
    if right_h < left_h {
        let temp = left_h;
        left_h = right_h;
        right_h = temp;
    }
    
    //Concatenate left_h and right_h and hash
    let mut lr = left_h.to_vec();
    lr.extend_from_slice(&right_h);
    return (ret, TapBranchHash::from_slice(&lr))
}

/**
    Given a script, returns the script with a compact-size prefix indicating it's length.
    
    From BIP-341
*/
fn ser_script(script: &RedeemScript) -> Vec<u8> {
    let len = script.code.len();
    let mut compact_size: Vec<u8> = vec![];
    if len <= 252 {
        compact_size = vec![len as u8];
    } else if len <=0xffff {
        compact_size = vec![0xfd];
        let mut len = len.to_le_bytes().to_vec();
        len.truncate(2);
        compact_size.extend_from_slice(&len);
    }
    
    let mut prefixed = compact_size;
    prefixed.extend_from_slice(&script.code);
    prefixed
}

/**
    Given an internal key and an optional script tree,
    this method will return the tweaked key.

    From BIP-341
*/
pub fn taproot_output_script(internal_key: &SchnorrPublicKey, script_tree: Option<TreeNode>) -> Result<SchnorrPublicKey, KeyError> {
    let h: Vec<u8>;
    if script_tree.is_none() {
        h = vec![];
    } else {
        let (_, merkle_root) = taproot_tree_helper(&script_tree.unwrap());
        h = merkle_root.to_vec();
    }

    let (_, output_key) = taproot_tweak_pubkey(internal_key, &h)?;
    Ok(output_key)
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
        let (_, h) = taproot_tree_helper(&tree);
        let expected_h = "41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b";
        assert_eq!(crate::util::encode_02x(&h), expected_h);

        //Tweak the internal key with the script tree
        let tweaked_key = taproot_output_script(&internal_pk, Some(tree)).unwrap();
        let expected_tweaked_key = "f128a8a8a636e19f00a80169550fedfc26b6f5dd04d935ec452894aad938ef0c";
        assert_eq!(tweaked_key.hex(), expected_tweaked_key);
    }

    #[test]
    fn simple_script_tree() {
        let scripts = vec![
            RedeemScript::new(vec![1]),
            RedeemScript::new(vec![2])
        ];

        let tree = TreeNode::new_script_tree(&scripts);
        let expected_tree = TreeNode {
            left: Some(Box::new(TreeNode { left: None, right: None, value: Some(LeafInfo::new(&scripts[0])) })),
            right: Some(Box::new(TreeNode { left: None, right: None, value: Some(LeafInfo::new(&scripts[1])) })),
            value: None
        };
        assert_eq!(tree, expected_tree);
    }

    #[test]
    fn single_tree() {
        let scripts = vec![
            RedeemScript::new(vec![1])
        ];
        
        let tree = TreeNode::new_script_tree(&scripts);
        let expected_tree = TreeNode {
            left: None,
            right: None,
            value: Some(LeafInfo::new(&scripts[0]))
        };
        assert_eq!(tree, expected_tree)
    }

    #[test]
    fn huffman() {
        //Expected result is a tree in this shape: https://imgur.com/a/VIJdsPD
        let scripts = vec![
            (3, RedeemScript::new(vec![1])),
            (4, RedeemScript::new(vec![2])),
            (1, RedeemScript::new(vec![3])),
            (6, RedeemScript::new(vec![1])),
            (1, RedeemScript::new(vec![2])),
            (4, RedeemScript::new(vec![3]))
        ];

        let items: Vec<HuffmanCoding<RedeemScript>> = scripts.iter().map(|x| HuffmanCoding::new_item(x.0, &x.1)).collect();
        let tree = HuffmanCoding::new_script_tree(&items);
        let expected_tree = 
        //19
        TreeNode {
            //11
            left: Some(Box::new(
                TreeNode {
                    //6
                    left: Some(Box::new(
                            TreeNode {
                                left: None,
                                right: None,
                                value: Some(LeafInfo::new(&scripts[3].1))
                            }
                    )),
                    //5
                    right: Some(Box::new(
                            TreeNode {
                                //3
                                left: Some(Box::new(
                                    TreeNode {
                                        left: None,
                                        right: None,
                                        value: Some(LeafInfo::new(&scripts[0].1))
                                    }
                                )),
                                //2
                                right: Some(Box::new(
                                    TreeNode {
                                        //1
                                        left: Some(Box::new(
                                            TreeNode {
                                                left: None,
                                                right: None,
                                                value: Some(LeafInfo::new(&scripts[2].1))
                                            }
                                        )),
                                        //1
                                        right: Some(Box::new(
                                            TreeNode {
                                                left: None,
                                                right: None,
                                                value: Some(LeafInfo::new(&scripts[4].1))
                                            }
                                        )),
                                        value: None
                                    }
                                )),
                                value: None
                            }
                    )),
                    value: None
                }
            )),

            //8
            right: Some(Box::new(
                TreeNode {
                    //4
                    left: Some(Box::new(
                        TreeNode {
                            left: None,
                            right: None,
                            value: Some(LeafInfo::new(&scripts[1].1))
                        }
                    )),
                    //4
                    right: Some(Box::new(
                        TreeNode {
                            left: None,
                            right: None,
                            value: Some(LeafInfo::new(&scripts[5].1))
                        }
                    )),
                    value: None 
                }
            )),
            value: None
        };

        assert_eq!(tree, expected_tree);
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

        let commitment_data = vec![5, 29, 03];
        let tweaked_keypair = taproot_tweak_seckey(&key_pair, &commitment_data).unwrap();
        let tweaked_pub_key = taproot_tweak_pubkey(&pub_key, &commitment_data).unwrap().1;

        assert_eq!(tweaked_keypair.get_pub(), tweaked_pub_key);
    }
}
