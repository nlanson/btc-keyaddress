/*
    This module implements methods relating to Taproot key and address computing.

    Most functions here are translated from the reference python code in BIP-340 and BIP-341.

    Todo:
        - Carry over tree complex multilevel tree test
        - Huffman tree creation
        - BIP-341 tweak value computing method
        - Once tweak value is calculated and internal key is tweaked, find and implement test cases
*/

use crate::{
    hash::{
        tagged_hash
    }, 
    key::{
        SchnorrPublicKey,
        Key,
        KeyError
    },
    script::RedeemScript
};

#[derive(Debug)]
pub enum TaprootErr {
    BadLeaves
}

/**
    Node struct to create binary trees
*/
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub left: Option<Box<Node>>,
    pub right: Option<Box<Node>>,

    //This value here could be an enum `NodeInfo` which contains either a (leaf version, script) tuple or hash of children
    //By doing this, each node will contain a value whether it is a leaf or branch and removes the need for an Option
    pub value: Option<LeafInfo>   
}

pub enum NodeValue {
    Hash([u8; 32]),
    Leaf(LeafInfo)
}


/**
    LeafInfo struct that stores the leaf version and script in a script tree leaf.
*/
#[derive(Debug, Clone, PartialEq)]
pub struct LeafInfo(u8, RedeemScript);
impl LeafInfo {
    /**
        Creates a new leaf given a version and script
    */
    pub fn new_leaf_with_version(version: u8, script: &RedeemScript) -> Self {
        Self(version, script.clone())
    }

    /**
        Creates a new leaf with default version 
    */
    pub fn new_leaf(script: &RedeemScript) -> Self {
        Self::new_leaf_with_version(0xc0, script)
    }
}


impl Node {
    /**
        Create a new tree from a list of scripts 
    */
    pub fn new_tree(scripts: &Vec<RedeemScript>) -> Self {
        //Create leaves from scripts
        let leaves: Vec<Node> = scripts.iter().map(|x| {
            Node { 
                left: None,
                right: None,
                value: Some(LeafInfo::new_leaf(x))
            }
        }).collect::<Vec<Node>>();

        Self::carry_over_tree(leaves)
    }

    /**
        Tries to create the most balanced tree from any amount of leaves.
        Does this by combining left over leaves with the last parent.
    */
    fn carry_over_tree(leaves: Vec<Node>) -> Self {
        //If there is only one leaf left, return it
        if leaves.len() == 1 { return leaves[0].clone() }

        //Create new parent nodes by grouping two leaves together
        let mut parent_level: Vec<Node> = vec![];
        for i in (0..leaves.len()).step_by(2) { //bug: loop fucks up with odd numbers
            //If there is a left over node, push a parent combining the left over node and the last parent created.
            if i+1 == leaves.len() { 
                let last_parent = parent_level[parent_level.len() - 1].clone();
                let left_over_child = leaves[leaves.len() - 1].clone();
    
                parent_level.remove(parent_level.len() - 1);
                parent_level.push(Self::carry_over_tree(vec![last_parent, left_over_child]));    
                
                break;
            }
            
            //Push a parent node combining two child nodes
            parent_level.push(
                Node {
                    left: Some(Box::new(leaves[i].clone())),
                    right: Some(Box::new(leaves[i+1].clone())),
                    value: None
                }
            )
        }

        //If there is a leaf left over, use the left over leaf and the last parent to create a new node
        //with the left over child and last parent, replacing the last parent with this new node.
        // if leaves.len()%2 != 0 {
        //     let last_parent = parent_level[parent_level.len() - 1].clone();
        //     let left_over_child = leaves[leaves.len() - 1].clone();

        //     parent_level.remove(parent_level.len() - 1);
        //     parent_level.push(Self::carry_over_tree(vec![last_parent, left_over_child]));
        // }

        //Call self again using parent level
        Self::carry_over_tree(parent_level)
    }

    /**
        Creates a huffman tree given a vector of nodes and their weights
    */
    fn huffman_tree(leaves: Vec<(u32, Node)>) -> Self {
        todo!();
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
*/
pub fn taproot_tweak_pubkey(pubkey: SchnorrPublicKey, h: &[u8]) -> Result<SchnorrPublicKey, KeyError> {
    //Extend pubkey by commitment
    let mut pc = pubkey.as_bytes::<32>().to_vec();
    pc.extend_from_slice(h);
    

    //Compute tweak which is the HashTapTweak of the committed puvkey
    let tweak = tagged_hash("TapTweak", &pc);
    
    //Compute the tweaked key
    let tweaked_key = pubkey.tweak(&tweak)?;
    Ok(tweaked_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_script_tree() {
        let scripts = vec![
            RedeemScript::new(vec![1]),
            RedeemScript::new(vec![2])
        ];

        let tree = Node::new_tree(&scripts);
        let expected_tree = Node {
            left: Some(Box::new(Node { left: None, right: None, value: Some(LeafInfo::new_leaf(&scripts[0])) })),
            right: Some(Box::new(Node { left: None, right: None, value: Some(LeafInfo::new_leaf(&scripts[1])) })),
            value: None
        };
        assert_eq!(tree, expected_tree);
    }

    #[test]
    fn single_leaf_tree() {
        let scripts = vec![
            RedeemScript::new(vec![1])
        ];
        
        let tree = Node::new_tree(&scripts);
        let expected_tree = Node {
            left: None,
            right: None,
            value: Some(LeafInfo::new_leaf(&scripts[0]))
        };
        assert_eq!(tree, expected_tree)
    }

    #[test]
    fn odd_count_script_tree() {
        let scripts = vec![
            RedeemScript::new(vec![1]),
            RedeemScript::new(vec![2]),
            RedeemScript::new(vec![3])
        ];

        let tree = Node::new_tree(&scripts);
        let expected_tree = 
        Node {
            left: 
                Some(Box::new(Node{
                    left:  Some(Box::new(Node {left: None, right: None, value: Some(LeafInfo::new_leaf(&scripts[0]))})),
                    right: Some(Box::new(Node {left: None, right: None, value: Some(LeafInfo::new_leaf(&scripts[1]))})),
                    value: None
                })),
            right: 
                Some(Box::new(Node {
                    left: None,
                    right: None,
                    value: Some(LeafInfo::new_leaf(&scripts[2]))
                })),
            value: None
        };

        assert_eq!(tree, expected_tree);
    }

    #[test]
    fn complex_script_tree() {

    }
}
