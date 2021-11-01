/*
    This module implements methods relating to Taproot key and address computing.

    Most functions here are translated from the reference python code in BIP-340 and BIP-341.

    Todo:
        - Huffman tree testing
        - BIP-341 tweak value computing method (taproot_tree_helper)
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
    BadLeaves,
    InvalidNode
}

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
struct HuffmanCoding<T> {
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

//Unfinished
pub fn taproot_tree_helper(script_tree: &TreeNode) -> (Vec<(LeafInfo, Vec<u8>)>, [u8; 32]) {
    //If the current node is a leaf
    if script_tree.value.is_some() {
        let leaf_info = script_tree.value.clone().unwrap();

        let mut h_data = vec![leaf_info.version];
        h_data.extend_from_slice(&ser_script(&leaf_info.script));
        let h = tagged_hash("TapLeaf", &h_data);
        return (vec![(leaf_info, vec![])], h)
    }
    let (left, left_h) = taproot_tree_helper(script_tree.left.as_ref().unwrap());
    let (right, right_h) = taproot_tree_helper(script_tree.right.as_ref().unwrap());
    let ret = 
    //Remaining Python code:
    //ret = [(l, c + right_h) for l, c in left] + [(l, c + left_h) for l, c in right]
    // if right_h < left_h:
    //     left_h, right_h = right_h, left_h
    // return (ret, tagged_hash("TapBranch", left_h + right_h))

    todo!();
}

/**
    Given a script, returns the script with a compact-size prefix indicating it's length.

    Currently only prefixes with the script length casted as u8 and NOT compact size.
    Need to write compact size int method.
*/
fn ser_script(script: &RedeemScript) -> Vec<u8> {
    let mut prefixed = script.code.clone();
    prefixed.insert(0, prefixed.len() as u8); //THIS NEEDS TO BE COMPACT-SIZE INSTEAD OF A REGULAR u8.

    prefixed
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
    fn odd_count_script_tree() {
        let scripts = vec![
            RedeemScript::new(vec![1]),
            RedeemScript::new(vec![2]),
            RedeemScript::new(vec![3])
        ];

        let tree = TreeNode::new_script_tree(&scripts);
        let expected_tree = 
        TreeNode {
            left: 
                Some(Box::new(TreeNode{
                    left:  Some(Box::new(TreeNode {left: None, right: None, value: Some(LeafInfo::new(&scripts[0]))})),
                    right: Some(Box::new(TreeNode {left: None, right: None, value: Some(LeafInfo::new(&scripts[1]))})),
                    value: None
                })),
            right: 
                Some(Box::new(TreeNode {
                    left: None,
                    right: None,
                    value: Some(LeafInfo::new(&scripts[2]))
                })),
            value: None
        };

        assert_eq!(tree, expected_tree);
    }

    #[test]
    fn complex_script_tree() {
        let scripts = vec![
            RedeemScript::new(vec![1]),
            RedeemScript::new(vec![2]),
            RedeemScript::new(vec![3]),
            RedeemScript::new(vec![4]),
            RedeemScript::new(vec![5])
        ];

        let tree = TreeNode::new_script_tree(&scripts);
        let expected_tree = 
        TreeNode {
            left: Some(Box::new(
                TreeNode { 
                    left: Some(Box::new(
                        TreeNode {
                            left: None,
                            right: None,
                            value: Some(LeafInfo::new(&scripts[0]))
                        }
                    )),
                    right: Some(Box::new(
                        TreeNode {
                            left: None,
                            right: None,
                            value: Some(LeafInfo::new(&scripts[1]))
                        }
                    )),
                    value: None
                }
            )),
            right: Some(Box::new(
                TreeNode { 
                    left: Some(Box::new(
                        TreeNode {
                            left: Some(Box::new(
                                TreeNode { left: None, right: None, value: Some(LeafInfo::new(&scripts[2])) }
                            )),
                            right: Some(Box::new(
                                TreeNode { left: None, right: None, value: Some(LeafInfo::new(&scripts[3])) }
                            )),
                            value: None
                        }
                    )),
                    right: Some(Box::new(
                        TreeNode { 
                            left: None, 
                            right: None, 
                            value: Some(LeafInfo::new(&scripts[4])) 
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
}
