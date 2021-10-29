/*
    This module implements methods relating to Taproot key and address computing.

    Most functions here are translated from the reference python code in BIP-340 and BIP-341.
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

//Node struct for constructing script trees
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub left: Option<Box<Node>>,
    pub right: Option<Box<Node>>,
    pub value: Option<(u8, RedeemScript)>
}

impl Node {
    /**
        Create a new tree from a list of scripts 
    */
    pub fn new_tree(scripts: &Vec<RedeemScript>) -> Self {
        //Create leaves from scripts
        let mut leaves: Vec<Node> = scripts.iter().map(|x| {
            Node { 
                left: None,
                right: None,
                value: Some((0xc0, x.clone()))
            }
        }).collect::<Vec<Node>>();
        
        //If the number of leaves is not a power of two, keep adding empty leaves until it is.
        loop {
            if Self::is_power_of_two( leaves.len() ){ break ;}
            leaves.push(Node::empty())
        }

        Self::leaves_to_tree(leaves).unwrap()
    }

    //Return an empty node
    pub fn empty() -> Self {
        Node { left: None, right: None, value: None }
    }

    /**
        Creates a tree given a vector of leaves.
    
        The way this method constructs the tree is not efficient as the amount of leaves needs to 
        be a power of two.
        This can be fixed by implementing an algorithm that efficiently creates parent branches and if there is
        a left over leaf, carry the leaf over into the parent branches vec and repeat.


    */
    fn leaves_to_tree(leaves: Vec<Node>) -> Result<Self, TaprootErr> {
        //If there is only one leaf left, it is the root.
        if leaves.len() == 1 {
            return Ok(leaves[0].clone())
        }

        //If the number of leaves is not a power of two, return error
        if !Self::is_power_of_two(leaves.len()) { return Err(TaprootErr::BadLeaves) }

        //Create parents from the children remainig and then call this function again using the parents
        let mut parent_branches: Vec<Node> = vec![];
        for i in (0..leaves.len()).step_by(2) {
            parent_branches.push(
                Node {
                    left: Some(Box::new(leaves[i].clone())),
                    right: Some(Box::new(leaves[i+1].clone())),
                    value: None
                }
            )
        }
        
        /*
            After looping, if there is a leaf left over, carry it over into the parent branches vector
        */


        Self::leaves_to_tree(parent_branches)
    }

    fn is_power_of_two(x: usize) -> bool {
        (x != 0) && ((x & (x - 1)) == 0)
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
            left: Some(Box::new(Node { left: None, right: None, value: Some((0xc0 as u8, scripts[0].clone())) })),
            right: Some(Box::new(Node { left: None, right: None, value: Some((0xc0 as u8, scripts[1].clone())) })),
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
            RedeemScript::new(vec![5]),
            RedeemScript::new(vec![6])
        ];

        let tree = Node::new_tree(&scripts); //Tree created should be 3 levels deep and 2 of the leaves will have no value as only 6 scripts are provided.
        let expected_tree = 
        Node {
            left: Some(Box::new(
                Node {
                    left: Some(Box::new(
                        Node {
                            left: Some(Box::new(
                                Node {
                                    left: None,
                                    right: None,
                                    value: Some((0xc0, scripts[0].clone()))
                                }
                            )),
                            right: Some(Box::new(
                                Node {
                                    left: None,
                                    right: None,
                                    value: Some((0xc0, scripts[1].clone()))
                                }
                            )),
                            value: None
                        }
                    )),
                    right: Some(Box::new(
                        Node {
                            left: Some(Box::new(
                                Node {
                                    left: None,
                                    right: None,
                                    value: Some((0xc0, scripts[2].clone()))
                                }
                            )),
                            right: Some(Box::new(
                                Node {
                                    left: None,
                                    right: None,
                                    value: Some((0xc0, scripts[3].clone()))
                                }
                            )),
                            value: None
                        }
                    )),
                    value: None
                }
            )),
            right: Some(Box::new(
                Node {
                    left: Some(Box::new(
                        Node {
                            left: Some(Box::new(
                                Node {
                                    left: None,
                                    right: None,
                                    value: Some((0xc0, scripts[4].clone()))
                                }
                            )),
                            right: Some(Box::new(
                                Node {
                                    left: None,
                                    right: None,
                                    value: Some((0xc0, scripts[5].clone()))
                                }
                            )),
                            value: None
                        }
                    )),
                    right: Some(Box::new(
                        Node {
                            left: Some(Box::new(
                                Node {
                                    left: None,
                                    right: None,
                                    value: None
                                }
                            )),
                            right: Some(Box::new(
                                Node {
                                    left: None,
                                    right: None,
                                    value: None
                                }
                            )),
                            value: None
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
