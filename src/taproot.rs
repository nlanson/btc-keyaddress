/*
    This module implements methods relating to Taproot key and address computing.

    Most functions here are translated from the reference python code in BIP-340 and BIP-341.
*/

use crate::{
    hash::{
        tagged_hash
    }, key::{
        SchnorrPublicKey,
        Key,
        KeyError
    }
};


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