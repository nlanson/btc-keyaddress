use std::ops::Add;

use crate::{
    BigInt,
    Sign,
    hash::{ 
        hmac_sha512,
        ripemd160,
        sha256
    },
    hdwallet::{
        ExtendedKey, Xprv, Xpub
    },
    key::{
        Key,
        PubKey,
        PrivKey
    },
    util::try_into
};

/**
    Function to derive new child xprv keys from parent xprv keys.
    Use the hardened bool to generated hardened child xprv.

    *NOT WORKING
*/
pub fn derive_xprv(parent: &Xprv, index: u32,  hardened: bool) -> Xprv {
    //If hardend, use private key as data. Else use public key as data.
    let mut index = index;
    let mut data = parent.get_pub().as_bytes(); //use public key bytes
    if hardened {
        data = parent.key::<32>(); //use private key bytes
        index += 2147483648;       //add 2^31 to index
    }
    
    let index = index.to_be_bytes(); //convert index back into byte array.
    let mut data = data.to_vec();
    index.iter().for_each(|x| data.push(*x));

    //Run data and key through HMAC-SHA512
    //Extract the left bytes and run through arithmatic
    //Leave the right bytes as chain code.
    let hmac = hmac_sha512(&data, &parent.chaincode());
    let left_bytes: [u8; 32] = try_into(hmac[0..32].to_vec());
    let child_chaincode: [u8; 32] = try_into(hmac[32..64].to_vec());
    
    //Running the arithmatic on the left bytes
    let child_key: PrivKey = PrivKey::from_slice(&add_mod(parent.key::<32>(), left_bytes));

    //Return the new extended private key
    Xprv::construct(
        child_key,
        &child_chaincode,
        parent.depth+1,
        try_into(ripemd160(sha256(&parent.get_pub().as_bytes::<33>()))[0..4].to_vec()),
        index
    )
}

/**
    Converts 4 byte integers as a byte array into a single 32bit uint.
*/
fn as_u32_be(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 24) +
    ((array[1] as u32) << 16) +
    ((array[2] as u32) <<  8) +
    ((array[3] as u32) <<  0)
}


fn n() -> BigInt {
    let curve_order: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 0xFF, 
        0xBA, 0xAE, 0xDC, 0xE6,
        0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C,
        0xD0, 0x36, 0x41, 0x41
    ];
    
    BigInt::from_bytes_be(Sign::Plus, &curve_order)
}

fn add_mod(n1: [u8; 32], n2: [u8; 32]) ->  [u8; 32] {
    //Add k1 and k2
    let k1: BigInt = BigInt::from_bytes_be(Sign::Plus, &n1);
    let k2: BigInt = BigInt::from_bytes_be(Sign::Plus, &n2);
    let sum: BigInt = k1.add(k2);

    //Mod sum by n
    let n: BigInt = n();
    let res: BigInt = sum.modpow(&BigInt::from(1), &n);

    try_into(res.to_bytes_be().1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BigInt, Sign
    };
}