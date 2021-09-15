use std::ops::Add;

use rand::AsByteSliceMut;

use crate::{
    BigInt,
    Sign,
    hash::{ 
        hmac_sha512,
        hash160
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

    *NOT WORKING FOR HARDENED CHILDREN 
    *INCONSISTENT WITH NORMAL CHILDREN

    This is most likely because the modulo is not being applied correctly.
*/
pub fn derive_xprv(parent: &Xprv, index: u32,  harden: bool) -> Xprv {
    if index >= (2 as u32).pow(31)-1 { panic!("Index must be less than 2147483648 at depth {}", parent.depth) }
    
    let I: [u8; 64];
    if harden {
        let index = index + (2 as u32).pow(31);
        
        let mut data: Vec<u8> = vec![];
        data.push(0x00);
        parent.key::<32>().to_vec().iter().for_each(|x| data.push(*x) );
        index.to_be_bytes().iter().for_each(|x| data.push(*x) );

        let key: [u8; 32] = parent.chaincode();

        I = hmac_sha512(&data, &key);
    } else {
        let mut data: Vec<u8> = vec![];
        parent.get_pub().as_bytes::<33>().iter().for_each(|x| data.push(*x) );
        index.to_be_bytes().iter().for_each(|x| data.push(*x) );

        let key: [u8; 32] = parent.chaincode();

        I = hmac_sha512(&data, &key)
    }

    let IL: [u8; 32] = try_into(I[0..32].to_vec());
    let IR: [u8; 32] = try_into(I[32..64].to_vec());

    let child_key = scalar_add_mod(IL, parent.key());
    let child_chaincode = IR;
    let depth = parent.depth + 1;
    let pf: [u8; 4] = try_into(hash160(&parent.get_pub().as_bytes::<33>())[0..4].to_vec());

    Xprv::construct(PrivKey::from_slice(&child_key), child_chaincode, depth, pf, index.to_be_bytes())

    // let mut index = index;
    // let mut data: Vec<u8>;
    // if harden { index += (2 as u32).pow(31) }
    
    // //If index is above 2^31, produce a hardened child.
    // if index >= (2 as u32).pow(31) { 
    //     //use the private key as data is hardened
    //     data = vec![0x00]; //prepend 0x00 to make it 33bytes in total
    //     parent.key::<32>().to_vec().iter().for_each(|x| data.push(*x) );
    // } else {
    //     //use the public key as data if not hardened
    //     data = parent.get_pub().as_bytes::<33>().to_vec(); 
    // }

    // //convert and append index's bytes to data
    // let index = index.to_be_bytes();
    // index.iter().for_each(|x| data.push(*x));

    // //run data and key through HMAC-SHA512
    // //extract the left bytes and run through arithmatic
    // //leave the right bytes as chain code.
    // let hmac = hmac_sha512(&data, &parent.chaincode());
    // let left_bytes: [u8; 32] = try_into(hmac[0..32].to_vec());
    // let child_chaincode: [u8; 32] = try_into(hmac[32..64].to_vec());
    
    // //run addition arithmatic on the left bytes.
    // //add the left_bytes to the parent private key. the result is the child private key
    // let child_key: PrivKey = PrivKey::from_slice(&scalar_add_mod(parent.key::<32>(), left_bytes));
    
    // let depth = parent.depth + 1; //Increment the depth
    // let pf: [u8; 4] = try_into(hash160(&parent.get_pub().as_bytes::<33>())[0..4].to_vec());

    // //Return the new extended private key
    // Xprv::construct(
    //     child_key,
    //     child_chaincode,
    //     depth, 
    //     pf,
    //     index
    // )
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


/**
    Return the order of the SECPP256K curve as a BigInt
*/
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

/**
    Add the two 32 byte array inputs and return modulus
    the sum by the order of secp256k1 and return the value.

    Used to derive child private keys.
*/
fn scalar_add_mod(n1: [u8; 32], n2: [u8; 32]) ->  [u8; 32] {
    //Add k1 and k2
    let k1: BigInt = BigInt::from_bytes_be(Sign::Plus, &n1);
    let k2: BigInt = BigInt::from_bytes_be(Sign::Plus, &n2);
    let sum: BigInt = k1.add(k2);
    //When sum is 33 bytes, the derived key is wrong. Meaning, the modulo below is not working.

    //Mod sum by n to prevent infinity
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