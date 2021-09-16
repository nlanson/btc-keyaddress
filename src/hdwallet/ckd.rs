/*
    This module implements child key deriveration
    from parent extended private and public keys
    under the BIP32 standard.

    Reference:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
*/

use crate::{
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
    Enum to pattern match child key deriveration options.
*/
#[derive(Debug)]
pub enum ChildOptions {
    Normal(u32),
    Hardened(u32)
}

/**
    Enum for handling deriveration errors
*/
pub enum Error {
    IndexTooLarge(String),
    IndexReserved(String)
}

/**
    Function to derive new child xprv keys from parent xprv keys.
    Use the hardened bool to generated hardened child xprv.
*/
pub fn derive_xprv(parent: &Xprv, options: ChildOptions) -> Result<Xprv, Error> {
    //Assign the index and data based on ChildOptions
    let (index, data): (u32, Vec<u8>) = match options {
        ChildOptions::Normal(x) => {
            let index: u32 = x;
            if index >= (2 as u32).pow(31) { //If index is larger than 2^31, then return an error as those indexes are reserved for hardened keys.
                return Err(Error::IndexReserved(
                    format!("Expected index to be less than 2^31. Found {} which is reserved for hardened keys", index)
                )) 
            }
            
            //Normal private key child is [0x00 || parent pub bytes || index bytes]
            let mut data: Vec<u8> = vec![];
            parent.get_pub().as_bytes::<33>().iter().for_each(|x| data.push(*x) );
            index.to_be_bytes().iter().for_each(|x| data.push(*x) );

            (index, data)
        },
        ChildOptions::Hardened(x) => {       
            if x >= (2 as u32).pow(31) { //If provided index is larger than 2^31, then return an error since 2^31 + 2^31 wont fit in a u32 int
                return Err(Error::IndexTooLarge(
                    format!("Expected provided index to be less than 2^31. Found {}", x)
                )) 
            }
            let index: u32 = x + (2 as u32).pow(31);
            

            //Hardened private key child is [parent priv bytes || index bytes]
            let mut data: Vec<u8> = vec![0x00];
            parent.key::<32>().to_vec().iter().for_each(|x| data.push(*x) );
            index.to_be_bytes().iter().for_each(|x| data.push(*x) );

            (index, data)
        }
    };
    
    //Hash the data with the parent chaincode as the key
    let hash: [u8; 64] = hmac_sha512(&data, &parent.chaincode());

    //Split the hash into two halves. The right half is the child chaincode.
    let left_bytes: [u8; 32] = try_into(hash[0..32].to_vec());
    let child_chaincode: [u8; 32] = try_into(hash[32..64].to_vec());

    //Calculate the child private key from the left bytes and parent private key
    let mut child_key: PrivKey = PrivKey::from_slice(&parent.key::<32>()).unwrap();
    child_key.add_assign(&left_bytes).unwrap();

    //Set the remaining meta data
    let depth: u8 = parent.depth + 1;
    let fingerprint: [u8; 4] = try_into(hash160(&parent.get_pub().as_bytes::<33>())[0..4].to_vec());
    let index = index.to_be_bytes();

    //Return the new Xpriv
    Ok(
        Xprv::construct(
            child_key,
            child_chaincode,
            depth,
            fingerprint,
            index
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
}