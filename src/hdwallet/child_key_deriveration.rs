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
    Function to derive new child xprv keys from parent xprv keys.
    Use the hardened bool to generated hardened child xprv.
*/
pub fn derive_xprv(parent: &Xprv, index: u32,  harden: bool) -> Xprv {
    if index >= (2 as u32).pow(31)-1 { panic!("Index must be less than 2147483648 at depth {}", parent.depth) }
    
    let I: [u8; 64];
    let mut index = index;
    if harden {
        index = index + (2 as u32).pow(31);
        
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

    let mut child_key: PrivKey = PrivKey::from_slice(&parent.key::<32>()); //scalar_add_mod(IL, parent.key());
    child_key.add_assign(&IL);
    let child_chaincode = IR;
    let depth = parent.depth + 1;
    let pf: [u8; 4] = try_into(hash160(&parent.get_pub().as_bytes::<33>())[0..4].to_vec());

    Xprv::construct(child_key, child_chaincode, depth, pf, index.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
}