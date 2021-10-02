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
        ExtendedKey, Xprv, Xpub,
        HDWError
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
#[derive(Debug, Clone)]
pub enum ChildOptions {
    Normal(u32),
    Hardened(u32)
}

/**
    Function to derive new child xprv keys from parent xprv keys.
    Use the hardened bool to generated hardened child xprv.

    Xprv -> Xprv
*/
pub fn derive_xprv(parent: &Xprv, options: ChildOptions) -> Result<Xprv, HDWError> {
    //Assign the index and data based on ChildOptions
    let (index, data): (u32, Vec<u8>) = match options {
        ChildOptions::Normal(x) => {
            let index: u32 = x;
            if index >= (2 as u32).pow(31) { //If index is larger than 2^31, then return an error as those indexes are reserved for hardened keys.
                return Err(HDWError::IndexReserved(index)) 
            }
            
            //Normal private key child is [0x00 || parent pub bytes || index bytes]
            let mut data: Vec<u8> = vec![];
            parent.get_pub().as_bytes::<33>().iter().for_each(|x| data.push(*x) );
            index.to_be_bytes().iter().for_each(|x| data.push(*x) );

            (index, data)
        },
        ChildOptions::Hardened(x) => {       
            if x >= (2 as u32).pow(31) { //If provided index is larger than 2^31, then return an error since 2^31 + 2^31 wont fit in a u32 int
                return Err(HDWError::IndexTooLarge(x)) 
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

    //Calculate the child private key from the left bytes and parent private key. 
    //Return an error if this cannot be done
    let mut child_key: PrivKey = match PrivKey::from_slice(&parent.key::<32>()) {
        Ok(x) => x,
        Err(_) => return Err(HDWError::BadKey())
    };
    match child_key.add_assign(&left_bytes) {
        Ok(_) => { },
        Err(_) => return Err(HDWError::BadArithmatic())
    }

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

/** 
    Function to derive new chilc xpub keys from parnent xpub keys.

    Xpub -> Xpub
*/
pub fn derive_xpub(parent: &Xpub, options: ChildOptions) -> Result<Xpub, HDWError> {
    //Extract the index from the options.
    //if the options specify hardened, then return an error
    let index: u32 = match options {
        ChildOptions::Hardened(_) => return Err(HDWError::CantHarden()),
        ChildOptions::Normal(x) => {
            if x >= (2 as u32).pow(31) {
                return Err(HDWError::IndexTooLarge(x));
            }
            x
        }
    };

    //Create the data Vec from the parent public key and index
    let mut data: Vec<u8> = vec![];
    parent.key::<33>().iter().for_each(|x| data.push(*x));
    index.to_be_bytes().iter().for_each(|x| data.push(*x));

    //hash the data with the parent chaincode as the key
    let hash: [u8; 64] = hmac_sha512(&data, &parent.chaincode());

    //split the hash into two halves. The right half is the child chaincode.
    let left_bytes: [u8; 32] = try_into(hash[0..32].to_vec());
    let child_chaincode: [u8; 32] = try_into(hash[32..64].to_vec());

    //Add the parent public key to the left bytes to get the final child key
    //Return appropriate error if unable to do so
    let mut child_key: PubKey =  PubKey::from_slice(&parent.key::<33>()).unwrap();
    let sk: PrivKey = match PrivKey::from_slice(&left_bytes) {
        Ok(x) => x,
        Err(_) => return Err(HDWError::BadKey())
    };
    match child_key.add_assign(&sk.as_bytes::<32>()[..]) {
        Ok(_) => { },
        Err(_) => return Err(HDWError::BadArithmatic())
    }


    //Set the remaining meta data
    let depth = parent.depth + 1;
    let fingerprint: [u8; 4] = try_into(hash160(&parent.key::<33>())[0..4].to_vec());
    let index = index.to_be_bytes();

    Ok(
        Xpub::construct(
            child_key,
            child_chaincode,
            depth,
            fingerprint,
            index
        )
    )
}

#[allow(non_snake_case, non_upper_case_globals)]
#[cfg(test)]
mod tests {
    use crate::{
        hdwallet::{
            HDWallet,
            HDWError,
        },
        bip39::{
            Mnemonic,
            MnemonicErr,
            Language
        }
    };
    use super::*;

    const TEST_MNEMONIC: &str = "glow laugh acquire menu anchor evil occur put hover renew calm purpose";

    const EXPECTED_m0: &str = "xprv9veD4fr6rg67aWannnQipC3ZkKj9CP2xaQf8yQkRGyp9N32PVzwvMs2nYoDzVyYdviChaXVzokWJnQLixWgZZNDaKRvRMMVJVJU85GZ5uTW";
    const EXPECTED_M0: &str = "xpub69dZUBNzh3eQnzfFtowjBKzJJMZdbqkowdajmoA2qKM8EqMY3YGAufMGQ6MD3Mr3mrsCp8ihwGekfogUyRK3kHaj4Qk7WUPa8NUCGB8BK6D";
    const EXPECTED_m0h: &str = "xprv9veD4frFCLd5k5JeTE37vHNabs5r4CrNy6wyW1WKj8ZsnkpLY9SwaAitRyrDZp9vZqiNEL5pbntcdnk7Zxea5WeKP3aQBdQNfern39bV93Q";
    const EXPECTED_M0h: &str = "xpub69dZUBP92iBNxZP7ZFa8HRKK9tvLTfaELKsaJPuwHU6rfZ9V5gmC7y3NHF6M2ggSKAEZit9dEKo4fhEp2hsJW3Nk5Hd9JrrJRgeEkGryygR";

    const EXPECTED_m0_0_address: &str = "1E8UW1NDvpG7xTBxRTa9FXwvrXNq95dQyp";
    const EXPECTED_m0_1_address: &str = "1Pg7rysbg9D2D94rxfkPiK4XdPM6qzMv42";

    fn create_hdw_from_test_mnemonic() -> HDWallet {
        let mnemonic: Mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC.to_string(), Language::English, "").unwrap();
        HDWallet::new(mnemonic).unwrap()
    }

    #[test]
    fn ckd_normal() {
        let hdw: HDWallet = create_hdw_from_test_mnemonic();

        //Get the first child extended private and public key of the master key.
        //Calculate the child extended public key twice  through the master xpub and child xprv
        let derived_m0 = hdw.mpriv_key().get_xchild(ChildOptions::Normal(0)).unwrap().serialize_legacy();
        let derived_M0_fromxprv = hdw.mpriv_key().get_xchild(ChildOptions::Normal(0)).unwrap().get_xpub().serialize_legacy();
        let derived_M0_fromxpub = hdw.mpub_key().get_xchild(ChildOptions::Normal(0)).unwrap().serialize_legacy();

        //Test is derived values are equal to expected values and if derived xpubs are both identical
        assert_eq!(derived_m0, EXPECTED_m0.to_string());
        assert_eq!(derived_M0_fromxprv, derived_M0_fromxpub);
        assert_eq!(derived_M0_fromxprv, EXPECTED_M0.to_string());
        assert_eq!(derived_M0_fromxpub, EXPECTED_M0.to_string());
    }

    #[test]
    fn ckd_hardened() {
        let hdw: HDWallet = create_hdw_from_test_mnemonic();

        //Calculate the hardened children of the master keys.
        //Deriving the corresponding xpub of a hardened xprv is not possible. So pattern match the error.
        let derived_m0h = hdw.mpriv_key().get_xchild(ChildOptions::Hardened(0)).unwrap().serialize_legacy();
        let derived_M0h_fromxpub = match hdw.mpub_key().get_xchild(ChildOptions::Hardened(0)) {
            Ok(_) => true,
            Err(_) => false
        }; 
        let derived_M0h_fromxprv = hdw.mpriv_key().get_xchild(ChildOptions::Hardened(0)).unwrap().get_xpub().serialize_legacy();

        //Test is derived values are equal to expected values and if hardened xpub deriveration failed
        assert_eq!(derived_m0h, EXPECTED_m0h);
        assert_eq!(derived_M0h_fromxpub, false);
        assert_eq!(derived_M0h_fromxprv, EXPECTED_M0h);
    }
    
    #[test]
    fn ckd_address_test() {
        let hdw: HDWallet = create_hdw_from_test_mnemonic();

        //Get the addresses at m/0/0 and m/0/1 using both the public and private keys
        let m0_0_address_from_xprv: String = hdw.mpriv_key()
                                                .get_xchild(ChildOptions::Normal(0)).unwrap()
                                                .get_xchild(ChildOptions::Normal(0)).unwrap()
                                                .get_address();
        let m0_0_address_from_xpub: String = hdw.mpub_key()
                                                .get_xchild(ChildOptions::Normal(0)).unwrap()
                                                .get_xchild(ChildOptions::Normal(0)).unwrap()
                                                .get_address();
        let m0_1_address_from_xprv: String = hdw.mpriv_key()
                                                .get_xchild(ChildOptions::Normal(0)).unwrap()
                                                .get_xchild(ChildOptions::Normal(1)).unwrap()
                                                .get_address();
        let m0_1_address_from_xpub: String = hdw.mpub_key()
                                                .get_xchild(ChildOptions::Normal(0)).unwrap()
                                                .get_xchild(ChildOptions::Normal(1)).unwrap()
                                                .get_address();

        //Compare the derived addresses to the expected address as 
        //well as checking addresses derived from private keys and 
        //the same as addresses derived from public keys
        assert_eq!(m0_0_address_from_xprv, m0_0_address_from_xpub);
        assert_eq!(m0_0_address_from_xprv, EXPECTED_m0_0_address);
        assert_eq!(m0_1_address_from_xprv, m0_1_address_from_xpub);
        assert_eq!(m0_1_address_from_xprv, EXPECTED_m0_1_address);
    }
}