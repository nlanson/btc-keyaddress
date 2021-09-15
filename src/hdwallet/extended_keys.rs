/*
    This module implements extended keys that are
    used in BIP32 hierarchal deterministic wallets.

    Extended keys are 64 bytes in length. The first 32 bytes
    are the keys and the last 32 bytes is the chaincode.
*/

use std::any::TypeId;
use crate::{
    key::{
        PrivKey,
        PubKey,
        Key
    },
    bs58check::{
        check_encode,
        VersionPrefix
    },
    hdwallet::derive_children,
    util::try_into
};

#[derive(Clone)]
pub struct Xprv {
    key: PrivKey,
    chaincode: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: [u8; 4]
}

#[derive(Clone)]
pub struct Xpub {
    key: PubKey,
    chaincode: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: [u8; 4]
}

pub trait ExtendedKey {
    /**
        Constructs the Extended Key.
    */
    fn construct<T: 'static>(key: T, chaincode: &[u8], depth: u8, pf: [u8; 4], index: [u8; 4]) -> Self
    where T: Key;

    /**
        Returns the key part (left 32 bytes) of the extended key
    */
    fn key<const N: usize>(&self) -> [u8; N];

    /**
        Returns the chaincode (right 32 bytes) of the extended key
    */
    fn chaincode(&self) -> [u8; 32];

    /**
        Base58 check encode the extended key with serialisation info.
    */
    fn serialize(&self) -> String;
}

impl ExtendedKey for Xprv {
    fn construct<T: 'static>(key: T, chaincode: &[u8], depth: u8, pf: [u8; 4], index: [u8; 4]) -> Self 
    where T: Key
    {
        if TypeId::of::<T>() == TypeId::of::<PrivKey>() {
            return Self {
                key: PrivKey::from_slice(&key.as_bytes::<32>()),
                chaincode: try_into(chaincode.to_vec()),
                //Serialisation info
                depth: depth,
                parent_fingerprint: pf,
                child_number: index
            }
        } else { panic!("Tried to create extended private key without using PrivKey") }
    }

    /**
        32 bytes (No indicator)
    */
    fn key<const N:usize>(&self) -> [u8; N] {
        self.key.as_bytes()
    }

    fn chaincode(&self) -> [u8; 32] {
        self.chaincode
    }

    fn serialize(&self) -> String {
        let mut payload: Vec<u8> = vec![];
        payload.push(self.depth);
        self.parent_fingerprint.iter().for_each(|x| payload.push(*x));
        self.child_number.iter().for_each(|x| payload.push(*x));
        self.chaincode().iter().for_each(|x| payload.push(*x));
        payload.push(0x00);
        self.key::<32>().iter().for_each(|x| payload.push(*x));
        
        check_encode(VersionPrefix::Xprv,&payload)
    }
    
}

impl Xprv {
    /**
        Return the public key of the private key in the Xprv.
    */
    pub fn get_pub(&self) -> PubKey {
        PubKey::from_priv_key(&PrivKey::from_slice(&self.key::<32>()))
    }

    /**
        Gets the child key of Self
    */
    pub fn get_child(&self, index: u32, harden: bool) -> Xprv {
        derive_children::derive_xprv(self, 0, false)
    }
}

impl ExtendedKey for Xpub {
    fn construct<T: 'static>(key: T, chaincode: &[u8], depth: u8, pf: [u8; 4], index: [u8; 4]) -> Self 
    where T: Key
    {
        if TypeId::of::<T>() == TypeId::of::<PubKey>() {
            return Self {
                key: PubKey::from_slice(&key.as_bytes::<33>()),
                chaincode: try_into(chaincode.to_vec()),
                //Serialisation info
                depth: depth,
                parent_fingerprint: pf,
                child_number: index
            }
        } else { panic!("Tried to create extended public key without using PubKey") }
    }

    /**
        33 bytes
    */
    fn key<const N:usize>(&self) -> [u8; N] {
        self.key.as_bytes()
    }

    fn chaincode(&self) -> [u8; 32] {
        self.chaincode
    }

    fn serialize(&self) -> String {
        let mut payload: Vec<u8> = vec![];
        payload.push(self.depth);
        self.parent_fingerprint.iter().for_each(|x| payload.push(*x));
        self.child_number.iter().for_each(|x| payload.push(*x));
        self.chaincode().iter().for_each(|x| payload.push(*x));
        self.key::<33>().iter().for_each(|x| payload.push(*x));
        
        check_encode(VersionPrefix::Xpub,&payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bip39::{lang::Language, mnemonic::Mnemonic, mnemonic::PhraseLength}, hdwallet::HDWallet, util::{
            decode_02x
        }};

    const TEST_MNEMONIC: &str = "glow laugh acquire menu anchor evil occur put hover renew calm purpose";
    const TEST_MPRIV: &str = "081549973bafbba825b31bcc402a3c4ed8e3185c2f3a31c75e55f423e9629aa3";
    const TEST_MCC: &str = "1d7d2a4c940be028b945302ad79dd2ce2afe5ed55e1a2937a5af57f8401e73dd";

    #[test]
    fn extended_keys_test() {
        let mnemonic: Mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC.to_string(), Language::English, "").unwrap();
        let hdw: HDWallet = HDWallet::new(mnemonic);

        //Test if the calculated and expected key and chaincode are equal
        assert_eq!(decode_02x(TEST_MPRIV), hdw.mpriv_key.key::<32>());
        assert_eq!(decode_02x(TEST_MCC), hdw.mpriv_key.chaincode());
    }

    #[test]
    fn random_extended_keys_test() {
        for _i in 0..5 {
            let mnemonic: Mnemonic = Mnemonic::new(PhraseLength::TwentyFour, Language::English, "").unwrap();
            let hdw: HDWallet = HDWallet::new(mnemonic);

            //Check lengths of mpriv, mpub and cc as well as compression prefix
            // of mpub.key to check if it is 0x02 or 0x03
            assert_eq!(hdw.mpriv_key.key::<32>().len(), 32);
            assert_eq!(hdw.mpriv_key.chaincode().len(), 32);
            assert_eq!(hdw.mpub_key().key::<33>().len(), 33);
            assert!(
                match hdw.mpub_key().key::<33>()[0] {
                    0x02 | 0x03 => true,
                    _ => false
                }
            );
            assert_eq!(hdw.mpub_key().chaincode().len(), 32);
        }
    }
}