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
    hdwallet::ckd::{
        derive_xprv,
        ChildOptions
    },
    util::try_into
};

#[derive(Clone)]
pub struct Xprv {
    key: PrivKey,
    chaincode: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub index: [u8; 4]
}

#[derive(Clone)]
pub struct Xpub {
    key: PubKey,
    chaincode: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub index: [u8; 4]
}

pub trait ExtendedKey {
    /**
        Constructs the Extended Key.
    */
    fn construct<T: 'static>(key: T, chaincode: [u8; 32], depth: u8, pf: [u8; 4], index: [u8; 4]) -> Self
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
    fn construct<T: 'static>(key: T, chaincode: [u8; 32], depth: u8, pf: [u8; 4], index: [u8; 4]) -> Self 
    where T: Key
    {
        if TypeId::of::<T>() == TypeId::of::<PrivKey>() {
            return Self {
                key: PrivKey::from_slice(&key.as_bytes::<32>()).unwrap(),
                chaincode: chaincode,
                //Serialisation info
                depth: depth,
                parent_fingerprint: pf,
                index: index
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
        payload.push(self.depth); //depth
        self.parent_fingerprint.iter().for_each(|x| payload.push(*x)); //fingerprint
        self.index.iter().for_each(|x| payload.push(*x)); //index
        self.chaincode().iter().for_each(|x| payload.push(*x)); //chaincode
        payload.push(0x00); //private key append 0x00
        self.key::<32>().iter().for_each(|x| payload.push(*x)); //private key
        
        check_encode(VersionPrefix::Xprv,&payload)
    }
    
}

impl Xprv {
    /**
        Return the public key of the private key in the Xprv.
    */
    pub fn get_pub(&self) -> PubKey {
        PubKey::from_priv_key(&PrivKey::from_slice(&self.key::<32>()).unwrap())
    }

    /**
        Gets the child key of Self
    */
    pub fn get_child(&self, options: ChildOptions) -> Xprv {
        match derive_xprv(self, options) {
            Ok(x) => x,
            Err(x) => panic!("{}", x)
        }
    }
}

impl ExtendedKey for Xpub {
    fn construct<T: 'static>(key: T, chaincode: [u8; 32], depth: u8, pf: [u8; 4], index: [u8; 4]) -> Self 
    where T: Key
    {
        if TypeId::of::<T>() == TypeId::of::<PubKey>() {
            return Self {
                key: PubKey::from_slice(&key.as_bytes::<33>()).unwrap(),
                chaincode: chaincode,
                //Serialisation info
                depth: depth,
                parent_fingerprint: pf,
                index: index
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
        payload.push(self.depth); //depth
        self.parent_fingerprint.iter().for_each(|x| payload.push(*x)); //parent fingerprint
        self.index.iter().for_each(|x| payload.push(*x)); //index
        self.chaincode().iter().for_each(|x| payload.push(*x)); //chaincode
        self.key::<33>().iter().for_each(|x| payload.push(*x)); //public key
        
        check_encode(VersionPrefix::Xpub,&payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bip39::{lang::Language, mnemonic::Mnemonic, mnemonic::PhraseLength}, hdwallet::HDWallet, util::{
            decode_02x
        }};

    //Data generated on leanrmeabitcoin.com/technical/hd-wallets
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

    #[test]
    fn serialize_extended_keys() {
        let mnemonic: Mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC.to_string(), Language::English, "").unwrap();
        let hdw: HDWallet = HDWallet::new(mnemonic);

        //master xprv serialization test
        assert_eq!(hdw.mpriv_key().serialize(), 
        "xprv9s21ZrQH143K2MPKHPWh91wRxLKehoCNsRrwizj2xNaj9zD5SHMNiHJesDEYgJAavgNE1fDWLgYNneHeSA8oVeVXVYomhP1wxdzZtKsLJbc".to_string()
        );

        //master xpub serialization test
        assert_eq!(hdw.mpub_key().serialize(),
        "xpub661MyMwAqRbcEqTnPR3hW9tAWNA97FvEEenYXP8eWi7i2nYDypfdG5d8iWfK8YgesKi2EE5mk9THcTqnveDWwZVMuctjmxeEaUKgtg7CEEc".to_string()
        );
    }
}