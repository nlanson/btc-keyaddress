/*
    This module implements extended keys that are
    used in BIP32 hierarchal deterministic wallets.

    Extended keys are 64 bytes in length. The first 32 bytes
    are the keys and the last 32 bytes is the chaincode.
*/

use crate::{
    key::{
        PrivKey,
        PubKey,
        Key
    },
    bs58check::{
        check_encode,
        decode,
        validate_checksum,
        VersionPrefix,
        Bs58Error
    },
    hdwallet::{
        ckd::{
            derive_xprv,
            derive_xpub,
            ChildOptions
        },
        HDWError
    },
    address::Address,
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

pub trait ExtendedKey<T> {
    /**
        Constructs the Extended Key.
    */
    fn construct(key: T, chaincode: [u8; 32], depth: u8, pf: [u8; 4], index: [u8; 4]) -> Self
    where T: Key;

    /**
        Import a extended key from a string.
        "xprv[...]" or "xpub[...]""
    */
    fn from_str(key: &str) -> Result<Self, HDWError>
    where Self: Sized;

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

    /**
        Derives the child key of self
    */
    fn get_xchild(&self, options: ChildOptions) -> Result<Self, HDWError>
    where Self: Sized;

    /**
        Return the non extended public key of self.
    */
    fn get_pub(&self) -> PubKey;

    /**
        Get the address of self.
    */
    fn get_address(&self) -> String {
        Address::from_pub_key(&self.get_pub(), true)
    }

    /**
        Derive the key at the given path.
    */
    fn derive_from_path(&self, path: &str) -> Result<Self, HDWError>
    where Self: Sized + Clone
    {
        let mut children: Vec<&str> = path.split('/').map(|x| x).collect();
        
        if children[0] == "m" {
            children.remove(0);
        } else {
            return Err(HDWError::BadPath(path.to_string()))
        }

        let mut current_key: Self = self.clone();
        let mut childkey: Self = self.clone();
        for i in 0..children.len() {
            //Set the options for the child
            let options: ChildOptions = match children[i].parse() {
                //If the provided index can be parsed without errors, it will be a normal child
                Ok(x) => ChildOptions::Normal(x),

                //If the provided index cant be parsed, check if it can be parsed with the last char removed.
                //If this works, then it will be a hardened child. Else return an error.
                Err(_) => {
                    let hardened_index = &children[i][0..children[i].len()-1];
                    match hardened_index.parse() {
                        Ok(x) => ChildOptions::Hardened(x),
                        Err(_) => return Err(HDWError::BadPath(path.to_string()))
                    }
                }
            };
            
            childkey = match current_key.get_xchild(options) {
                Ok(x) => x,
                Err(x) => return Err(x)
            };
            current_key = childkey.clone();
        }


        Ok(childkey)  
    }
}

impl ExtendedKey<PrivKey> for Xprv {
    fn construct(key: PrivKey, chaincode: [u8; 32], depth: u8, pf: [u8; 4], index: [u8; 4]) -> Self {
        Self {
            key: PrivKey::from_slice(&key.as_bytes::<32>()).unwrap(),
            chaincode: chaincode,
            //Serialisation info
            depth: depth,
            parent_fingerprint: pf,
            index: index
        }
    }

    fn from_str(key: &str) -> Result<Self, HDWError> {
        let bytes = match decode(&key.to_string()) {
            Ok(x) => x,
            //If decode error, return the index of the bad character or a generic error
            Err(x) => match x {
                Bs58Error::InvalidChar(x) => return Err(HDWError::BadChar(x.1)),
                Bs58Error::NonAsciiChar(x) => return Err(HDWError::BadChar(x)),
                _ => return Err(HDWError::BadKey())
            }
        };
        //Check if the decoded key is 84 bytes large
        if bytes.len() != 82 { return Err(HDWError::BadKey()) }
        
        //Check if the checkum of the decoded bytes is equal to the calculated checksum.
        //validate_checksum() method will likely not return an Error as the key has already been decoded once.
        if let Ok(x) = validate_checksum(key) {
            if !x { return Err(HDWError::BadChecksum()) } 
        }
        
        //Check if the verion of the key is for "xprv" keys
        let version = bytes[0..4].to_vec();
        if version != vec![0x04, 0x88, 0xAD, 0xE4] { return Err(HDWError::BadPrefix(version)) }

        //Extract the remaining data from the payload
        let depth: u8 = bytes[4];
        let fingerprint: [u8; 4] = try_into(bytes[5..9].to_vec());
        let index: [u8; 4] = try_into(bytes[9..13].to_vec());
        let chaincode: [u8; 32] = try_into(bytes[13..45].to_vec());
        let key: PrivKey = match PrivKey::from_slice(&bytes[46..78]) {
            Ok(x) => x,
            Err(_) => return Err(HDWError::BadKey())
        };

        //Construct self
        Ok(Self::construct(
            key,
            chaincode,
            depth,
            fingerprint,
            index
        ))
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

    fn get_xchild(&self, options: ChildOptions) -> Result<Xprv, HDWError> {
        match derive_xprv(self, options) {
            Ok(x) => Ok(x),
            Err(x) => Err(x)
        }
    }


    fn get_pub(&self) -> PubKey {
        PubKey::from_priv_key(&PrivKey::from_slice(&self.key::<32>()).unwrap())
    }
    
}

impl Xprv {
    /**
        Return the private key part of self
    */
    pub fn get_prv(&self) -> PrivKey {
        PrivKey::from_slice(&self.key::<32>()).unwrap()
    }

    /**
        Find the corresponding xpub for a hardened xprv
    */
    pub fn get_xpub(&self) -> Xpub {
        let privk: PrivKey = PrivKey::from_slice(&self.key::<32>()).unwrap();
        let chaincode: [u8; 32] = self.chaincode();
        let pubk: PubKey = PubKey::from_priv_key(&privk);

        Xpub::construct(
            pubk, chaincode,
            self.depth,
            self.parent_fingerprint,
            self.index
        )
    }
    
}

impl ExtendedKey<PubKey> for Xpub {
    fn construct(key: PubKey, chaincode: [u8; 32], depth: u8, pf: [u8; 4], index: [u8; 4]) -> Self {
            return Self {
                key: PubKey::from_slice(&key.as_bytes::<33>()).unwrap(),
                chaincode: chaincode,
                //Serialisation info
                depth: depth,
                parent_fingerprint: pf,
                index: index
            }
    }

    fn from_str(key: &str) -> Result<Self, HDWError> {
        let bytes = match decode(&key.to_string()) {
            Ok(x) => x,
            //If decode error, return the index of the bad character or a generic error
            Err(x) => match x {
                Bs58Error::InvalidChar(x) => return Err(HDWError::BadChar(x.1)),
                Bs58Error::NonAsciiChar(x) => return Err(HDWError::BadChar(x)),
                _ => return Err(HDWError::BadKey())
            }
        };
        //Check if the decoded key is 84 bytes large
        if bytes.len() != 82 { return Err(HDWError::BadKey()) }

        //Check if the checkum of the decoded bytes is equal to the calculated checksum
        if let Ok(x) = validate_checksum(key) {
            if !x { return Err(HDWError::BadChecksum()) } 
        }
        
        //Check if the verion of the key is for "xpub" keys
        let version = bytes[0..4].to_vec();
        if version != vec![0x04, 0x88, 0xB2, 0x1E] { return Err(HDWError::BadPrefix(version)) }
        
        //Extract the remaining data from the payload
        let depth: u8 = bytes[4];
        let fingerprint: [u8; 4] = try_into(bytes[5..9].to_vec());
        let index: [u8; 4] = try_into(bytes[9..13].to_vec());
        let chaincode: [u8; 32] = try_into(bytes[13..45].to_vec());
        let key: PubKey = match PubKey::from_slice(&bytes[45..78]) {
            Ok(x) => x,
            Err(_) => return Err(HDWError::BadKey())
        };

        //Construct self
        Ok(Self::construct(
            key,
            chaincode,
            depth,
            fingerprint,
            index
        ))
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

    fn get_xchild(&self, options: ChildOptions) -> Result<Xpub, HDWError> {
        match derive_xpub(self, options) {
            Ok(x) => Ok(x),
            Err(x) => Err(x)
        }
    }

    fn get_pub(&self) -> PubKey {
        PubKey::from_slice(&self.key::<33>()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    /*
        Tests for child key deriveration are implemented in ckd.rs
    */
    
    use super::*;
    use crate::{
        bip39::{
            Language,
            Mnemonic,
            PhraseLength
        },
        hdwallet::HDWallet,
        util::{
            decode_02x
        }
    };

    //Data generated on leanrmeabitcoin.com/technical/hd-wallets
    const TEST_MNEMONIC: &str = "glow laugh acquire menu anchor evil occur put hover renew calm purpose";
    const TEST_MPRIV: &str = "081549973bafbba825b31bcc402a3c4ed8e3185c2f3a31c75e55f423e9629aa3";
    const TEST_MCC: &str = "1d7d2a4c940be028b945302ad79dd2ce2afe5ed55e1a2937a5af57f8401e73dd";

    #[test]
    fn extended_keys_test() {
        let mnemonic: Mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC.to_string(), Language::English, "").unwrap();
        let hdw: HDWallet = HDWallet::new(mnemonic).unwrap();

        //Test if the calculated and expected key and chaincode are equal
        assert_eq!(decode_02x(TEST_MPRIV), hdw.mpriv_key().key::<32>());
        assert_eq!(decode_02x(TEST_MCC), hdw.mpriv_key().chaincode());
    }

    #[test]
    fn random_extended_keys_test() {
        for _i in 0..5 {
            let mnemonic: Mnemonic = Mnemonic::new(PhraseLength::TwentyFour, Language::English, "").unwrap();
            let hdw: HDWallet = HDWallet::new(mnemonic).unwrap();

            //Check lengths of mpriv, mpub and cc as well as compression prefix
            // of mpub.key to check if it is 0x02 or 0x03
            assert_eq!(hdw.mpriv_key().key::<32>().len(), 32);
            assert_eq!(hdw.mpriv_key().chaincode().len(), 32);
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
        let hdw: HDWallet = HDWallet::new(mnemonic).unwrap();

        //master xprv serialization test
        assert_eq!(hdw.mpriv_key().serialize(), 
        "xprv9s21ZrQH143K2MPKHPWh91wRxLKehoCNsRrwizj2xNaj9zD5SHMNiHJesDEYgJAavgNE1fDWLgYNneHeSA8oVeVXVYomhP1wxdzZtKsLJbc".to_string()
        );

        //master xpub serialization test
        assert_eq!(hdw.mpub_key().serialize(),
        "xpub661MyMwAqRbcEqTnPR3hW9tAWNA97FvEEenYXP8eWi7i2nYDypfdG5d8iWfK8YgesKi2EE5mk9THcTqnveDWwZVMuctjmxeEaUKgtg7CEEc".to_string()
        );
    }

    #[test]
    fn create_xkeys_from_str() {
        //XPRV
        let test_data: Vec<&str> = vec![
            "xprv9s21ZrQH143K2MPKHPWh91wRxLKehoCNsRrwizj2xNaj9zD5SHMNiHJesDEYgJAavgNE1fDWLgYNneHeSA8oVeVXVYomhP1wxdzZtKsLJbc",
            "this is definately not a extended private key",
            "xpub661MyMwAqRbcEqTnPR3hW9tAWNA97FvEEenYXP8eWi7i2nYDypfdG5d8iWfK8YgesKi2EE5mk9THcTqnveDWwZVMuctjmxeEaUKgtg7CEEc"
        ];
        let expected_results: Vec<bool> = vec![
            true,
            false,
            false,
        ];
        for i in 0..test_data.len() {
            assert_eq!(Xprv::from_str(test_data[i]).is_ok(), expected_results[i]);
        }

        //XPUB
        let test_data: Vec<&str> = vec![
            "xpub661MyMwAqRbcEqTnPR3hW9tAWNA97FvEEenYXP8eWi7i2nYDypfdG5d8iWfK8YgesKi2EE5mk9THcTqnveDWwZVMuctjmxeEaUKgtg7CEEc",
            "this is definately not a extended private key",
            "xprv661MyMwAqRbcEqTnPR3hW9tAWNA97FvEEenYXP8eWi7i2nYDypfdG5d8iWfK8YgesKi2EE5mk9THcTqnveDWwZVMuctjmxeEaUKgtg7CEEc"
        ];
        let expected_results: Vec<bool> = vec![
            true,
            false,
            false,
        ];
        for i in 0..test_data.len() {
            assert_eq!(Xpub::from_str(test_data[i]).is_ok(), expected_results[i]);
        }
    }

    #[test]
    fn derive_from_path_tests() {
        let mnemonic: Mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC.to_string(), Language::English, "").unwrap();
        let hdw: HDWallet = HDWallet::new(mnemonic).unwrap();
        
        let (xprv_at_path, xpub_at_path) = match hdw.mpriv_key().derive_from_path("m/44'/0'/0'/0") {
            Ok(x) => {
                (x.serialize(), x.get_xpub().serialize())
            },
            Err(x) => panic!("{}", x)
        };

        assert_eq!(xprv_at_path, "xprvA2RVpXN1QL4okLkV3NT6ADt7UcqauZdi6Tyv2wBscQ3kq9zvvfsxBBgQTcoj7GZCa7wkmmeLvQHdqVJEQ1D4PGoDgYV8CZj9w9jqGNbGCaT");
        assert_eq!(xpub_at_path, "xpub6FQrE2tuEhd6xppx9Pz6XMpr2eg5K2MZTguWqKbVAjajhxL5UDCCiyztJtCFDrAqPoQfmbVeVX5BKXQ7vxgR42DtsVa3g2YMLZQjbEnxbqi");
    }
}