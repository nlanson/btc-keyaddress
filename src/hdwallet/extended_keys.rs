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
    encoding::{
        // check_encode,
        // decode,
        // validate_checksum,
        // VersionPrefix,
        // Bs58Error,
        base58::Base58,
        base58::Base58Error,
        version_prefix::VersionPrefix
        
    },
    hdwallet::{
        ckd::{
            derive_xprv,
            derive_xpub,
            ChildOptions,
        },
        HDWError,
        Path,
        WalletType
    },
    bip39::Mnemonic,
    hash,
    address::Address,
    util::{
        try_into,
        as_u32_be
    },
    util::Network,
    script::RedeemScript,
    taproot
};

#[derive(Debug, Clone, Copy)]
pub struct Xprv {
    key: PrivKey,
    chaincode: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub index: [u8; 4]
}

#[derive(Debug, Clone, Copy)]
pub struct Xpub {
    key: PubKey,
    chaincode: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub index: [u8; 4]
}

pub trait ExtendedKey<T> where T: Key {
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

    fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Self, HDWError>
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
        Serialize the extended key with the selected prefix
    */
    fn serialize(&self, v_prefix: &VersionPrefix) -> String;

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
        Converts an extended key to an address. 
    */
    fn get_address(&self, r#type: &WalletType, network: Network) -> String {
        match r#type {
            WalletType::P2PKH => Address::P2PKH(self.get_pub(), network).to_string().unwrap(),
            WalletType::P2WPKH => Address::P2WPKH(self.get_pub(), network).to_string().unwrap(),
            WalletType::P2SH_P2WPKH => {
                let script: RedeemScript = RedeemScript::p2wpkh(&self.get_pub());
                Address::P2SH(script, network).to_string().unwrap()
            },
            WalletType::P2TR => {
                //Tweaking with no script tree
                let internal_key = self.get_pub().schnorr();
                let tweaked_key = taproot::taproot_output_script(&internal_key, None).unwrap();
                Address::P2TR(tweaked_key, Network::Bitcoin).to_string().unwrap()
            }
        }
    }

    /**
        Derive the key at the given path.
        Takes in a vec of strings representing the path.
        eg. [44', 0', 0', 0] would represent the path m/44'/0'/0'/0
    */
    fn derive_from_path(&self, path: &Path) -> Result<Self, HDWError>
    where Self: Sized + Clone
    {

        let mut current_key: Self = self.clone();
        let mut childkey: Self = self.clone();
        for i in 0..path.children.len() {
            childkey = match current_key.get_xchild(path.children[i].clone()) {
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
        let bytes = match Base58::decode(&key.to_string()) {
            Ok(x) => x,
            //If decode error, return the index of the bad character or a generic error
            Err(x) => match x {
                Base58Error::BadChar(x) => return Err(HDWError::BadChar(x as usize)),
                _ => return Err(HDWError::BadKey())
            }
        };
        //Check if the decoded key is 84 bytes large
        if bytes.len() != 82 { return Err(HDWError::BadKey()) }
        
        //Check if the checkum of the decoded bytes is equal to the calculated checksum.
        //validate_checksum() method will likely not return an Error as the key has already been decoded once.
        if let Ok(x) = Base58::validate_checksum(key) {
            if !x { return Err(HDWError::BadChecksum()) } 
        }
        
        //Check if the verion of the key is for xprv keys
        let version: u32 = as_u32_be(&try_into(bytes[0..4].to_vec()));
        match VersionPrefix::from_int(version) {
            //Only continue if version is for extended private keys
            Ok(x) => match x {
                VersionPrefix::Xprv |
                VersionPrefix::Yprv |
                VersionPrefix::Zprv |
                VersionPrefix::Tprv |
                VersionPrefix::Uprv |
                VersionPrefix::Vprv |
                VersionPrefix::SLIP132Yprv |
                VersionPrefix::SLIP132Zprv |
                VersionPrefix::SLIP132Uprv |
                VersionPrefix::SLIP132Vprv => { /* Continue */ },
                _ => return Err(HDWError::BadKey())
            },
            
            //Return an error if not valid
            _ => return Err(HDWError::BadPrefix(version.to_be_bytes().to_vec()))
        }

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
        Convert a mnemonic to mater private key.
    */
    fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Xprv, HDWError> {
        let mprivkey_bytes: [u8; 64] = hash::hmac_sha512(&mnemonic.seed(), b"Bitcoin seed");
        let master_private_key: Xprv = Xprv::construct(
            match PrivKey::from_slice(&mprivkey_bytes[0..32]) {
                Ok(x) => x,
                Err(_) => return Err(HDWError::BadKey())
            },
            try_into(mprivkey_bytes[32..64].to_vec()),
            0x00,
            [0x00; 4],
            [0x00; 4]
        );

        Ok( master_private_key )
    }

    /**
        32 bytes (No indicator)
    */
    fn key<const N:usize>(&self) -> [u8; N] {
        self.key.as_bytes::<N>()
    }

    fn chaincode(&self) -> [u8; 32] {
        self.chaincode
    }

    fn serialize(&self, v_prefix: &VersionPrefix) -> String {
        let mut payload: Vec<u8> = vec![];
        payload.push(self.depth); //depth
        self.parent_fingerprint.iter().for_each(|x| payload.push(*x)); //fingerprint
        self.index.iter().for_each(|x| payload.push(*x)); //index
        self.chaincode().iter().for_each(|x| payload.push(*x)); //chaincode
        payload.push(0x00); //private key append 0x00
        self.key::<32>().iter().for_each(|x| payload.push(*x)); //private key

        
        Base58::new(Some(*v_prefix), &payload).check_encode()
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
        let bytes = match Base58::decode(key) {
            Ok(x) => x,
            //If decode error, return the index of the bad character or a generic error
            Err(x) => match x {
                Base58Error::BadChar(x) => return Err(HDWError::BadChar(x as usize)),
                _ => return Err(HDWError::BadKey())
            }
        };
        //Check if the decoded key is 84 bytes large
        if bytes.len() != 82 { return Err(HDWError::BadKey()) }

        //Check if the checkum of the decoded bytes is equal to the calculated checksum
        if let Ok(x) = Base58::validate_checksum(key) {
            if !x { return Err(HDWError::BadChecksum()) } 
        }

        //Check if the verion of the key is for xprv keys
        let version: u32 = as_u32_be(&try_into(bytes[0..4].to_vec()));
        match VersionPrefix::from_int(version) {
            //Only continue if version is for extended public keys (including slip-132)
            Ok(x) => match x {
                VersionPrefix::Xpub |
                VersionPrefix::Ypub |
                VersionPrefix::Zpub |
                VersionPrefix::Tpub |
                VersionPrefix::Upub |
                VersionPrefix::Vpub |
                VersionPrefix::SLIP132Ypub |
                VersionPrefix::SLIP132Zpub |
                VersionPrefix::SLIP132Upub |
                VersionPrefix::SLIP132Vpub => { /* Continue */ },
                _ => return Err(HDWError::BadKey())
            },
            
            //Return an error if not valid
            _ => return Err(HDWError::BadPrefix(version.to_be_bytes().to_vec()))
        }

        
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
        Convert a mnemonic to mater private key.
    */
    fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Xpub, HDWError> {
        let mprivkey_bytes: [u8; 64] = hash::hmac_sha512(&mnemonic.seed(), b"Bitcoin seed");
        let master_private_key: Xprv = Xprv::construct(
            match PrivKey::from_slice(&mprivkey_bytes[0..32]) {
                Ok(x) => x,
                Err(_) => return Err(HDWError::BadKey())
            },
            try_into(mprivkey_bytes[32..64].to_vec()),
            0x00,
            [0x00; 4],
            [0x00; 4]
        );

        Ok( master_private_key.get_xpub() )
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

    //Need to extend to add SLIP-0132 multisig keys
    fn serialize(&self, v_prefix: &VersionPrefix) -> String {
        let mut payload: Vec<u8> = vec![];
        payload.push(self.depth); //depth
        self.parent_fingerprint.iter().for_each(|x| payload.push(*x)); //parent fingerprint
        self.index.iter().for_each(|x| payload.push(*x)); //index
        self.chaincode().iter().for_each(|x| payload.push(*x)); //chaincode
        self.key::<33>().iter().for_each(|x| payload.push(*x)); //public key

        
        Base58::new(Some(*v_prefix), &payload).check_encode()
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

//Implementing ordering and comparing for extended public keys.
//This is used for legacy HD Multisig under BIP-45 in determining the cosigner index.
impl Eq for Xpub { }
impl PartialEq for Xpub { 
    //Check the key and chaincode bytes are equal
    fn eq(&self, other: &Self) -> bool {
        (self.key(), &self.chaincode()) == (other.key::<33>(), &other.chaincode())
    }
}

impl PartialOrd for Xpub {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Xpub {
    //Sort lexicographically
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.get_pub().hex().cmp(&other.get_pub().hex())
    }
}

#[cfg(test)]
mod tests {
    /*
        Tests for child key deriveration are implemented in ckd.rs
    */
    
    use super::*;
    use crate::{
        encoding::ToVersionPrefix,
        bip39::{
            Language,
            Mnemonic,
        },
        hdwallet::{
            HDWallet,
            HDWalletBuilder,
            Unlocker,
            WalletType
        },
        util::{
            decode_02x
        }};

    //Data generated on leanrmeabitcoin.com/technical/hd-wallets
    const TEST_MNEMONIC: &str = "glow laugh acquire menu anchor evil occur put hover renew calm purpose";
    const TEST_MPRIV: &str = "081549973bafbba825b31bcc402a3c4ed8e3185c2f3a31c75e55f423e9629aa3";
    const TEST_MCC: &str = "1d7d2a4c940be028b945302ad79dd2ce2afe5ed55e1a2937a5af57f8401e73dd";

    //Test wallet for P2PKH
    fn hdwallet_set() -> (HDWallet, Unlocker) {
        let mut b = HDWalletBuilder::new();
        let mnemonic: Mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC.to_string(), Language::English, "").unwrap();
        b.set_signer_from_mnemonic(&mnemonic).unwrap();
        b.set_type(WalletType::P2PKH).unwrap();

        (b.build().unwrap(), Unlocker::from_mnemonic(&mnemonic).unwrap())
    }
    
    #[test]
    fn extended_keys_test() -> Result<(), HDWError> {
        let (hdw, unlocker) = hdwallet_set();

        //Test if the calculated and expected key and chaincode are equal
        assert_eq!(decode_02x(TEST_MPRIV), hdw.master_private_key(&unlocker)?.key::<32>());
        assert_eq!(decode_02x(TEST_MCC), hdw.master_private_key(&unlocker)?.chaincode());

        Ok(())
    }

    #[test]
    fn random_extended_keys_test() -> Result<(), HDWError> {
        for _i in 0..5 {
            let (hdw, unlocker) = hdwallet_set();

            //Check lengths of mpriv, mpub and cc as well as compression prefix
            // of mpub.key to check if it is 0x02 or 0x03
            assert_eq!(hdw.master_private_key(&unlocker)?.key::<32>().len(), 32);
            assert_eq!(hdw.master_private_key(&unlocker)?.chaincode().len(), 32);
            assert_eq!(hdw.master_public_key(&unlocker)?.key::<33>().len(), 33);
            assert!(
                match hdw.master_public_key(&unlocker)?.key::<33>()[0] {
                    0x02 | 0x03 => true,
                    _ => false
                }
            );
            assert_eq!(hdw.master_public_key(&unlocker)?.chaincode().len(), 32);
        }

        Ok(())
    }

    #[test]
    fn serialize_extended_keys() -> Result<(), HDWError> {
        let (hdw, unlocker) = hdwallet_set();

        //master xprv serialization test
        assert_eq!(hdw.master_private_key(&unlocker)?.serialize(&WalletType::P2PKH.private_version_prefix(Network::Bitcoin)), 
        "xprv9s21ZrQH143K2MPKHPWh91wRxLKehoCNsRrwizj2xNaj9zD5SHMNiHJesDEYgJAavgNE1fDWLgYNneHeSA8oVeVXVYomhP1wxdzZtKsLJbc".to_string()
        );

        //master xpub serialization test
        assert_eq!(hdw.master_public_key(&unlocker)?.serialize(&WalletType::P2PKH.public_version_prefix(Network::Bitcoin)),
        "xpub661MyMwAqRbcEqTnPR3hW9tAWNA97FvEEenYXP8eWi7i2nYDypfdG5d8iWfK8YgesKi2EE5mk9THcTqnveDWwZVMuctjmxeEaUKgtg7CEEc".to_string()
        );

        Ok(())
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
    fn derive_from_path_tests()-> Result<(), HDWError> {
        let (hdw, unlocker) = hdwallet_set();
        let path: Path = Path::from_str("m/44'/0'/0'/0").unwrap();

        let (xprv_at_path, xpub_at_path) = match hdw.master_private_key(&unlocker)?.derive_from_path(&path) {
            Ok(x) => {
                (x.serialize(&WalletType::P2PKH.private_version_prefix(Network::Bitcoin)), x.get_xpub().serialize(&WalletType::P2PKH.public_version_prefix(Network::Bitcoin)))
            },
            Err(x) => panic!("{}", x)
        };

        assert_eq!(xprv_at_path, "xprvA2RVpXN1QL4okLkV3NT6ADt7UcqauZdi6Tyv2wBscQ3kq9zvvfsxBBgQTcoj7GZCa7wkmmeLvQHdqVJEQ1D4PGoDgYV8CZj9w9jqGNbGCaT");
        assert_eq!(xpub_at_path, "xpub6FQrE2tuEhd6xppx9Pz6XMpr2eg5K2MZTguWqKbVAjajhxL5UDCCiyztJtCFDrAqPoQfmbVeVX5BKXQ7vxgR42DtsVa3g2YMLZQjbEnxbqi");
    
        Ok(())
    }

    //Test wallet for BIP-84
    fn segwit_hdwallet_set() -> (HDWallet, Unlocker) {
        let mut b = HDWalletBuilder::new();
        let mnemonic: Mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(), Language::English, "").unwrap();
        b.set_signer_from_mnemonic(&mnemonic).unwrap();
        b.set_type(WalletType::P2WPKH).unwrap();

        (b.build().unwrap(), Unlocker::from_mnemonic(&mnemonic).unwrap())
    }

    #[test]
    fn bip84_test_vectors() -> Result<(), HDWError> {
        let (hdw, unlocker) = segwit_hdwallet_set();
        
        // Account 0, root = m/84'/0'/0'
        assert_eq!(hdw.account_private_key(&unlocker)?.serialize(&hdw.wallet_type.private_version_prefix(hdw.network)), "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE");
        assert_eq!(hdw.account_public_key().serialize(&hdw.wallet_type.public_version_prefix(hdw.network)), "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs");

        // Account 0, first receiving address = m/84'/0'/0'/0/0
        let address = hdw.address_at(false, 0)?;
        let key = hdw.address_private_key(false, 0, &unlocker)?;
        assert_eq!(key.export_as_wif(true, Network::Bitcoin), "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d");
        assert_eq!(address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");

        // Account 0, second receiving address = m/84'/0'/0'/0/1
        let address = hdw.address_at(false, 1)?;
        let key = hdw.address_private_key(false, 1, &unlocker)?;
        assert_eq!(key.export_as_wif(true, Network::Bitcoin), "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy");
        assert_eq!(address, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");

        // Account 0, first change address = m/84'/0'/0'/1/0
        let address = hdw.address_at(true, 0)?;
        let key = hdw.address_private_key(true, 0, &unlocker)?;
        assert_eq!(key.export_as_wif(true, Network::Bitcoin), "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF");
        assert_eq!(address, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
    
        Ok(())
    }
}