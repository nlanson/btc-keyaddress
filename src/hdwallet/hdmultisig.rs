/*
    Module implementing Multisig HD Wallet data structures
*/

use crate::{
    address::Address,
    bip39::Mnemonic,
    key::PrivKey,
    key::PubKey,
    key::Key,
    script::Script,
    util::Network
};
use super::{
    HDWallet,
    WalletType,
    HDWError,
    ExtendedKey,
    Xprv, Xpub,
    Path,
    ChildOptions,
    WatchOnly
};

pub struct HDMultisig {
    pub mnemonics: Vec<Mnemonic>,
    pub m: u8,
    pub n: u8,
    pub r#type: MultisigWalletType
}

pub enum MultisigWalletType {
    P2SH,
    P2WSH,
    P2SH_P2WSH
}

impl HDMultisig {
    pub fn new(
        mnemonics: &Vec<Mnemonic>,
        m: u8,
        n: u8,
        r#type: MultisigWalletType
    ) -> Self {
        Self {
            mnemonics: mnemonics.clone(),
            m,
            n,
            r#type
        }
    }

    /**
       Returns the redeem script at a certain deriveration path 
    */
    pub fn redeem_script_at(&self, path: &str, network: Network) -> Result<Script, HDWError> {
        let mut p: Path = Path::from_str(path)?;
        let mut keys: Vec<PubKey> = vec![];
        for i in 0..self.n {
            let key = HDWallet::new(self.mnemonics[i as usize].clone(), WalletType::P2PKH).unwrap();
            keys.push(key.get_xprv_key_at(path)?.get_pub());
        }

        Ok(Script::multisig(self.m, self.n, &keys).unwrap())
    }

    /**
       Returns the private key for the given cosigner index at a certain deriveration path
    */
    pub fn key_at(&self, signer_index: usize, path: &str) -> Result<PrivKey, HDWError> {
        let key = HDWallet::new(self.mnemonics[signer_index].clone(), WalletType::P2PKH)?
                    .get_xprv_key_at(path)?
                    .key::<32>();
        
        Ok(PrivKey::from_slice(&key).unwrap())
    }

    /**
       Returns the address at a certain deriveration path 
    */
    pub fn address_at(&self, path: &str, network: Network) -> Result<String, HDWError> {
        let redeem_script = self.redeem_script_at(path, network.clone()).unwrap();

        let address = match &self.r#type {
            MultisigWalletType::P2SH => Address::P2SH(redeem_script, network),
            MultisigWalletType::P2WSH => Address::P2WSH(redeem_script, network),
            MultisigWalletType::P2SH_P2WSH => {
                let script: Script = Script::p2sh_p2wsh(&redeem_script);
                Address::P2SH(script, network)
            }
        };

        Ok(address.to_string().unwrap())
    }

    /**
       Returns a vector of addresses from a certain deriveration path
    */
    pub fn get_addresses(&self, path: &str, count: usize, network: Network) -> Result<Vec<String>, HDWError> {
        let mut addresses: Vec<String> = vec![];
        let mut p: Path = Path::from_str(path)?;
        let last_index = p.children.len()-1;
        for _i in 0..count {
            addresses.push(self.address_at(&p.to_string(), network.clone())?);
            
            //Then increment the deepest index by one
            match p.children[last_index] {
                ChildOptions::Normal(x) => {
                    let n = x + 1;
                    if n >= (2 as u32).pow(31) { return Err(HDWError::IndexTooLarge(n)) }
                    p.children[last_index] = ChildOptions::Normal(n);
                },
                ChildOptions::Hardened(x) => {
                    let n = x + 1;
                    if n >= (2 as u32).pow(32) { return Err(HDWError::IndexTooLarge(n)) }
                    p.children[last_index] = ChildOptions::Hardened(n);
                }
            }
        }

        Ok(addresses)
    }
}



//New and revised Multisig HD Wallet


pub struct MultisigHDWallet {
    master_public_keys: Vec<Xpub>,
    m: u8,
    n: u8,
    wallet_type: MultisigWalletType
}

pub struct MultiSigUnlocker {
    master_private_keys: Vec<Xprv>
}

impl MultiSigUnlocker {
    pub fn from_mnemonics(mnemonics: &Vec<Mnemonic>) -> Result<Self, HDWError> {
        Ok(Self{
            master_private_keys: mnemonics.iter().map(|x| {
                Xprv::from_mnemonic(x).unwrap()
            }).collect::<Vec<Xprv>>()
        })
    }

    pub fn from_master_privates(keys: &Vec<&str>) -> Result<Self, HDWError> {
        Ok(Self {
            master_private_keys: keys.iter().map(|x| {
                Xprv::from_str(x).unwrap()
            }).collect::<Vec<Xprv>>()
        })
    }
}

impl MultisigHDWallet {
    pub fn from_mnemonics(mnemonics: &Vec<Mnemonic>, m: u8, wallet_type: MultisigWalletType) -> Result<Self, HDWError> {
        let master_public_keys = mnemonics.iter().map(|x| {
            Xpub::from_mnemonic(x).unwrap()
        }).collect::<Vec<Xpub>>();
        let n = master_public_keys.len() as u8;

        Ok(Self{
            master_public_keys,
            m,
            n,
            wallet_type
        })
    }

    pub fn from_master_privates(keys: &Vec<&str>, m: u8) -> Result<Self, HDWError> {
        //Check if each provided key is the same type

        //Convert each to xpubs
        todo!()
    }

    pub fn from_master_publics(keys: &Vec<&str>, m: u8) -> Result<Self, HDWError> {
        //Check if each provided key is the same type
        
        todo!()
    }

    pub fn redeem_script_at(&self, path: &str) -> Result<Script, HDWError> {
        //Return the redeem script at the given path

        todo!()
    }

    pub fn key_for(&self, cosigner_index: usize, path: &str, unlocker: &MultiSigUnlocker) -> Result<PrivKey, HDWError> {
        //Return the private key at the given path.

        //The Unlocker here can contain as little Xprv keys.
        //The code will get the xpub at the deriveration path using the stored Xpubs and compare it with the Xpub derived
        //from any Xprvs provided in the unlocker. 

        //If none match, no private key can be returned. 

        //If there is a match, return the matched key.

        todo!();
    }
}

impl WatchOnly for MultisigHDWallet {
    fn addresses_at(&self, path: &str, count: usize, network: Network) -> Result<Vec<String>, HDWError>
    where Self: Sized {
        //Get the addresses at the given path and up count times.
        
        todo!()
    }
}