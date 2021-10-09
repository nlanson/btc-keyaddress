/*
    Module implementing Multisig HD Wallet data structures
*/

use crate::{address::Address, bip39::Mnemonic, key::PrivKey, key::PubKey, prelude::{ExtendedKey, Key}, script::Script, util::Network};
use super::{
    HDWallet,
    WalletType,
    HDWError,
    Path,
    ChildOptions,
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