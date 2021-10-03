/*
    Minimal implementation of P2SH addresses
*/

use crate::{
    hash,
    address::Address,
    key::{
        PrivKey,
        Key,
        PubKey
    }
};

pub struct Script {
    pub script: Vec<u8>
}

#[derive(Debug)]
pub enum ScriptErr {
    BadNetwork(),
    KeyCountDoesNotMatch(),
    MaxKeyCountExceeded()
}

impl Script {
    /**
        Create a new instance of self
    */
    pub fn new(script: Vec<u8>) -> Self {
        Self {
            script
        }
    }

    /**
        Hash the script with Hash160
    */
    pub fn hash(&self) -> [u8; 20] {
        hash::hash160(&self.script)
    }

    /**
        Get the address of the script
    */
    pub fn address(&self, network: &str) -> Result<String, ScriptErr> {
        match network {
            "testnet" => Ok(Address::testnet_script_address(self)),
            "mainnet" => Ok(Address::from_script(self)),
            _ => Err(ScriptErr::BadNetwork())
        }
    }

    /**
        Creates the redeem script for a m-of-n multisig wallet
        BIP-11
    */
    pub fn multisig(m: u8, n: u8, keys: &Vec<PrivKey>) -> Result<Self, ScriptErr> {
        if n != keys.len() as u8 { return Err(ScriptErr::KeyCountDoesNotMatch()) }
        if m > 15 { return Err(ScriptErr::MaxKeyCountExceeded()) }
        
        let mut script: Vec<u8> = vec![m + 80]; //m value as opcode

        for i in 0..keys.len() {
            script.push(0x20);
            script.append(&mut keys[i].as_bytes::<32>().to_vec());
            script.append(&mut PubKey::from_priv_key(&keys[i]).as_bytes::<33>().to_vec())
        }

        script.push(n + 80); //n value as opcode
        script.push(0xAE);   //op_checkmultisig

        Ok(Script::new(script))
    }
}