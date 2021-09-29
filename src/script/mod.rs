/*
    Minimal implementation of P2SH addresses
*/

use crate::{
    hash,
    address::Address
};

pub struct RedeemScript {
    pub script: Vec<u8>
}

pub enum ScriptErr {
    BadNetwork()
}

impl RedeemScript {
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
}