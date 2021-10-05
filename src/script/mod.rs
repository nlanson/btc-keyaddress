/*
    Minimal implementation of P2SH addresses
*/

use crate::{
    hash,
    key::{
        PrivKey,
        Key,
        PubKey
    }
};

#[derive(Debug, Clone)]
pub struct Script {
    pub script: Vec<u8>
}

#[derive(Debug)]
pub enum ScriptErr {
    BadNetwork(),
    KeyCountDoesNotMatch(),
    MaxKeyCountExceeded(),
    HashLenIncorrect(usize)
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
        Creates the redeem script for a m-of-n multisig wallet
        BIP-11
    */
    pub fn multisig(m: u8, n: u8, keys: &Vec<PrivKey>) -> Result<Self, ScriptErr> {
        if n != keys.len() as u8 { return Err(ScriptErr::KeyCountDoesNotMatch()) }
        if m > 15 { return Err(ScriptErr::MaxKeyCountExceeded()) }
        
        let mut script: Vec<u8> = vec![m + 80]; //m value as opcode

        for i in 0..keys.len() {
            script.push(PubKey::from_priv_key(&keys[i]).as_bytes::<33>().len() as u8 /*0x21*/);
            script.append(&mut PubKey::from_priv_key(&keys[i]).as_bytes::<33>().to_vec())
        }

        script.push(n + 80); //n value as opcode
        script.push(0xAE);   //op_checkmultisig

        Ok(Script::new(script))
    }

    /**
        Creates the redeem script for a P2SH nested P2WPKH address
    */
    pub fn p2sh_p2wpkh(hash: &[u8]) -> Result<Self, ScriptErr> {
        if hash.len() != 20 { return Err(ScriptErr::HashLenIncorrect(hash.len())) }

        //<0 20 <pub key hash>>
        let mut script = vec![0x00, 0x14]; //Witness Version, Pubkey Hash len
        script.append(&mut hash.to_vec());
        
        Ok(Script::new(script))
    }
}