/*
    Script module that implements necessary scripts for creating addresses and
    redeem scripts.
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
    pub code: Vec<u8>
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
    pub fn new(code: Vec<u8>) -> Self {
        Self {
            code
        }
    }

    /**
        Hash the script with Hash160
    */
    pub fn hash(&self) -> [u8; 20] {
        hash::hash160(&self.code)
    }

    /**
        Creates the redeem script for a m-of-n multisig wallet
        BIP-11 and BIP-67 compliant
    */
    pub fn multisig(m: u8, n: u8, keys: &Vec<PubKey>) -> Result<Self, ScriptErr> {
        if n != keys.len() as u8 { return Err(ScriptErr::KeyCountDoesNotMatch()) }
        if m > 15 { return Err(ScriptErr::MaxKeyCountExceeded()) }

        //Sort the private keys in lexiographical order of the public keys (BIP-67)
        let mut keys = keys.clone();
        keys.sort_by(|a, b| {
            a.hex().cmp(&b.hex())
        });
        
        let mut script: Vec<u8> = vec![m + 80]; //m value as opcode

        for i in 0..keys.len() {
            script.push(keys[i].as_bytes::<33>().len() as u8 /*0x21*/);
            script.append(&mut keys[i].as_bytes::<33>().to_vec())
        }

        script.push(n + 80); //n value as opcode
        script.push(0xAE);   //op_checkmultisig

        Ok(Script::new(script))
    }

    /**
        Creates the redeem script for a P2SH nested P2WPKH address
    */
    pub fn p2sh_p2wpkh(pubkey: &PubKey) -> Self {
        let hash = hash::hash160(pubkey.as_bytes::<33>());
        

        //<0 20 <pub key hash>>
        let mut script = vec![0x00, 0x14]; //Witness Version, Pubkey Hash len
        script.append(&mut hash.to_vec());
        
        Script::new(script)
    }

    /**
        Creates the redeem script for a P2SH nested P2WSH address
    */
    pub fn p2sh_p2wsh(script: &Self) -> Self {
        let mut hash = hash::sha256(script.code.clone()).to_vec();

        //<0 32 <script hash>>
        let mut script = vec![0x00, 0x20];
        script.append(&mut hash);

        Script::new(script)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::Address,
        util::Network
    };

    #[test]
    fn bip67_test_vectors() {
        let keys = vec![
            PubKey::from_str("022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da").unwrap(),
            PubKey::from_str("03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9").unwrap(),
            PubKey::from_str("021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18").unwrap(),
        ];

        let script = Script::multisig(2, 3, &keys).unwrap();
        let address = Address::P2SH(script, Network::Bitcoin).to_string().unwrap();

        assert_eq!(address, "3Q4sF6tv9wsdqu2NtARzNCpQgwifm2rAba");
    }
}