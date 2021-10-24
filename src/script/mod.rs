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
    },
    encoding::bech32::{
        Bech32,
        Bech32Err
    },
    util::Network
};

#[derive(Debug, Clone)]
pub struct RedeemScript {
    pub code: Vec<u8>
}

#[derive(Debug)]
pub enum ScriptErr {
    BadNetwork(),
    KeyCountDoesNotMatch(),
    MaxKeyCountExceeded(),
    HashLenIncorrect(usize),
    BadVersion(u8)
}

impl RedeemScript {
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
        Creates a new witness program given a version and data.

        For P2WPKH, version is 0 and data is the Hash160 of the public key.
        For P2WSH, version is 0 and data is the SHA256 of the redeem script.
    */
    pub fn witness_program(version: u8, data: Vec<u8>) -> Result<Self, ScriptErr>{
        if version > 16 { return Err(ScriptErr::BadVersion(version)) }

        let mut witprog: Vec<u8> = vec![version, data.len() as u8];
        witprog.extend_from_slice(&data);

        Ok(Self::new(witprog))
    }

    /**
        Creates the redeem script for a m-of-n multisig wallet
        BIP-11 and BIP-67 compliant
    */
    pub fn multisig(m: u8, keys: &Vec<PubKey>) -> Result<Self, ScriptErr> {
        let n = keys.len() as u8;
        if n != keys.len() as u8 { return Err(ScriptErr::KeyCountDoesNotMatch()) }
        if m > 15 { return Err(ScriptErr::MaxKeyCountExceeded()) }

        //Sort the private keys in lexiographical order of the public keys (BIP-67)
        let mut keys = keys.clone();
        keys.sort();
        
        let mut script: Vec<u8> = vec![m + 80]; //m value as opcode

        for i in 0..keys.len() {
            script.push(keys[i].as_bytes::<33>().len() as u8 /*0x21*/);
            script.append(&mut keys[i].as_bytes::<33>().to_vec())
        }

        script.push(n + 80); //n value as opcode
        script.push(0xAE);   //op_checkmultisig

        Ok(RedeemScript::new(script))
    }

    /**
        Creates the redeem script for a P2SH nested P2WPKH address

        OP_0  PUSH_BYTES_0x14  20 BYTE PUB KEY HASH
    */
    pub fn p2sh_p2wpkh(pubkey: &PubKey) -> Self {
        let hash = hash::hash160(pubkey.as_bytes::<33>());
        

        //<0 20 <pub key hash>>
        let mut script = vec![0x00, 0x14]; //Witness Version, Pubkey Hash len
        script.append(&mut hash.to_vec());
        
        RedeemScript::new(script)
    }

    /**
        Creates the redeem script for a P2SH nested P2WSH address

        OP_0  PUSH_BYTES_0x20 32 BYTE SCRIPT HASH
    */
    pub fn p2sh_p2wsh(script: &Self) -> Self {
        let mut hash = hash::sha256(script.code.clone()).to_vec();

        //<0 32 <script hash>>
        let mut script = vec![0x00, 0x20];
        script.append(&mut hash);

        RedeemScript::new(script)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct WitnessProgram {
    pub version: u8,
    pub program: Vec<u8>
}

impl WitnessProgram {
    /**
        Creates a new witness program given a version and data.

        For P2WPKH, version is 0 and data is the Hash160 of the public key.
        For P2WSH, version is 0 and data is the SHA256 of the redeem script.
    */
    pub fn new(version: u8, data: Vec<u8>) -> Result<Self, ScriptErr>{
        if version > 16 { return Err(ScriptErr::BadVersion(version)) }
        
        Ok(Self {
            version,
            program: data
        })
    }

    pub fn to_address(&self, network: &Network) -> Result<String, Bech32Err> {
        let hrp = match network {
            Network::Bitcoin => "bc".to_string(),
            Network::Testnet => "tb".to_string()
        };
        
        let mut data = vec![self.version];
        data.extend_from_slice(&self.program);

        let encoder = Bech32::from_witness_program(&hrp, self);
        match self.version {
            0 => encoder.bech32(),
            _ => encoder.bech32m()
        }
    }

    pub fn from_address(address: &str) -> Result<Self, Bech32Err> {
        Ok( Bech32::to_witness_program(address)? )
    }

    pub fn to_scriptpubkey(&self) -> RedeemScript {
        let mut pubkey: Vec<u8> = Vec::new();
        
        //Version OP code for anything above 0 needs to add 0x50.
        let mut version = self.version;
        if version > 0 {
            version += 0x50;
        }

        //Redeem script = version | program len | program
        pubkey.push(version);
        pubkey.push(self.program.len() as u8);
        pubkey.extend_from_slice(&self.program);
        
        RedeemScript::new(pubkey)
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

        let script = RedeemScript::multisig(2, &keys).unwrap();
        let address = Address::P2SH(script, Network::Bitcoin).to_string().unwrap();

        assert_eq!(address, "3Q4sF6tv9wsdqu2NtARzNCpQgwifm2rAba");
    }
}