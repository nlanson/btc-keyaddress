use crate::{
    hash,
    key::{
        Key,
        PubKey
    },
    script::{
        ScriptBuilder,
        Opcode,
        opcodes
    },
    util::decode_02x
};

#[derive(Hash, Debug, Clone, PartialEq, Eq)]
pub struct RedeemScript {
    pub code: Vec<u8>     //Later this can be updated to use [Opcode]
}

#[derive(Debug)]
pub enum ScriptErr {
    BadNetwork(),
    KeyCountDoesNotMatch(),
    MaxKeyCountExceeded(),
    HashLenIncorrect(usize),
    BadVersion(u8),
    InvalidString
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

    /// Return the underlying byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        self.code.clone()
    }

    /// Create a new instance of self from a hexadecimal string
    pub fn from_str(hex: &str) -> Self {
        Self::new(decode_02x(hex))
    }

    /// Returns a byte vector of the script prefixed with it's length in compact size.
    pub fn prefix_compactsize(&self) -> Vec<u8> {
        let len = self.code.len();
        let mut compact_size: Vec<u8> = vec![];
        if len <= 252 {
            compact_size = vec![len as u8];
        } else if len <=0xffff {
            compact_size = vec![0xfd];
            let mut len = len.to_le_bytes().to_vec();
            len.truncate(2);
            compact_size.extend_from_slice(&len);
        }
        
        let mut prefixed = compact_size;
        prefixed.extend_from_slice(&self.code);
        prefixed
    }

    pub fn to_string(&self) -> String {
        crate::util::encode_02x(&self.code)
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

    
    ///Creates the redeem script for a m-of-n multisig wallet
    ///BIP-11 and BIP-67 compliant
    pub fn multisig(m: u8, keys: &Vec<PubKey>) -> Result<Self, ScriptErr> {
        let n = keys.len() as u8;
        if n != keys.len() as u8 { return Err(ScriptErr::KeyCountDoesNotMatch()) }
        if m > 15 { return Err(ScriptErr::MaxKeyCountExceeded()) }

        //Sort the private keys in lexiographical order of the public keys (BIP-67)
        let mut keys = keys.clone();
        keys.sort();

        let mut builder = ScriptBuilder::new().push_opcode(Opcode::from(m+80));
        
        for i in 0..keys.len() {
            builder = builder.push_opcode(opcodes::OP_PUSHBYTES_33);
            builder = builder.push_slice(&keys[i].as_bytes::<33>());
        }

        builder = builder.push_opcode(Opcode::from(n+80));
        builder = builder.push_opcode(opcodes::OP_CHECKMULTISIG);

        Ok(builder.into_script())
    }

    /// P2PKH script pub key
    /// OP_DUP OP_HASH160 <Pubkey Hash> OP_EQUALVERIFY OP_CHECKSIG
    pub fn p2pkh(pubkey: &PubKey) -> Self {
        let hash = hash::hash160(pubkey.as_bytes::<33>());
        ScriptBuilder::new()
            .push_opcode(opcodes::OP_DUP)
            .push_opcode(opcodes::OP_HASH160)
            .push_slice(&hash)
            .push_opcode(opcodes::OP_EQUALVERIFY)
            .push_opcode(opcodes::OP_CHECKSIG)
            .into_script()
    }

    /// P2SH script pub key
    /// OP_HASH160 <Hash160(redeemScript)> OP_EQUAL
    pub fn p2sh(script: &Self) -> Self {
        let hash = hash::hash160(&script.code);
        ScriptBuilder::new()
            .push_opcode(opcodes::OP_HASH160)
            .push_slice(&hash)
            .push_opcode(opcodes::OP_EQUAL)
            .into_script()
    }

    /// P2WPKH script pub key
    /// 0x0014 <20-byte-pubkey-hash>
    pub fn p2wpkh(pubkey: &PubKey) -> Self {
        let hash = hash::hash160(pubkey.as_bytes::<33>());
        ScriptBuilder::new()
            .push_opcode(opcodes::OP_PUSHBYTES_0)
            .push_opcode(opcodes::OP_PUSHBYTES_20)
            .push_slice(&hash)
            .into_script()
    }

    /// P2WSH script pub key
    /// 0x0020 <32-byte-script-hash>
    pub fn p2wsh(script: &Self) -> Self {
        let hash = hash::sha256(&script.code).to_vec();
        ScriptBuilder::new()
            .push_opcode(opcodes::OP_PUSHBYTES_0)
            .push_opcode(opcodes::OP_PUSHBYTES_32)
            .push_slice(&hash)
            .into_script()
    }
}