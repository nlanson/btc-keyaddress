use crate::{
    script::{
        RedeemScript,
        ScriptErr,
        ScriptBuilder,
        Opcode
    },
    encoding::bech32::{
        Bech32,
        Bech32Err
    },
    util::Network
};

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
        //Version OP code for anything above 0 needs to add 0x50.
        let mut version = self.version;
        if version > 0 {
            version += 0x50;
        }

        //Redeem script = version | program len | program
        ScriptBuilder::new()
            .push_opcode(Opcode::from(version))
            .push_opcode(Opcode::from(self.program.len() as u8))
            .push_slice(&self.program)
            .into_script()
    }
}