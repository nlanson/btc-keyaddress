/*
    Module implements bech32 encoding
*/
use crate::{
    util::Network
};

use bitcoin_bech32::{ 
    WitnessProgram,
    u5
};
use bitcoin_bech32::constants::Network as bech32Network;

#[derive(Debug)]
pub enum Bech32Err {
    BadNetwork(),
    CannotEncode()
}

/**
    Takes in either a compressed public key or redeem script and encodes it in
    Bech32.

    The data is either a pubkey hash (p2wpkh) or script hash (p2wsh) or pubkey (taproot).
    The WitnessProgram is created from the data using the given witness version and network.
    Use witness version 0 for P2WPKH and P2WSH. Use verion 1 for P2TR
*/
pub fn encode(witness_version: u8, data: &[u8], network: &Network) -> Result<String, Bech32Err> {
    let network = match network {
        Network::Testnet => bech32Network::Testnet,
        Network::Bitcoin => bech32Network::Bitcoin,
        _ => return Err(Bech32Err::BadNetwork())
    };
    
    let data = match WitnessProgram::new(
        u5::try_from_u8(witness_version).unwrap(), //Witness version
        data.to_vec(),               //Witness Program  (RedeemScript or PubKey Hash)
                network                     //Network
    ) {
        Ok(x) => x,
        Err(_) => return Err(Bech32Err::CannotEncode())
    };

    Ok(data.to_address())
}

/**
    Takes in a compressed public key or redeem script and 
    returns the SegWit script pubkey of it.
*/
pub fn decode_to_script_pub_key(witness_version: u8, data: &[u8], network: &Network) -> Result<Vec<u8>, Bech32Err> {
    let network = match network {
        Network::Testnet => bech32Network::Testnet,
        Network::Bitcoin => bech32Network::Bitcoin,
        _ => return Err(Bech32Err::BadNetwork())
    };
    
    let data = match WitnessProgram::new(
        u5::try_from_u8(witness_version).unwrap(), //Witness version
        data.to_vec(),               //Witness Program  (RedeemScript or PubKey Hash)
                network                     //Network
    ) {
        Ok(x) => x,
        Err(_) => return Err(Bech32Err::CannotEncode())
    };

    Ok(data.to_scriptpubkey())
}