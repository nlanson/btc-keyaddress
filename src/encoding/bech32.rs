/*
    Module implements bech32 encoding
*/
use bitcoin_bech32::{WitnessProgram, u5};
use bitcoin_bech32::constants::Network;

#[derive(Debug)]
pub enum Bech32Err {
    BadNetwork(),
    CannotEncode()
}

/**
    Takes in either a compressed public key or redeem script and encodes it in
    Bech32.
*/
pub fn encode_to_address(data: &[u8], network: &str) -> Result<String, Bech32Err> {
    let network = match network {
        "testnet" => Network::Testnet,
        "mainnet" => Network::Bitcoin,
        _ => return Err(Bech32Err::BadNetwork())
    };
    
    let data = match WitnessProgram::new(
        u5::try_from_u8(0).unwrap(), //Witness version
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
pub fn encode_to_script_pub_key(data: &[u8], network: &str) -> Result<Vec<u8>, Bech32Err> {
    let network = match network {
        "testnet" => Network::Testnet,
        "mainnet" => Network::Bitcoin,
        _ => return Err(Bech32Err::BadNetwork())
    };
    
    let data = match WitnessProgram::new(
        u5::try_from_u8(0).unwrap(), //Witness version
        data.to_vec(),               //Witness Program  (RedeemScript or PubKey Hash)
                network                     //Network
    ) {
        Ok(x) => x,
        Err(_) => return Err(Bech32Err::CannotEncode())
    };

    Ok(data.to_scriptpubkey())
}