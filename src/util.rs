use std::convert::TryInto;
use crate::{
    encoding::bs58check::decode,
    encoding::bs58check::VersionPrefix
};

/*
    Decodes hex strings into a byte vector
*/
pub fn decode_02x(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("Hex decode error"))
        .collect::<Vec<u8>>()
}

/*
    Encodes byte slices into hex string
*/
pub fn encode_02x(bytes: &[u8]) -> String {
    bytes.iter().map(|x| {
        format!("{:02x}", x)
    }).collect::<String>()
}

/**
    Takes in a binary integer as a string and returns it integer value.
*/
pub fn decode_binary_string(b: &str) -> usize {
    usize::from_str_radix(b, 2).unwrap()
}

/**
    Converts a vector into an array
*/
pub fn try_into<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected {}, found {}", N, v.len()))
}

//Converts a byte array to int
pub fn as_u32_be(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 24) +
    ((array[1] as u32) << 16) +
    ((array[2] as u32) <<  8) +
    ((array[3] as u32) <<  0)
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Network {
    Bitcoin,
    Testnet
}

impl Network {
    pub fn from_xkey(key: &str) -> Result<Self, ()> {
        let bytes = match decode(&key.to_string()) {
            Ok(x) => x,
            Err(_) => return Err(())
        };

        let version: u32 = as_u32_be(&try_into(bytes[0..4].to_vec()));
        match VersionPrefix::from_int(version) {
            Ok(x) => match x {
                //Mainnet
                VersionPrefix::Xprv |
                VersionPrefix::Yprv |
                VersionPrefix::Zprv |
                VersionPrefix::Xpub |
                VersionPrefix::Ypub |
                VersionPrefix::Zpub |
                VersionPrefix::SLIP132Yprv |
                VersionPrefix::SLIP132Ypub |
                VersionPrefix::SLIP132Zprv |
                VersionPrefix::SLIP132Zpub => return Ok(Network::Bitcoin),

                //Testnet
                VersionPrefix::Tprv |
                VersionPrefix::Uprv |
                VersionPrefix::Vprv |
                VersionPrefix::Tpub |
                VersionPrefix::Upub |
                VersionPrefix::Vpub |
                VersionPrefix::SLIP132Uprv |
                VersionPrefix::SLIP132Upub |
                VersionPrefix::SLIP132Vprv |
                VersionPrefix::SLIP132Vpub => return Ok(Network::Testnet),
                
                _ => return Err(())
            },
            
            //Return an error if not valid
            _ => return Err(())
        }
    }
}