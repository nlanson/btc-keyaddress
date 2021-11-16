use crate::{
    hash,
    util::{
        try_into,
        Network
    },
    encoding::bs58check::VersionPrefix
};


pub struct Base58 {
    data: Vec<u8>
}

pub enum Base58Error {
    InvalidVersionPrefix,
    BadChar(char)
}

impl Base58 {
    pub fn new(data: Vec<u8>) -> Self {
        Base58 { data }
    }
    
    pub fn encode(self) -> String {
        unimplemented!()
    }

    pub fn decode(string: &str) -> Result<Self, Base58Error> {
        unimplemented!()
    }
}