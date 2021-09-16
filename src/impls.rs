/**
    This module combines all the boilerplate
    implementations of fmt::Display and more.
*/

use crate::{
    key,
    key::{Key},
    address,
    hdwallet::{
        ckd
    },
    bip39
};
use std::fmt;

/*
    key module impls
*/
impl fmt::Display for key::PrivKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.as_bytes::<32>())
    }
}

impl fmt::Display for key::PubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.as_bytes::<33>())
    }
}

/*
    address module impls
*/
impl fmt::Display for address::Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

/*
    bip39 module impls
*/
impl fmt::Display for bip39::mnemonic::MnemonicErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let val: String = match self {
            Self::ChecksumUnequal() => "Bad checksum".to_string(),
            Self::InvalidBits(x) => x.to_string(),
            Self::InvalidWord(x) => x.to_string(),
            Self::InvalidChecksumLen(x) => x.to_string()
        };
        
        write!(f, "{}", val)
    }
}

impl fmt::Debug for bip39::mnemonic::MnemonicErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MnemonicErr")
         .field("Err:", &self)
         .finish()
    }
}

impl fmt::Display for bip39::mnemonic::Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {        
        write!(f, "{}", self)
    }
}


/*
    hdwallet module impls
*/
impl fmt::Display for ckd::Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let val = match self {
            Self::IndexTooLarge(x) => x,
            Self::IndexReserved(x) => x,
            Self::CantHarden() => "cannot produce hardened child public key"
        };
        
        write!(f, "{}", val)
    }
}