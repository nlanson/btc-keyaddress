/**
    This module combines all the boilerplate
    implementations of fmt::Display and more.
*/

use crate::{
    key,
    key::{Key},
    address,
    hdwallet,
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

impl fmt::Display for key::KeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let val: &str = match self {
            Self::BadSlice() => "Bad slice input",
            Self::BadArithmatic() => "Bad arithmatic",
            Self::BadWif() => "Bad WIF",
            Self::BadString() => "Bad string"
        };
        
        write!(f, "{}", val)
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
impl fmt::Display for bip39::MnemonicErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let val: String = match self {
            Self::ChecksumUnequal() => "Bad checksum".to_string(),
            Self::InvalidBits() => "Invalid bits detected".to_string(),
            Self::InvalidWord(x) => format!("Word '{}' at position {} is not valid", x.0, x.1),
            Self::InvalidChecksumLen() => "Invalid checksum".to_string()
        };
        
        write!(f, "{}", val)
    }
}

impl fmt::Debug for bip39::MnemonicErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val: String = match self {
            Self::ChecksumUnequal() => "Bad checksum".to_string(),
            Self::InvalidBits() => "Invalid bits detected".to_string(),
            Self::InvalidWord(x) => format!("Word '{}' at position {} is not valid", x.0, x.1),
            Self::InvalidChecksumLen() => "Invalid checksum".to_string()
        };
        
        f.debug_struct("MnemonicErr")
         .field("Err:", &val)
         .finish()
    }
}

impl fmt::Display for bip39::Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {        
        write!(f, "{}", self)
    }
}


/*
    hdwallet module impls
*/
impl fmt::Display for hdwallet::HDWError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let val = match self {
            Self::IndexTooLarge(x) => format!("The index {} is too large.", x),
            Self::IndexReserved(x) => format!("The index {} is reserved for hardened keys.", x),
            Self::CantHarden() => "cannot produce hardened child public key".to_string(),
            Self::BadKey() => "Cannot use this key. Likely a bad slice.".to_string(),
            Self::BadArithmatic() => "Bad arithmatic.".to_string(),
            Self::BadChar(x) => format!("Bad character at index {}.", x),
            Self::BadChecksum() => "Checksum unequal.".to_string(),
            Self::BadPrefix(x) => format!("Got bad prefix: {:?}.", x),
            Self::BadPath(x) => format!("'{}' is not a valid path.", x),
            Self::WatchOnly => format!("Cannot get the master public key as this wallet is watch only."),
            Self::DefaultError => format!("Method is unsupported for the wallet type."),
            Self::IndexMissing => format!("Index needs to be Some(u32)"),
            Self::MissingFields => format!("One or more missing fields"),
            Self::BadQuorum(q) => format!("Quorum {} is not valid", q),
            Self::TypeDiscrepancy => format!("Wallet type or network does not match")
        };
        
        write!(f, "{}", val)
    }
}