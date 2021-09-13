/*
    Wrapper around the rust-secp256k1 library to 
    create random private keys, public keys and
    addresses in both compressed and uncompressed
    format.

    Not for use with the bitcoin main network.

    Based on chapter 4 of the bitcoin book. (https://github.com/bitcoinbook/bitcoinbook/)

    Todo:
     - bip39::mnemonic::Mnemonic::new() -> return Self instead of Vec<String>
*/

pub mod key;
pub mod address;
pub mod hash;
pub mod bs58check;
pub mod util;
pub mod entropy;
pub mod bip39;

pub use secp256k1::rand::rngs::OsRng as SecpOsRng;
pub use rand::rngs::OsRng;
pub use secp256k1::{PublicKey, Secp256k1, SecretKey};
pub use sha2::{Sha256, Digest};
pub use ripemd160::Ripemd160;
pub use bs58;


/**
    Tests aren't implemented yet.
*/
#[cfg(test)]
mod tests {
    // use sha2::{Sha256, Digest};
    // use crate::{
    //     key::PubKey,
    //     key::PrivKey,
    //     address::Address
    // };

    //Tests unimplemented
    #[test]
    fn tests_work() {
        assert!(2+2 == 4)
    }
}
