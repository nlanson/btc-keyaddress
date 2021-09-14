/*
    Wrapper around the rust-secp256k1 library to 
    create random private keys, public keys and
    addresses in both compressed and uncompressed
    format.

    Not for use with the bitcoin main network.

    Based on chapter 4 of the bitcoin book. (https://github.com/bitcoinbook/bitcoinbook/)

    Todo:
     - Start implementing HD wallets
        Notes:
            https://learnmeabitcoin.com/technical/hd-wallets
            
     - Investigate why Base58 module does not encode ExtendedKey prefixes correctly
            
*/

//Outward facing modules
pub mod key;
pub mod address;
pub mod bip39;
pub mod hdwallet;

//Modules for internal use
mod hash;
mod bs58check;
pub mod util;
mod entropy;

//Dependencies
use secp256k1::rand::rngs::OsRng as SecpOsRng; //Seperate rand 0.6.0 OsRng used by Secp256k from rand 0.8.0 OsRng
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use hmac::{Mac, NewMac, Hmac};
use pbkdf2::pbkdf2;
use sha2::{Sha256, Sha512, Digest};
use ripemd160::Ripemd160;
use bs58;


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
