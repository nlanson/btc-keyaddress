/*
    Library to create non-deterministic and 
    deterministic keys and addresses for Bitcoin.

    Not for use with the bitcoin main network.

    References:
        - The Bitcoin Book (https://github.com/bitcoinbook/bitcoinbook/)
            most of the general concepts come from here
        
        - learn me a bitcoin (https://learnmeabitcoin.com/)
            for great visualisation of the concepts inroduced in the book

        - The Rust-Bitcoin repository (https://github.com/rust-bitcoin/rust-bitcoin)
            for providing clear reference code to work against, especially with bip32.

    Todo:
     - Derive child public keys
        Notes:
            https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/bip32.rs
   
     - Make the following files cleaner and error handling easier: (Error enums etc...)
            - extended_keys.rs
            - hdwallet/mod.rs
        
     
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
mod impls;

//Dependencies
use secp256k1::rand::rngs::OsRng as SecpOsRng; //Seperate rand 0.6.0 OsRng used by Secp256k from rand 0.8.0 OsRng
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use hmac::{Mac, NewMac, Hmac};
use pbkdf2::pbkdf2;
use sha2::{Sha256, Sha512, Digest};
use ripemd160::Ripemd160;
use bs58;