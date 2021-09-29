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
        - Create HDWallet from a Xprv string (use the provided key as master)
        - Generate array of addresses given a deriveration path and count
            Implement tests and function to create xprv and xpub by count
        - Create P2SH addresses using multisig.
           - Method to take in m of n option and the required keys -> MultiSig redeem Script
           - Hash the script to make the address
        - Create Bech32 addresses
*/

//Outward facing modules
pub mod prelude;
pub mod key;
pub mod address;
pub mod bip39;
pub mod hdwallet;
pub mod script;

//Modules for internal use
mod hash;
mod encoding;
mod util;
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