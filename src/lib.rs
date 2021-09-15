/*
    Wrapper around the rust-secp256k1 library to 
    create random private keys, public keys and
    addresses in both compressed and uncompressed
    format.

    Not for use with the bitcoin main network.

    Based on chapter 4 of the bitcoin book. (https://github.com/bitcoinbook/bitcoinbook/)

    Todo:
     - Start implementing HD wallets, specifically the deriveration of child keys.
        Notes:
            https://learnmeabitcoin.com/technical/hd-wallets
            https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch05.asciidoc
            https://learnmeabitcoin.com/technical/extended-keys
        
        Need to investigate why derived keys are not equalling the expected derived key.
     
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
use num_bigint::{BigInt, Sign};
use hmac::{Mac, NewMac, Hmac};
use pbkdf2::pbkdf2;
use sha2::{Sha256, Sha512, Digest};
use ripemd160::Ripemd160;
use bs58;