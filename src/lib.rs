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
        - Unit tests for:
            > Path deriveration
            > HDWallets (Single and multi sig)
            > P2SH nested Segwit address generation (Stand alone and in HD Wallets imported from `ypub` keys)
        
        - Multisig HDWallets
            > Finish implementing wallet creation (Checking each key is the same type, converting to account pubs, etc...)
            > Create redeem scripts and addresses from account xpubs.
            > Write path methods similar to single sig HDWallets where the path upto the account is stored in a method
              and if a receiving address needs to be created only the change boolean and address index needs to be supplied.
              The WalletType enum needs to return a path to the account level and from there a method to create a path to the
              address level can be written.
            > Write methods to get account and address level keys and addresses
        
        - P2TR address generation


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