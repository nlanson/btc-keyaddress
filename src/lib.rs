/*
    Library to created to learn about Bitcoin keys, addresses, script and more.
    The library is not the best Bitcoin implementation, but it is a good reference 
    to learn about how Bitcoin keys, addresses, scripts and work.

    Not for use with the bitcoin main network.

    References:
        - The Bitcoin Book (https://github.com/bitcoinbook/bitcoinbook/)
            most of the general concepts come from here
        
        - learn me a bitcoin (https://learnmeabitcoin.com/)
            for great visualisation of the concepts inroduced in the book

        - The Rust-Bitcoin repository (https://github.com/rust-bitcoin/rust-bitcoin)
            for providing clear reference code to work against, especially with bip32.
        
        - The gods of the Bitcoin Stackexchange and Stackoverflow.

    Todo:
        - Unit tests for:
            > Path deriveration
            > HDWallets (Single and multi sig)
            > P2SH nested Segwit address generation (Stand alone and in HD Wallets imported from `ypub` keys)
            > Version prefix conversion (Key to prefix, int to prefix, etc..)
        
        - HDWallets
            > Better unlocker for multisig hd wallets
            > Custom path tests
            > Taproot standard HDMultisig (?)
            
        
        - Taproot
            > Script tree value use Enum instead of Option
            > Struct for spending data which consists of
                - Internal Key
                - Optional script tree and parity bit
                - [...]

        - Base58 encoding
            > Use the internal implementation of the base58 in the library for addresses, keys and extended keys.

        - Automated github tests
*/

//Outward facing modules
pub mod prelude;
pub mod key;
pub mod address;
pub mod bip39;
pub mod hdwallet;
pub mod script;
pub mod taproot;

//Modules for internal use
mod hash;
mod encoding;
mod util;
mod entropy;
mod impls;

//Dependencies
use secp256k1::rand::rngs::OsRng as SecpOsRng; //Seperate rand 0.6.0 OsRng used by Secp256k from rand 0.8.0 OsRng
use rand::rngs::OsRng;
use secp256k1::{ PublicKey, Secp256k1, SecretKey };
use secp256k1::schnorrsig::{ KeyPair as lib_SchnorrKeyPair, PublicKey as lib_SchnorrPublicKey };
use hmac::{ Mac, NewMac, Hmac };
use pbkdf2::pbkdf2;
use sha2::{ Sha256, Sha512, Digest };
use ripemd160::Ripemd160;
use bs58;