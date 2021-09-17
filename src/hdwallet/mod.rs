/*
    This module aims to implement hierarchical deterministic wallets
    under the BIP 32 standard.

    Not for use with the bitcoin main network.

    Based on chapter 5 of the bitcoin book. (https://github.com/bitcoinbook/bitcoinbook/)

    Todo:
        - Think about the structure of the HD Wallet.
        - Setup the deriveration of child keys
*/

pub mod extended_keys;
pub mod ckd;
use extended_keys::{
    ExtendedKey,
    Xprv,
    Xpub
};

use crate::{
    bip39::mnemonic::Mnemonic as Mnemonic,
    key::{
        PrivKey,
        PubKey,
        Key
    },
    hash,
    util::try_into
};


pub struct HDWallet {
    pub mnemonic: Mnemonic,
    mpriv_key: Xprv
}

#[derive(Debug)]
pub enum HDWError {
    IndexTooLarge(String),
    IndexReserved(String),
    CantHarden()
}

impl HDWallet {
    /**
        Creates a new HD Wallet structure from mnemonic
    */
    pub fn new(mnemonic: Mnemonic) -> Self {
        let mprivkey_bytes: [u8; 64] = hash::hmac_sha512(&mnemonic.seed(), b"Bitcoin seed");
        let mpriv_key: Xprv = Xprv::construct(
        PrivKey::from_slice(&mprivkey_bytes[0..32]).unwrap(),
        try_into(mprivkey_bytes[32..64].to_vec()),
        0x00,
        [0x00; 4],
        [0x00; 4]
        );

        Self {
            mnemonic,
            mpriv_key
        }
    }

    /**
        Returns the stored extended master private key. Wrapped in a method for consistency.
    */
    pub fn mpriv_key(&self) -> Xprv {
        self.mpriv_key.clone()
    }

    /**
        Get the master extended public key derived from the master extended private key
    */
    pub fn mpub_key(&self) -> Xpub {
        self.mpriv_key().get_xpub()
    }
}


