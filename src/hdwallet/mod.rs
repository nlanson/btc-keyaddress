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
use extended_keys::{
    ExtendedKey,
    ExtendedPrivateKey,
    ExtendedPublicKey
};

use crate::{
    bip39::mnemonic::Mnemonic as Mnemonic,
    key::{
        PrivKey,
        PubKey,
        Key
    },
    hash
};


pub struct HDWallet {
    pub mnemonic: Mnemonic,
    pub mpriv_key: ExtendedPrivateKey
}

impl HDWallet {
    /**
        Creates a new HD Wallet structure from mnemonic
    */
    pub fn new(mnemonic: Mnemonic) -> Self {
        let mprivkey_bytes: [u8; 64] = hash::hmac_sha512(&mnemonic.seed(), b"Bitcoin seed");
        let mpriv_key: ExtendedPrivateKey = ExtendedPrivateKey::construct(
        PrivKey::from_slice(&mprivkey_bytes[0..32]),
        &mprivkey_bytes[32..64]
        );

        Self {
            mnemonic,
            mpriv_key
        }
    }

    /**
        Get the master extended public key derived from the master extended private key
    */
    pub fn mpub_key(&self) -> ExtendedPublicKey {
        let privk: PrivKey = PrivKey::from_slice(&self.mpriv_key.key::<32>());
        let chaincode: [u8; 32] = self.mpriv_key.chaincode();
        let pubk: PubKey = PubKey::from_priv_key(&privk);

        ExtendedPublicKey::construct(pubk, &chaincode)
    }
}


