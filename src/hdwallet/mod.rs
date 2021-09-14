/*
    This module aims to implement hierarchical deterministic wallets
    under the BIP 32 standard.

    Not for use with the bitcoin main network.

    Based on chapter 5 of the bitcoin book. (https://github.com/bitcoinbook/bitcoinbook/)
*/

use crate::{
    bip39::mnemonic::Mnemonic as Mnemonic,
    key::{
        PrivKey,
        PubKey
    },
    hash,
    util::try_into
};

pub struct HDWallet {                  //////////////////
    mnemonic: Mnemonic,                // STRUCTURE IS //
    pub master_priv_key: PrivKey,      //   NOT FINAL  //
    pub master_pub_key: PubKey,        //////////////////
    pub master_chaincode: [u8; 32]
}

impl HDWallet {
    /**
        Creates a new HD Wallet structure from mnemonic
    */
    pub fn new(mnemonic: Mnemonic) -> Self {
        let mprivkey_bytes: [u8; 64] = hash::hmac_sha512(&mnemonic.seed);
        let master_priv_key: PrivKey = PrivKey::from_slice(&mprivkey_bytes[0..32]);
        let master_chaincode: [u8; 32] = try_into(mprivkey_bytes[32..64].to_vec());
        let master_pub_key: PubKey = PubKey::from_priv_key(&master_priv_key);

        Self {
            mnemonic,
            master_priv_key,
            master_pub_key,
            master_chaincode
        }
    }
}   