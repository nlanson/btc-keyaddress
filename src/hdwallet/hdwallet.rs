use crate::{
    bip39::Mnemonic,
    key::{
        PrivKey,
        PubKey,
        Key
    },
    hdwallet::{
        ExtendedKey, Xprv, Xpub, 
        HDWError
    },
    hash,
    util::try_into
};


pub struct HDWallet {
    pub mnemonic: Mnemonic,
    mpriv_key: Xprv
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