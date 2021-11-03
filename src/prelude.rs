/*
    This module contains the default imports for the library.

    Import the library using:
        use btc_keyaddress::prelude::*;
    to quickly import the essential parts of the library.
*/

pub use crate::{

    key::{
        PubKey,
        PrivKey,
        Key
    },
    
    address::Address,

    bip39::{
        MnemonicErr,
        Language,
        Mnemonic,
        PhraseLength
    },

    hdwallet::{
        HDWalletBuilder,
        HDWallet,
        ChildOptions,
        ExtendedKey,
        Xprv, Xpub,
        HDWError,
        Path,
        WalletType,
        Unlocker,
        MultisigHDWallet,
        MultisigHDWalletBuilder,
        MultisigWalletType
    }, 

    encoding::{
        bs58check::{
            VersionPrefix,
            ToVersionPrefix
        }
    },

    util::{
        encode_02x,
        decode_02x,
        try_into,
        Network
    },

    script::RedeemScript,

    taproot::*

};