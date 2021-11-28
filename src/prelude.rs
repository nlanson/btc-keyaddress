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
        Key,
        TapTweak,
        KeyError
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
        version_prefix::{
            VersionPrefix,
            ToVersionPrefix
        },
        base58::{
            Base58,
            Base58Error
        },
        bech32::{
            Bech32,
            Bech32Err,
            Format
        }
    },

    util::{
        encode_02x,
        decode_02x,
        try_into,
        Network
    },

    script::{
        RedeemScript,
        WitnessProgram,
        ScriptBuilder,
        ScriptErr,
        opcodes,
        Opcode
    },

    taproot::*

};