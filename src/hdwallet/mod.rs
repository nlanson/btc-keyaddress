/*
    This module aims to implement hierarchical deterministic wallets
    under the BIP 32 standard.

    Not for use with the bitcoin main network.

    Based on chapter 5 of the bitcoin book. (https://github.com/bitcoinbook/bitcoinbook/)

    Todo:
        - Think about the structure of the HD Wallet.
        - Setup the deriveration of child keys
*/

mod hdwallet;
mod hdmultisig;
mod extended_keys;
mod ckd;
mod path;

//Singlesig HDWallet
pub use hdwallet::HDWalletBuilder;
pub use hdwallet::HDWallet;
pub use hdwallet::Unlocker;
pub use hdwallet::WalletType;

//Multisig HDWallet
pub use hdmultisig::MultisigHDWallet;
pub use hdmultisig::MultisigWalletType;
pub use hdmultisig::MultisigHDWalletBuilder;

//Util
pub use path::Path;
pub use ckd::ChildOptions;
pub use extended_keys::ExtendedKey;
pub use extended_keys::Xprv;
pub use extended_keys::Xpub;



#[derive(Debug, PartialEq)]
pub enum HDWError {
    IndexTooLarge(u32),
    IndexReserved(u32),
    CantHarden(),
    BadKey(),
    BadArithmatic(),
    BadChar(usize),
    BadChecksum(),
    BadPrefix(Vec<u8>),
    BadPath(String),
    WatchOnly,
    DefaultError,
    IndexMissing,
    MissingFields,
    BadQuorum(u8),
    TypeDiscrepancy
}
