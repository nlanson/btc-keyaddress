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
mod extended_keys;
mod ckd;

pub use hdwallet::HDWallet;
pub use ckd::derive_xprv;
pub use ckd::derive_xpub;
pub use ckd::ChildOptions;
pub use extended_keys::ExtendedKey;
pub use extended_keys::Xprv;
pub use extended_keys::Xpub;


#[derive(Debug)]
pub enum HDWError {
    IndexTooLarge(String),
    IndexReserved(String),
    CantHarden()
}
