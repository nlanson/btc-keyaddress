/*
    Module that bundles together the various encoding schemes used in Bitcoin
*/

pub mod bs58check;
pub mod bech32;
pub use bs58check::ToVersionPrefix as ToVersionPrefix;