/*
    Module that bundles together the various encoding schemes used in Bitcoin
*/

pub mod bs58check; // Uses external library
pub mod base58;    // Internal implementation
pub mod bech32;
pub use bs58check::ToVersionPrefix as ToVersionPrefix;