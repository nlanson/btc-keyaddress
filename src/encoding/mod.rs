/*
    Module that bundles together the various encoding schemes used in Bitcoin
*/

pub mod version_prefix; // Uses external library
pub mod base58;    // Internal implementation
pub mod bech32;
pub use version_prefix::ToVersionPrefix as ToVersionPrefix;