/*
    Module that bundles together the various encoding schemes used in Bitcoin
*/

pub mod version_prefix;
pub mod base58;
pub mod bech32;
pub use version_prefix::ToVersionPrefix as ToVersionPrefix;