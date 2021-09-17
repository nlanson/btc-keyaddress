/*
    This module aims to implement the BIP-39 standard
    for mnemonic phrases.

    Not for use with the bitcoin main network.

    Based on chapter 5 of the bitcoin book. (https://github.com/bitcoinbook/bitcoinbook/)
*/

mod lang;
mod mnemonic;

pub use mnemonic::Mnemonic as Mnemonic;
pub use mnemonic::PhraseLength as PhraseLength;
pub use lang::Language as Language;

pub enum MnemonicErr {
    InvalidWord(String),
    InvalidBits(String),
    InvalidChecksumLen(String),
    ChecksumUnequal()
}