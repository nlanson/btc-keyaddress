/*
    This module aims to implement the BIP-39 standard
    for mnemonic phrases.

    Not for use with the bitcoin main network.

    Based on chapter 5 of the bitcoin book. (https://github.com/bitcoinbook/bitcoinbook/)
*/

pub mod lang;
pub mod mnemonic;

pub enum MnemonicErr {
    InvalidWord(String),
    InvalidBits(String),
    InvalidChecksumLen(String),
    ChecksumUnequal()
}