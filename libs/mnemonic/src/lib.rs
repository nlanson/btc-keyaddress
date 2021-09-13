/*
    Another library implementing the BIP-0039
    standard.

    Not for use with the bitcoin main network.

    Based on chapter 5 of the bitcoin book. (https://github.com/bitcoinbook/bitcoinbook/)
*/

pub mod lang;
pub mod mnemonic;

pub use rand;

#[cfg(test)]
mod tests {
    use crate::lang::en::WORDS;
    
    #[test]
    fn it_works() {
        assert_eq!(WORDS[6], WORDS[6]);
    }
}
