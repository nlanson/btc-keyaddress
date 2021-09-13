use crate::{
    hash,
    util,
    entropy
};
use super::{ 
    lang
};

pub struct Mnemonic {
    phrase: String,
    seed: [u8; 64]
}

pub enum PhraseLength {
    Twelve,
    Fifteen,
    Eighteen,
    TwentyOne,
    TwentyFour
}

impl Mnemonic {
    pub fn new(length: PhraseLength, lang: lang::Language) -> Vec<String> {
        //Create random bits of variable length based on selected phrase length
        let (mut bytes, checksum_len) = match length {
            PhraseLength::Twelve => (entropy::random_bytes(16), 4),     //+4 bit checksum
            PhraseLength::Fifteen => (entropy::random_bytes(20), 5),    //+5 bit checksum
            PhraseLength::Eighteen => (entropy::random_bytes(24), 6),   //+6 bit checksum
            PhraseLength::TwentyOne => (entropy::random_bytes(28), 7),  //+7 bit checksum
            PhraseLength::TwentyFour => (entropy::random_bytes(32), 8)  //+8 bit checksum
        };

        //Hash and extract required bits
        let unmasked_checksum = hash::sha256(&bytes)[0];
        let checksum: u8 = match checksum_len {
            4 => {
                let mask = 0b11110000;
                let masked_checksum = unmasked_checksum & mask;
                masked_checksum >> 4
            },
            5 => {
                let mask = 0b11111000;
                let masked_checksum = unmasked_checksum & mask;
                masked_checksum >> 3
            },
            6 => {
                let mask = 0b11111100;
                let masked_checksum = unmasked_checksum & mask;
                masked_checksum >> 2
            },
            7 => {
                let mask = 0b11111110;
                let masked_checksum = unmasked_checksum & mask;
                masked_checksum >> 1
            },
            8 => {
                unmasked_checksum
            },
            _ => panic!("Invalid checksum length.")
        };

        let mut bit_string = bytes.iter().map(|x| format!("{:08b}", x)).collect::<String>();
        bytes.push(checksum);
        bit_string = format!("{}{:b}", bit_string, checksum);
        let mut phrase: Vec<String> = Vec::with_capacity(bit_string.len()/11);
        for i in 0..bit_string.len()/11 {
            let bits = &bit_string[i..i+11];
            phrase.push(lang.word_list()[util::decode_binary_string(&bits.to_string())].to_string());
        }
        phrase

        //Todo:
        // - Return an instance of struct Mneumonic instaed of Vec<String>
    }
}