use crate::{
    hash,
    util,
    entropy
};
use super::{ 
    lang
};

pub struct Mnemonic {
    phrase: String,  //The mnemonic phrase
    seed: [u8; 64]   //The seed key (512 bits)
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
        //Create random byte arrays of variable length based on selected phrase length
        let (bytes, checksum_len) = match length {
            PhraseLength::Twelve => (entropy::random_bytes(16), 4),     //+4 bit checksum
            PhraseLength::Fifteen => (entropy::random_bytes(20), 5),    //+5 bit checksum
            PhraseLength::Eighteen => (entropy::random_bytes(24), 6),   //+6 bit checksum
            PhraseLength::TwentyOne => (entropy::random_bytes(28), 7),  //+7 bit checksum
            PhraseLength::TwentyFour => (entropy::random_bytes(32), 8)  //+8 bit checksum
        };

        //Hash and extract required bits
        let unmasked_checksum = hash::sha256(&bytes)[0];
        let checksum: u8 = Self::mask_checksum(unmasked_checksum, checksum_len);

        //Create a string to store the binary bits of each byte generated earlier
        let mut bit_string = bytes.iter().map(|x| format!("{:08b}", x)).collect::<String>();
        bit_string = format!("{}{:b}", bit_string, checksum); //Add the checksum at the end of the bit string

        //Iterate over the bite string, step by 11.
        //Every step, extract the string at index i to i+11 (representing the 11 bits to index the word list)
        //Convert the 11 bit string to an integer and push the seed phrase at that index into a vec.
        let mut phrase: Vec<String> = Vec::with_capacity(bit_string.len()/11);
        for i in 0..bit_string.len()/11 {
            let bits = &bit_string[i..i+11];
            phrase.push(lang.word_list()[util::decode_binary_string(&bits.to_string())].to_string());
        }
        phrase

        //Todo:
        // - Return an instance of struct Mneumonic instaed of Vec<String>
        // - This means running the mnemonic + passphrase(if there is one) though PBKDF2(HMAC SHA512) to get the seed key.
    }

    /**
        Masks the checksum byte to extract required bits
    */
    fn mask_checksum(unmasked_checksum: u8, bits_required: u8) -> u8 {
        let checksum: u8 = match bits_required {
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

        checksum
    }
}