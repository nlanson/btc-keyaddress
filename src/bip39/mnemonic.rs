use std::fmt;
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

pub enum MnemonicErr {
    InvalidWord(String),
    InvalidBits(String),
    ChecksumUnequal()
}


impl Mnemonic {
    /**
        Creates a mnemonic struct that includes the phrase and derived seed.
        * CURRENTLY ONLY RETURNS A NEW SEED AS A VECTOR
    */
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
        bit_string = Self::append_checksum_to_bitstring(&bit_string, &checksum); //Add the checksum at the end of the bit string

        //Iterate over the bite string, step by 11.
        //Every step, extract the string at index i to i+11 (representing the 11 bits to index the word list)
        //Convert the 11 bit string to an integer and push the seed phrase at that index into a vec.
        let mut phrase: Vec<String> = Vec::with_capacity(bit_string.len()/11);
        let mut i: usize = 0;
        while phrase.len() != bit_string.len()/11 {
            let bits = &bit_string[i..i+11];
            phrase.push(lang.word_list()[util::decode_binary_string(&bits.to_string())].to_string());
            i += 11;
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

    /**
        Add the required amount of bits from the checksum to the bit string provided.
    */
    fn append_checksum_to_bitstring(bit_string: &String, checksum: &u8) -> String {
        match bit_string.len() {
            128 => format!("{}{:04b}", bit_string, checksum),
            160 => format!("{}{:05b}", bit_string, checksum),
            192 => format!("{}{:06b}", bit_string, checksum),
            224 => format!("{}{:07b}", bit_string, checksum),
            256 => format!("{}{:08b}", bit_string, checksum),
            _ => panic!("Invalid bit string length")
        }
    }

    pub fn from_phrase(phrase: String, lang: lang::Language) -> Result<Self, MnemonicErr> {
        let words: Vec<&str> = phrase.split_whitespace().collect();
         match Self::verify_phrase(&words, &lang) {
             Ok(()) => {
                //Continue to hash the seed and construct Mnemonic struct
             },
             Err(x) => return Err(x)
         }
        
        unimplemented!();
        /*
            This function will take in a string of words, split it by whitespace and convert
            the phrase list back to entropy.

            Steps:
                - split string by whitespace.
                - find index value of each word in word list
                - for each index, convert it to binary and push into a single string
                - Remove and store the last however many bits from the bit string to use later (based on word count)
                - Loop over the bit string, stepping by 8 converting each section of the string
                  to hex and collecting it in a byte array.
                - Hash the byte array and compare the first however many bits to the previously stored
                  and removed bits. If they are the same then the phrase is valid

        */
    }

    /*
        Verifies that a seed phrase is valid
    */
    pub fn verify_phrase(words: &Vec<&str>, lang: &lang::Language) -> Result<(), MnemonicErr> {
        let word_list = lang.word_list();
        
        //Iterate over the split phrase, and find the index of the word in the word list.
        //If the word list does not contain a word, return false.
        let indexes: Vec<usize> = words.iter().map(|x| {
            if word_list.contains(&x) {
                return word_list.iter().position(|i| i == x).unwrap();
            }
            return 0x11111111111; //2048 is a flag to indicate word does  not exist.
        }).collect::<Vec<usize>>();
        if indexes.contains(&2048) { return Err(MnemonicErr::InvalidWord("INSERT WRONG WORD HERE".to_string())) }
        
        //Convert the indexes into a bit string. If the bit string divided by 11 has a remainder return false
        let mut bit_string: String = indexes.iter().map(|x| {
            format!("{:011b}", x)
        }).collect::<String>();
        if bit_string.len()%11 != 0 { return Err(MnemonicErr::InvalidBits(format!("{} is not a valid bit length", bit_string.len()))) }
        
        //Remove the checksum from the bit string and store it to cross check later.
        let checksum_len: usize = match bit_string.len() {
            132 => 4,
            165 => 5,
            198 => 6,
            231 => 7,
            264 => 8,
            _ => return Err(MnemonicErr::InvalidBits(format!("{} is not a valid bit length", bit_string.len())))
        };
        let extracted_checksum: u8  = util::decode_binary_string(&bit_string[bit_string.len()-checksum_len..bit_string.len()].to_string()) as u8;
        bit_string.replace_range(bit_string.len()-checksum_len..bit_string.len(), "");

        //Collect the bit string into a byte vector
        let mut bytes: Vec<u8> = vec![];
        for i in (0..bit_string.len()).step_by(8) {
            bytes.push(util::decode_binary_string(&bit_string[i..i+8].to_string()) as u8)
        }

        //Hash the bytes and calculate the checksum
        let unmasked_checksum = hash::sha256(&bytes)[0];
        let calculated_checksum: u8 = Self::mask_checksum(unmasked_checksum, checksum_len as u8);

        //Compare the calculated and extracted checksums
        if calculated_checksum == extracted_checksum { return Ok(()) }

        Err(MnemonicErr::ChecksumUnequal())
    }
}

impl fmt::Display for MnemonicErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let val: String = match self {
            Self::ChecksumUnequal() => "Bad checksum".to_string(),
            Self::InvalidBits(x) => x.to_string(),
            Self::InvalidWord(x) => x.to_string()

        };
        
        write!(f, "{}", val)
    }
}