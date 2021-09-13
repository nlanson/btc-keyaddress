use rand::Rng;

use crate::lang;
use crate::rand::rngs::OsRng;

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
    pub fn new(length: PhraseLength, lang: lang::Language) -> Vec<String>{
        let count = match length {
            PhraseLength::Twelve => 12,
            PhraseLength::Fifteen => 15,
            PhraseLength::Eighteen => 18,
            PhraseLength::TwentyOne => 21,
            PhraseLength::TwentyFour => 24
        };

        let mut entropy  = match OsRng::new() {
            Ok(g) => g,
            Err(e) => panic!("Failed to obtain OS RNG: {}", e)
        };
        // println!("Osrng = {:?}", entropy.next_u64());

        let mut bytes = [0 as u8; 16]; //Array of 16 byte sized numbers.
        entropy.try_fill(&mut bytes);
        println!("{:?}", bytes);

        //Placeholder return. This only allows for 256 unique words.
        let mut v: Vec<String> = Vec::with_capacity(count);
        for i in 0..count {
            v.push(lang::en::WORDS[bytes[i] as usize].to_string());
        }
        v

        //Todo:
        // Split byte array into bits and bits into groups of 11 to index words.
    }
}