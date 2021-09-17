use crate::{
    hash,
    util,
    entropy
};
use super::{ 
    lang,
    MnemonicErr
};

#[derive(Clone)]
pub struct Mnemonic {
    pub phrase: Vec<String>,     //The mnemonic phrase
    pub passphrase: String       //The passphrase
}

pub enum PhraseLength {
    Twelve,
    Fifteen,
    Eighteen,
    TwentyOne,
    TwentyFour
}


impl Mnemonic {
    /**
        Creates a mnemonic struct that includes the phrase and derived seed.
    */
    pub fn new(length: PhraseLength, lang: lang::Language, passphrase: &str) -> Result<Self, MnemonicErr> {
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
        let checksum: u8 = match Self::mask_checksum(unmasked_checksum, checksum_len) {
            Ok(x) => x,
            Err(x) => return Err(x)
        };

        //Create a string to store the binary bits of each byte generated earlier
        let mut bit_string = bytes.iter().map(|x| format!("{:08b}", x)).collect::<String>();
        bit_string = match Self::append_checksum_to_bitstring(&bit_string, &checksum) { //Add the checksum at the end of the bit string
            Ok(x) => x,
            Err(x) => return Err(x)
        }; 

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
        
        //Get the seed and return
        Ok(
            Self {
            phrase: phrase.clone(),
            passphrase: passphrase.to_string()
            }
        )
    }

    /**
        Creates a mnemonic from phrase only if the phrase is valid.
    */
    pub fn from_phrase(phrase: String, lang: lang::Language, passphrase: &str) -> Result<Self, MnemonicErr> {
        let words: Vec<String> = phrase.split_whitespace().collect::<Vec<&str>>().iter().map(|x| x.to_string()).collect(); //Cannot create Vec<String> from &str iterator so have to create Vec<&str>, then create Vec<String> from there.
         match Self::verify_phrase(&words, &lang) {
             Ok(()) => {
                //Continue to hash the seed and construct Mnemonic struct
             },
             //If cannot verify then return error.
             Err(x) => return Err(MnemonicErr::ChecksumUnequal())//return Err(x) #REPLACE
         }

         Ok(
            Self {
                phrase: words,
                passphrase: passphrase.to_string()
            }
        )
    }

    /*
        Verifies that a seed phrase is valid
    */
    pub fn verify_phrase(words: &Vec<String>, lang: &lang::Language) -> Result<(), MnemonicErr> {
        let word_list = lang.word_list();
        
        //Iterate over the split phrase, and find the index of the word in the word list.
        //If the word list does not contain a word, return false.
        let indexes: Vec<usize> = words.iter().map(|x| {
            if word_list.contains(&&x[..]) {
                return word_list.iter().position(|i| i == x).unwrap();
            }
            return 0x11111111111; //2048 is a flag to indicate word does  not exist.
        }).collect::<Vec<usize>>();
        if indexes.contains(&0x11111111111) { return Err(MnemonicErr::InvalidWord("Invalid word detected".to_string())) }
        

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
        let calculated_checksum: u8 = match Self::mask_checksum(unmasked_checksum, checksum_len as u8) {
            Ok(x) => x,
            Err(x) => return Err(x)
        };

        //Compare the calculated and extracted checksums
        if calculated_checksum == extracted_checksum { return Ok(()) }

        
        Err(MnemonicErr::ChecksumUnequal())
    }

    /**
        This method returns the seed of the mnemonic phrase.

        This is done by passing the phrase and passphrase through
        a key stretching function PBKDF2.

        This seed is used by BIP32 as the root seed.
    */
    pub fn seed(&self) -> [u8; 64] {
        hash::pbkdf2_hmacsha512(&self.phrase, &self.passphrase)
    }

    /**
        Masks the checksum byte to extract required bits
    */
    fn mask_checksum(unmasked_checksum: u8, bits_required: u8) -> Result<u8, MnemonicErr> {
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
            _ => return Err(MnemonicErr::InvalidChecksumLen(format!("Bad checksum length")))
        };

        Ok(checksum)
    }

    /**
        Add the required amount of bits from the checksum to the bit string provided.
    */
    fn append_checksum_to_bitstring(bit_string: &String, checksum: &u8) -> Result<String, MnemonicErr> {
        let appended = match bit_string.len() {
            128 => format!("{}{:04b}", bit_string, checksum),
            160 => format!("{}{:05b}", bit_string, checksum),
            192 => format!("{}{:06b}", bit_string, checksum),
            224 => format!("{}{:07b}", bit_string, checksum),
            256 => format!("{}{:08b}", bit_string, checksum),
            _ => return Err(MnemonicErr::InvalidBits("Invalid bit string length".to_string()))
        };

        Ok(appended)
    }
}

#[cfg(test)]
mod tests {
    use crate::bip39::mnemonic::MnemonicErr;

    use super::{
        Mnemonic,
        PhraseLength,
        lang::Language,
        util::decode_02x,
        util::try_into
    };

    //Test data to use in non-random tests
    const TEST_PHRASE: &str = "army van defense carry jealous true garbage claim echo media make crunch";
    const PASSPHRASE: &str = "SuperDuperSecret";
    const TEST_SEED_HEX_NO_PASS: &str = "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570";
    const TEST_SEED_HEX_WITH_PASS: &str = "3b5df16df2157104cfdd22830162a5e170c0161653e3afe6c88defeefb0818c793dbb28ab3ab091897d0715861dc8a18358f80b79d49acf64142ae57037d1d54";

    //Create new Mnemonic struct from test data
    fn test_mnemonic(passphrase: &str) -> Mnemonic {
        Mnemonic::from_phrase(TEST_PHRASE.to_string(), Language::English, passphrase).unwrap()
    }

    #[test]
    fn mnemonic_tests() {
        let mnemonic_no_passphrase: Mnemonic = test_mnemonic("");
        let mnemonic_with_passphrase: Mnemonic = test_mnemonic(PASSPHRASE);
        let expected_seed_without_passphrase: [u8; 64] = try_into(decode_02x(TEST_SEED_HEX_NO_PASS));
        let expected_seed_with_passphrase: [u8; 64] = try_into(decode_02x(TEST_SEED_HEX_WITH_PASS));

        //Check if the seed is 64 bytes and derives properly.
        assert_eq!(mnemonic_no_passphrase.seed().len(), 64);
        assert_eq!(mnemonic_no_passphrase.seed(), expected_seed_without_passphrase);
        assert_eq!(mnemonic_with_passphrase.seed(), expected_seed_with_passphrase);
    }

    #[test]
    fn mnemonic_bad_checksum() {
        let bad_phrase: Vec<String> = "health maximum alcohol orange sugar spin era wash rely abuse liar govern"
            .to_string().split_whitespace().collect::<Vec<&str>>().iter().map(|x| x.to_string()).collect();
        
        //Verify that the bad_phrase returns ChecksumUnequal
        let result = match Mnemonic::verify_phrase(&bad_phrase, &Language::English) {
            Err(_) => true,
            _ => false
        };
        
        assert!(result);
    }

    #[test]
    fn random_mnemonic_tests() {
        //Creates and verifies 5 random mnemonics.
        //Test fails if one of the random mnemonics fails verification
        for _i in 0..5 {
            let mnemonic = Mnemonic::new(PhraseLength::TwentyFour, Language::English, "").unwrap();
            assert_eq!(
                Mnemonic::verify_phrase(
                    &mnemonic.phrase,
                    &Language::English
                ).unwrap(), ()
            )
        }
    }
}