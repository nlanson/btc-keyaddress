use crate::{
    encoding::{
        version_prefix::VersionPrefix
    },
    hash
};

const BASE58_ALPHABET: &'static [u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const MAP_BASE58: [i8; 256] = [
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
        -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
        22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
        -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
        47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
];


#[derive(Debug)]
pub struct Base58 {
    prefix: Option<VersionPrefix>,
    payload: Vec<u8>
}

#[derive(Debug)]
pub enum Base58Error {
    InvalidVersionPrefix,
    BadChar(char),
    CharAfterSpace(usize),
    BadChecksum
}

impl Base58 {
    pub fn new(prefix: Option<VersionPrefix>, payload: &[u8]) -> Base58 {
        Base58 {
            prefix,
            payload: payload.to_vec()
        }
    }

    /// Check encode data by appending the checksum and then encoding it.
    pub fn check_encode(self) -> String {
        //Concatenate: prefix | payload | checksum, to calculate checksum
        let mut bytes: Vec<u8> = if let Some(x) = self.prefix {
            x.to_bytes()
        } else {
            Vec::new()
        };
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&hash::sha256d(&bytes)[0..4]);
        
        

        //Return the Base58Check encoded value of the data.
        //Payload is none because it is already accounted for in the payload with the checksum.
        Self::encode(Self { prefix: None, payload: bytes })
    }

    /// Encode data in base58 format.
    pub fn encode(self) -> String {
        //Concatenate the prefix and payload
        let data = if let Some(x) = self.prefix {
            let mut d = x.to_bytes();
            d.extend_from_slice(&self.payload);
            d
        } else {
            self.payload
        };

        let mut result = Vec::new();
        let mut zcount = 0;
        let mut encoding_flag = true;

        //For each byte...
        for d in data {
            //Check if the "leading" byte is zero.
            //If so, increment the zero-counter and continue onto the next iteration.
            let mut carry = d as usize;
            if encoding_flag && carry == 0 {
                zcount += 1;
                continue;
            } else {
                encoding_flag = false;
            }

            // IDK what this loop does but encoding wont work without it. (Sourced from rust-bitcoin library)
            // It seems to update each item in the result vector and the carry value by the following equation:
            //    char = (char*256 + carry)%58    |   carry = (char*256 + carry)/58
            //
            // It stays for now but in the future I would like to rewrite it as something I understand.
            for char in result.iter_mut() {
                let new_char = *char as usize * 256 + carry;
                *char = (new_char % 58) as u8;
                carry = new_char / 58;
            }

            //While carry does not equal zero, push carry%58 to the result and set carry to itself divided by 58.
            while carry > 0 {
                result.push((carry % 58) as u8);
                carry /= 58;
            }
        }

        //Push the leading zeroes to the result and reverse it and return it as a string.
        for _ in 0..zcount {
            result.push(0);
        }
        result.iter().rev().map(|x| BASE58_ALPHABET[*x as usize] as char).collect()
    }


    /// Decodes a base58 string into a byte vector.
    /// DOES NOT remove the checksum or version prefix if present.
    /// 
    /// Translated from the original C implementation of Base58 in the Bitcoin Core repository with help
    /// from https://stackoverflow.com/questions/25855062/decoding-bitcoin-base58-address-to-byte-array
    pub fn decode(encoded: &str) -> Result<Vec<u8>, Base58Error> {
        let source: String = String::from(encoded);
        
        //Skip leading spaces
        let mut i = 0;
        while i < source.len() {
            if !source.chars().nth(i).unwrap().is_whitespace() {
                break;
            }
            i+=1;
        }

        //Skip and count leading '1's
        let mut zeroes = 0;
        while i < source.len() {
            if source.chars().nth(i).unwrap() != '1' {
                break;
            }
            zeroes+=1;
            i+=1;
        }

        //Allocate enough space in big-endian base256 representation.
        let size = source.len() * 733 / 1000 + 1; // log(58) / log(256), rounded up.
        let mut b256: Vec<u8> = vec![0; size];

        //Process the characters
        assert!(MAP_BASE58.len() == 256); //guarantee not out of range
        while i < source.len() && !source.chars().nth(i).unwrap().is_whitespace() {
            //Decode the base58 character
            let ch: i32 = MAP_BASE58[source.chars().nth(i).unwrap() as usize] as i32;
            if ch == -1 { return Err(Base58Error::BadChar(source.chars().nth(i).unwrap())); } //Invalid base58 character


            let mut carry = ch as u32;
            for char in b256.iter_mut().rev() {
                carry += 58 * (*char as u32);
                *char = (carry % 256) as u8;
                carry /= 256;
            }
            //assert!(carry == 0);
            i += 1;
        }


        //Skip trailing spaces
        while i < source.len() && source.chars().nth(i).unwrap().is_whitespace() {
            i+=1;
        }
        if i != source.len() {
            return Err(Base58Error::CharAfterSpace(i));
        }

        //Skip leading zeroes in b256
        let mut j = 0;
        while j < b256.len() && b256[j] == 0 {
            j+=1;
        }
        //Copy result into output vector
        let mut result: Vec<u8> = vec![0; zeroes + b256.len() - j]; //Vec::with_capacity(zeroes + b256.len() - j);
        for k in 0..result.len() {
            if k < zeroes {
                result[k] = 0x00;
            } else {
                result[k] = b256[j];
                j+=1;
            }
        }

        
        Ok(result)
    }

    /// Checks if a base58 check encoded string is valid
    pub fn validate_checksum(encoded: &str) -> Result<bool, Base58Error> {
        let bytes = Base58::decode(encoded)?;

        //Check derived_checksum == extracted_checksum
        Ok(hash::sha256d(&bytes[..bytes.len()-4])[0..4] == bytes[bytes.len()-4..])
    }

    /// Returns the decoded payload with the checksum removed.
    /// Version prefix is NOT removed as it is variable length depending on context.
    pub fn check_decode(encoded: &str) -> Result<Vec<u8>, Base58Error> {
        if !Self::validate_checksum(encoded)? { return Err(Base58Error::BadChecksum); }

        let bytes = Base58::decode(encoded)?;
        Ok(bytes[..bytes.len()-4].to_vec())
    }
}


#[cfg(test)]
mod tests {
    use crate::{
        key::{ PubKey, Key },
        util::decode_02x
    };
    use super::*;


    #[test]
    /// Tests encoding of data without checksum
    /// Sourced from https://tools.ietf.org/id/draft-msporny-base58-01.html
    fn base58_ietf_test_vectors() {
        let hello_world = b"Hello World!";
        let fox = b"The quick brown fox jumps over the lazy dog.";
        let int = [0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd];

        assert_eq!(Base58::new(None, hello_world).encode(), "2NEpo7TZRRrLZSi2U");
        assert_eq!(Base58::new(None, fox).encode(), "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z");
        assert_eq!(Base58::new(None, &int).encode(), "11233QC4");
    }

    #[test]
    /// Tests encoding of data without checksum.
    /// Sourced from the Bitcoin Core repository (https://github.com/bitcoin/bitcoin/blob/master/src/test/data/base58_encode_decode.json)
    /// and modifed for use with Rust.
    fn base58_bitcoin_core_test_vectors() {
        let test_data: [(&str, &str); 14] = [
            ("", ""),
            ("61", "2g"),
            ("626262", "a3gV"),
            ("636363", "aPEr"),
            ("73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"),
            ("00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"),
            ("516b6fcd0f", "ABnLTmg"),
            ("bf4f89001e670274dd", "3SEo3LWLoPntC"),
            ("572e4794", "3EFU7m"),
            ("ecac89cad93923c02321", "EJDM8drfXA6uyA"),
            ("10c8511e", "Rt5zm"),
            ("00000000000000000000", "1111111111"),
            ("000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5", "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "1cWB5HCBdLjAuqGGReWE3R3CguuwSjw6RHn39s2yuDRTS5NsBgNiFpWgAnEx6VQi8csexkgYw3mdYrMHr8x9i7aEwP8kZ7vccXWqKDvGv3u1GxFKPuAkn8JCPPGDMf3vMMnbzm6Nh9zh1gcNsMvH3ZNLmP5fSG6DGbbi2tuwMWPthr4boWwCxf7ewSgNQeacyozhKDDQQ1qL5fQFUW52QKUZDZ5fw3KXNQJMcNTcaB723LchjeKun7MuGW5qyCBZYzA1KjofN1gYBV3NqyhQJ3Ns746GNuf9N2pQPmHz4xpnSrrfCvy6TVVz5d4PdrjeshsWQwpZsZGzvbdAdN8MKV5QsBDY")
        ];

        for case in test_data {
            assert_eq!(Base58::new(None, &decode_02x(case.0)).encode(), case.1);
        }
    }

    #[test]
    ///Tests check encoding of a public key.
    fn base58_check_encode() {
        let key = PubKey::from_slice(&decode_02x("0204664c60ceabd82967055ccbd0f56a1585dfbd42032656efa501c463b16fbdfe")).unwrap();
        let expected_address = "124ERAK4SqHMNWXycHPautn5zDYRKr3b2E";
        let derived_address = Base58::new(Some(VersionPrefix::BTCAddress), &key.hash160()).check_encode();
        
        assert_eq!(expected_address, derived_address);
    }

    #[test]
    /// Tests the check decosing of a public key.
    fn base58_decode() {
        let expected_key = PubKey::from_slice(&decode_02x("0204664c60ceabd82967055ccbd0f56a1585dfbd42032656efa501c463b16fbdfe")).unwrap();
        let address = "124ERAK4SqHMNWXycHPautn5zDYRKr3b2E";
        let decoded = Base58::check_decode(address).expect("Decode failed");

        assert_eq!(decoded[1..], expected_key.hash160());
    }
}