use crate::{
    encoding::{
        bs58check::VersionPrefix
    },
    hash
};

const BASE58_ALPHABET: &'static [u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";


#[derive(Debug)]
pub struct Base58 {
    prefix: Option<VersionPrefix>,
    payload: Vec<u8>
}

#[derive(Debug)]
pub enum Base58Error {
    InvalidVersionPrefix,
    BadChar(char)
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
        bytes.extend_from_slice(&hash::double_sha256(&bytes)[0..4]);
        
        

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
    pub fn decode(encoded: &str) -> Result<Vec<u8>, Base58Error> {
        todo!();
    }

    /// Checks if a base58 check encoded string is valid
    pub fn validate_checksum(encoded: &str) -> Result<bool, Base58Error> {
        let bytes = Base58::decode(encoded)?;
        todo!();
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
    fn base58_check_encode() {
        let key = PubKey::from_slice(&decode_02x("0204664c60ceabd82967055ccbd0f56a1585dfbd42032656efa501c463b16fbdfe")).unwrap();
        let expected_address = "124ERAK4SqHMNWXycHPautn5zDYRKr3b2E";
        let derived_address = Base58::new(Some(VersionPrefix::BTCAddress), &key.hash160()).check_encode();
        
        assert_eq!(expected_address, derived_address);
    }

}