/*
    Module implements bech32 encoding
*/
use crate::{
    util::Network,
    util::decode_binary_string
};

use bitcoin_bech32::{ 
    WitnessProgram,
    u5
};
use bitcoin_bech32::constants::Network as bech32Network;

#[derive(Debug)]
pub enum Bech32Err {
    BadNetwork(),
    CannotEncode(),
    InvalidInt(u8),
    InvalidLength,
    InvalidData,
}

/**
    Takes in either a compressed public key or redeem script and encodes it in
    Bech32.

    The data is either a pubkey hash (p2wpkh) or script hash (p2wsh) or pubkey (taproot).
    The WitnessProgram is created from the data using the given witness version and network.
    Use witness version 0 for P2WPKH and P2WSH. Use verion 1 for P2TR
*/
pub fn encode(witness_version: u8, data: &[u8], network: &Network) -> Result<String, Bech32Err> {
    let network = match network {
        Network::Testnet => bech32Network::Testnet,
        Network::Bitcoin => bech32Network::Bitcoin,
        _ => return Err(Bech32Err::BadNetwork())
    };
    
    let witness_program = match WitnessProgram::new(
        u5::try_from_u8(witness_version).unwrap(), //Witness version
        data.to_vec(),               //Witness Program  (RedeemScript Hash or PubKey Hash)
                network                     //Network
    ) {
        Ok(x) => x,
        Err(_) => return Err(Bech32Err::CannotEncode())
    };

    Ok(witness_program.to_address())
}

/**
    Takes in a compressed public key or redeem script and 
    returns the SegWit script pubkey of it.

    Not sure where this method is used....
*/
pub fn decode_to_script_pub_key(witness_version: u8, data: &[u8], network: &Network) -> Result<Vec<u8>, Bech32Err> {
    let network = match network {
        Network::Testnet => bech32Network::Testnet,
        Network::Bitcoin => bech32Network::Bitcoin,
        _ => return Err(Bech32Err::BadNetwork())
    };
    
    let data = match WitnessProgram::new(
        u5::try_from_u8(witness_version).unwrap(), //Witness version
        data.to_vec(),                             //Witness Program  (RedeemScript or PubKey Hash)
                network                                   //Network
    ) {
        Ok(x) => x,
        Err(_) => return Err(Bech32Err::CannotEncode())
    };

    Ok(data.to_scriptpubkey())
}






//Custom Bech32 Implementation

// Encoding character set.
const CHARSET: [char; 32] = [
    'q','p','z','r','y','9','x','8',
    'g','f','2','t','v','d','w','0',
    's','3','j','n','5','4','k','h',
    'c','e','6','m','u','a','7','l'
];

struct Bech32Encoder {
    hrp: String,
    seperator: String,
    data: Vec<u8>
}

impl Bech32Encoder{
    pub fn new(
        hrp: &str,
        seperator: &str,
        data: &Vec<u8>
    ) -> Self {
        Self {
            hrp: hrp.to_string(),
            seperator: seperator.to_string(),
            data: data.clone()
        }
    }

    pub fn bech32(&self) -> Result<String, Bech32Err> {
        //See ref image

        todo!();
    }

    fn bech32_create_checksum(&self, m: bool) {
        todo!();
    }

    /**
        Magical function that takes in an array of unsigned 8bit integers 
        and converts it into an array of 5 bit integers.

        Uses a combination of bit masking and bit shifting to achieve the end result
        without having to sacrifice PC resources.
    */
    pub fn convert_bits(data: &Vec<u8>) -> Vec<u8> {
        let mut result = vec![];
        let mut i = 0;
        let mut b = 0;
        while b < data.len()*8 {
            //If cannot extract 5 bits from current index,
            if b%8 > 3 {
                //Magic number masks
                let m1 = (1 << 8-b%8) - 1;                        //Last x bits from current int
                let m2 = ((1 << 5-(8-b%8)) - 1) << 8-(5-(8-b%8)); //First x bits from next int


                //Check if padding bits are needed
                if data.len() != i+1 {
                    //Don't need padding bits

                    //Extract the starting and ending bits using masks.
                    let mut s = data[i]&m1;           //The starting bits are the last x bits from the current int
                    let mut e = data[i+1]&m2;         //Ending bits are the last x bits form the next int
                    s = s << (5-(8-b%8));             //Bit shift the starting and ending bits to be in correct positions
                    e = e >> (8-(5-(8-b%8)));


                    result.push( s|e );    //Push the bitwise OR result of the starting and ending bits
                } else {
                    //Need padding bits
                    result.push((data[i]&m1) << (5-(8-b%8)));    //Right shift the mask of the current entry and m1 by however many bits are missing to achieve a padding result
                    return result;
                }

            } 
            //If can extract 5 bits from current entry
            else {
                let m = ((1 << 5) - 1) << 3-b%8;    //Mask to extract 5 bits from the current int starting at current bit index
                result.push((data[i]&m) >> 3-b%8);  //Push the masked bits right shifted by however much needed (idk shift val)
            }

            b+=5;             //Increment current bit index by 5
            if b >= (i+1)*8 { //Increment current data index by 1 if bit index has gone into the next data point
                i+=1;
            }
        }

        //Return result
        result
    }

    /**
        Does the same thing as the other converting function but instead of using bitwise operations,
        this method simply converts the bytes into an bit string and slices the string into groups of 5.
     
        Less complicated and MUCH SIMPLER but uses more resources that bitwise operations.
    */
    pub fn convert_bits_str(data: &Vec<u8>) -> Vec<u8> {
        //Convert bytes to a string of bits.
        let mut bit_string = data.iter().map(|x| format!("{:08b}", x)).collect::<String>();
        while bit_string.len()%5 != 0 {
            bit_string+="0";
        }

        //Split bit string into groups of five
        let mut squashed_bytes = vec![];
        for i in (0..bit_string.len()-bit_string.len()%5).step_by(5) {
            let bits = &bit_string[i..i+5];
            squashed_bytes.push( decode_binary_string(bits) as u8 );
        }

        squashed_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_convert_tests() {
        let data  = vec![2, 45, 70, 25, 125, 0, 255];
        assert_eq!(Bech32Encoder::convert_bits(&data), [0, 8, 22, 20, 12, 6, 11, 29, 0, 3, 31, 16]);
        assert_eq!(Bech32Encoder::convert_bits(&data), Bech32Encoder::convert_bits_str(&data));

        let data = vec![2, 45];
        assert_eq!(Bech32Encoder::convert_bits(&data), [0b00000, 0b01000, 0b10110, 0b10000]);
        assert_eq!(Bech32Encoder::convert_bits(&data), Bech32Encoder::convert_bits_str(&data));

        let data = vec![255; 5];
        assert_eq!(Bech32Encoder::convert_bits(&data), [31; 8]);
        assert_eq!(Bech32Encoder::convert_bits(&data), Bech32Encoder::convert_bits_str(&data));

        let data = vec![0; 5];
        assert_eq!(Bech32Encoder::convert_bits(&data), [0; 8]);
        assert_eq!(Bech32Encoder::convert_bits(&data), Bech32Encoder::convert_bits_str(&data));

    }
}