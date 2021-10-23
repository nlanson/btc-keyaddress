/*
    Module implements Bech32 encoding.

    Made to work with the WitnessProgram struct
*/
use crate::{
    util::decode_binary_string,
    script::WitnessProgram as WitProg
};

#[derive(Debug)]
pub enum Bech32Err {
    BadNetwork(),
    CannotEncode(),
    InvalidInt(u8),
    InvalidLength(usize),
    InvalidData(u8),
}

// Encoding character set.
const SEPERATOR: char = '1';
const CHARSET: [char; 32] = [
    'q','p','z','r','y','9','x','8',
    'g','f','2','t','v','d','w','0',
    's','3','j','n','5','4','k','h',
    'c','e','6','m','u','a','7','l'
];

//Encoding values.
const BECH32M_CONST: u32 = 0x2bc830a3;  //Bech32m xor constant
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; //polymod generator coefficients

pub struct Bech32 {
    //Human readable part string
    pub hrp: String,

    //Data with parts that need to be squashed already squashed
    pub data: Vec<u8>
}

impl Bech32 {
    //Return a new encoder instance
    pub fn from_witness_program (
        hrp: &str,
        wit_prog: &WitProg
    ) -> Self {
        //The data from a witness program is not the same as a script pub key
        let mut squashed_data = vec![wit_prog.version];    //Version
        squashed_data.extend_from_slice( &Self::to_u5(&wit_prog.program) ); //Witness program converted to 5 bits
        
        Self {
            hrp: hrp.to_string(),
            data: squashed_data
        }
    }

    //Encode self with Bech32
    pub fn bech32(&self) -> Result<String, Bech32Err> {
        self.encode(false)
    }

    //Encode self with Bech32m
    pub fn bech32m(&self) -> Result<String, Bech32Err> {
        self.encode(true)
    }

    fn encode(&self, bech32m: bool) -> Result<String, Bech32Err> {
        let mut result = format!("{}{}", self.hrp, SEPERATOR);

        //Create the checksum
        let hrp_bytes = self.hrp.clone().into_bytes();
        let checksum = Self::create_checksum(&hrp_bytes, &self.data, bech32m);

        //Payload is data + checksum concatenated
        let mut payload = self.data.clone();
        payload.extend_from_slice(&checksum);

        //match payload bytes to character set
        for x in payload {
            if x >= 32 { return Err(Bech32Err::InvalidData(x)) }
            result.push(CHARSET[x as usize]);
        }
        
        //Return
        Ok(result)
    }

    //BIP-0713 defined method
    fn create_checksum(hrp_bytes: &Vec<u8>, data: &Vec<u8>, bech32m: bool) -> Vec<u8> {
        let mut values = Self::hrp_expand(hrp_bytes);
        values.extend_from_slice(data);
        values.extend_from_slice(&[0,0,0,0,0,0]);

        //Bech32m uses a different constant here.
        let polymod: u32;
        if bech32m { polymod = Self::polymod(&values) ^ BECH32M_CONST }
        else { polymod = Self::polymod(&values) ^ 1 }

        
        let mut checksum: Vec<u8> = vec![];
        for i in 0..6 { checksum.push(((polymod >> 5 * (5 - i)) & 31) as u8) }
        checksum
    }

    //BIP-0713 defined method
    fn hrp_expand(hrp_bytes: &Vec<u8>) -> Vec<u8> {
        let mut values: Vec<u8> = vec![];
        for x in hrp_bytes { values.push(x >> 5) }
        values.push(0);
        for x in hrp_bytes { values.push(x & 31) }

        values
    }

    
    //BIP-0713 defined method
    fn polymod(values: &Vec<u8>) -> u32 {
        let mut chk: u32 = 1;
        for v in values {
            let b = (chk >> 25) as u8;
            chk = (chk & 0x1ffffff) << 5 ^ (*v as u32);
            for i in 0..5 {
                if (b >> i) & 1 == 1 {
                    chk ^= GEN[i]
                }
            }
        }

        chk
    }

    //BIP-0173 defined method
    fn verify_checksum(hrp_bytes: &Vec<u8>, data: &Vec<u8>) -> bool {
        let mut values = Self::hrp_expand(hrp_bytes);
        values.extend_from_slice(&data);

        Self::polymod(&values) == 1
    }

    /**
        Magical function that takes in an array of unsigned 8bit integers 
        and converts it into an array of 5 bit integers.

        Uses a combination of bit masking and bit shifting to achieve the end result
        without having to sacrifice PC resources.

        What the numbers and symbols mean:
            - b = current bit position
            - i = current index in the data vec
            - b%8 = current bit position in the current data index value
    */
    pub fn to_u5(data: &Vec<u8>) -> Vec<u8> {
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
     
        Less complicated and much easier to read but uses more resources than bitwise operations.
    */
    fn to_u5_str(data: &Vec<u8>) -> Vec<u8> {
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

    /**
        Converts a 5 bit int array to a 8 bit int array using bitwise operations.
        Unimplemented as it is too complicated and there is an alternative.
    */
    fn try_from_u5(data: &Vec<u8>) -> Result<Vec<u8>, Bech32Err> {
        unimplemented!("Use to_u5_str() method");
    }

    /**
        Converts an array of 5 bit ints into an array of 8 bit ints using string manipulation.
    */
    fn try_from_u5_str(data: &Vec<u8>) -> Result<Vec<u8>, Bech32Err> {
        //Extract 5 relevant bits from data into string
        let mut bit_string = String::new();
        for x in data {
            if *x >= 32 { return Err(Bech32Err::InvalidData(*x)) }
            let bits = format!("{:05b}", x);
            bit_string += &bits;
        }

        //Remove padding
        while bit_string.len()%8 != 0 {
            match bit_string.chars().nth( bit_string.len()-1 ) {
                Some(x) => { 
                    if x != '0' { return Err(Bech32Err::InvalidData(0)) }
                    bit_string.remove( bit_string.len()-1 );
                },

                _ => return Err(Bech32Err::InvalidData(0))
            }
        }

        let mut result: Vec<u8> = vec![];
        for i in (0..bit_string.len()).step_by(8) {
            let bits = &bit_string[i..i+8];
            result.push( decode_binary_string(bits) as u8 );
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_convert_tests() -> Result<(), Bech32Err> {
        //Testing the following:
        // u8 -> u5 with bitwise operations
        // u8 -> u5 with string manipulation
        // u5 -> u8 with string manipulation
        let data  = vec![2, 45, 70, 25, 125, 0, 255];
        assert_eq!(Bech32::to_u5(&data), [0, 8, 22, 20, 12, 6, 11, 29, 0, 3, 31, 16]);
        assert_eq!(Bech32::to_u5(&data), Bech32::to_u5_str(&data));
        assert_eq!(Bech32::try_from_u5_str(&Bech32::to_u5(&data))?, data);

        let data = vec![2, 45];
        assert_eq!(Bech32::to_u5(&data), [0b00000, 0b01000, 0b10110, 0b10000]);
        assert_eq!(Bech32::to_u5(&data), Bech32::to_u5_str(&data));
        assert_eq!(Bech32::try_from_u5_str(&Bech32::to_u5(&data))?, data);

        let data = vec![255; 5];
        assert_eq!(Bech32::to_u5(&data), [31; 8]);
        assert_eq!(Bech32::to_u5(&data), Bech32::to_u5_str(&data));
        assert_eq!(Bech32::try_from_u5_str(&Bech32::to_u5(&data))?, data);

        let data = vec![0; 5];
        assert_eq!(Bech32::to_u5(&data), [0; 8]);
        assert_eq!(Bech32::to_u5(&data), Bech32::to_u5_str(&data));
        assert_eq!(Bech32::try_from_u5_str(&Bech32::to_u5(&data))?, data);


        Ok(())
    }
}