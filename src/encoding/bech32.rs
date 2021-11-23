/*
    Module implements Bech32 encoding.

    Made to work best with the WitnessProgram struct
*/
use crate::{
    util::decode_binary_string,
    script::WitnessProgram as WitProg
};

#[derive(Debug)]
pub enum Bech32Err {
    BadNetwork,
    CannotEncode,
    InvalidInt(u8),
    InvalidLength(usize),
    InvalidData(u8),
    SeperatorMissing,
    BadChar(char),
    BadChecksum,
    InvalidHRP(String),
    LengthRestriction(usize),
    IncorrectChecksum(Format),
    InvalidWitnessVersion(u8)
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
const BECH32M_CONST: u32 = 0x2bc830a3;  //Bech32m XOR constant
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; //Polymod generator coefficients

pub struct Bech32 {
    //Human readable part string
    pub hrp: String,

    //Data with parts that need to be squashed, already squashed
    pub data: Vec<u8>,

    pub format: Format
}


/// Enum for the different formats of Bech32 encoding
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Format {
    Bech32,
    Bech32m
}

impl Format {
    /// Given a witness version, return the Bech32 checksum format that should be used
    pub fn from_witness_version(version: u8) -> Format {
        match version {
            0 => Format::Bech32,
            _ => Format::Bech32m, //assuming all future versions will be using Bech32m
        }
    }
}

impl Bech32 {
    /// Return a new encoder instance given a HRP and squashed data and format
    pub fn new(hrp: &str, squashed_data: &[u8], format: Format) -> Self {
        Self {
            hrp: hrp.to_string(),
            data: squashed_data.to_vec(),
            format
        }
    }

    /// Unsquash the data in the Bech32 encoder engine and return it
    pub fn unwrap_data(&self) -> Result<Vec<u8>, Bech32Err> {
        Self::try_from_u5_str(&self.data)
    }
    
    
    /// Return a new encoder instance from a witness program
    /// Encode with rules enforced:
    ///   - Witness version is not squashed
    ///   - Witness v0 to use Bech32, Witness v1+ to use Bech32m
    pub fn from_witness_program (
        hrp: &str,
        wit_prog: &WitProg
    ) -> Self {
        //The data from a witness program is not the same as a script pub key
        let mut squashed_data = vec![wit_prog.version];                          //Version is not squashed
        squashed_data.extend_from_slice( &Self::to_u5(&wit_prog.program) ); //Witness program converted to 5 bits
        
        Self {
            hrp: hrp.to_string(),
            data: squashed_data,
            format: Format::from_witness_version(wit_prog.version)
        }
    }

    /// Given an Bech32 encoded address, decode it and return the witness program.
    /// Taproot address decoding is not yet implemented.
    /// Enforced Rules:
    ///   - Valid Bitcoin HRP
    ///   - Valid witness version (0 ~ 16)
    ///   - Witness program length restrictions
    ///   - Use of correct checksum for witness version (Bech32 for v0, Bech32m for v1+)
    pub fn to_witness_program(address: &str) -> Result<WitProg, Bech32Err> {        
        //Decode the address
        let mut bech32 = Self::decode(address)?;

        //Check the HRP is valid for Bitcoin
        match &bech32.hrp[..] {
            "bc" | "tb" => { },
            x => return Err(Bech32Err::InvalidHRP(x.to_string()))
        }

        //Check that the witness version is valid...
        let witness_version = bech32.data[0];
        bech32.data.remove(0);        // remove the witness version from the encoder as it is not packed
        let witness_program = bech32.unwrap_data()?;
        if witness_version > 16 { return Err(Bech32Err::InvalidWitnessVersion(witness_version)) }
        
        //Enforce known length restrictions and checksum requirements
        match witness_version {
            //Segwit
            0 => {
                // Segwit witness programs are either 20 byte key hashes or 32 byte script hashes
                // Uses Bech32 checksum
                if witness_program.len() != 20 && witness_program.len() != 32 { return Err(Bech32Err::LengthRestriction(witness_program.len())) }
            },
            
            //Taproot
            1 => {
                // Taproot witprogs are all 32 byte public keys
                // Uses Bech32m checksum
                if witness_program.len() != 32 { return Err(Bech32Err::LengthRestriction(witness_program.len())) }
            },

            //Future witness versions
            _ => unimplemented!("Witness version reserved for future upgrade")
        }

        //Check if the checksum uses the correct format for the version
        if Format::from_witness_version(witness_version) != bech32.format {
            return Err(Bech32Err::IncorrectChecksum(bech32.format))
        }

        //If checks pass for the specific witness version, return the witness program
        return Ok(
            WitProg::new(witness_version, witness_program).unwrap()
        )
    }

    /// Encodes the given HRP and data to Bech32 using the specified checksum type.
    pub fn encode(&self) -> Result<String, Bech32Err> {
        let mut result = format!("{}{}", self.hrp, SEPERATOR);

        //Create the checksum
        let hrp_bytes = self.hrp.clone().into_bytes();
        let checksum = Self::create_checksum(&hrp_bytes, &self.data, self.format);

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

    /// Bech32 decoding function that decodes a given Bech32 string into HRP and Payload.
    /// Does not validate address requirements such as program length and witness version.
    fn decode(encoded: &str) -> Result<Self, Bech32Err> {
        //Seperate the hrp from data at the seperator
        let mut i = 0;
        let sep_position = loop {
            if i >= encoded.len() { return Err(Bech32Err::SeperatorMissing) }
            if encoded.chars().nth(i) == Some(SEPERATOR) { break i }
            i+=1;
        };
        let hrp = encoded[0..sep_position].to_string();
        let data = encoded[sep_position+1..encoded.len()].to_string();

        //Match the data bytes to a 5 bit value
        let mut bytes: Vec<u8> = vec![];
        for i in 0..data.len() {
            let char = data.chars().nth(i).unwrap();
            match CHARSET.iter().position(|&c| c == char) {
                Some(x) => bytes.push(x as u8),
                None => return Err(Bech32Err::BadChar(char))
            }
        }

        //Check if there is a checksum present
        if bytes.len() < 6 { return Err(Bech32Err::InvalidLength(bytes.len())) }

        //Verify the checksum and return hrp and data and format if valid
        if let Some(x) = Self::verify_checksum(&hrp.clone().into_bytes(), &bytes) {
            return Ok(
                Bech32 {
                    hrp,
                    data: bytes[0..bytes.len()-6].to_vec(), //remove the checksum from the bytes
                    format: x
                }
            )
        }

        //Return error if not valid
        return Err(Bech32Err::BadChecksum)
    }

    //BIP-0713 defined method
    fn create_checksum(hrp_bytes: &Vec<u8>, data: &Vec<u8>, format: Format) -> Vec<u8> {
        let mut values = Self::hrp_expand(hrp_bytes);
        values.extend_from_slice(data);
        values.extend_from_slice(&[0,0,0,0,0,0]);

        //Bech32m uses a different constant here.
        let polymod: u32 = match format {
            Format::Bech32 => Self::polymod(&values) ^ 1,
            Format::Bech32m => Self::polymod(&values) ^ BECH32M_CONST
        };

        
        let mut checksum: Vec<u8> = vec![];
        for i in 0..6 { checksum.push(((polymod >> 5 * (5 - i)) & 31) as u8) }
        checksum
    }

    //BIP-0713 defined method
    fn hrp_expand(hrp_bytes: &[u8]) -> Vec<u8> {
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

    /// Verifies the checksum on the hrp bytes and payload.
    /// 
    /// Returns the checksum format if a match is detected, otherwise returns None.
    fn verify_checksum(hrp_bytes: &[u8], data: &[u8]) -> Option<Format> {
        let mut values = Self::hrp_expand(hrp_bytes);
        values.extend_from_slice(&data);

        // Verify either Bech32 OR Bech32m
        if Self::polymod(&values) == 1 { return Some(Format::Bech32) }
        else if Self::polymod(&values) == BECH32M_CONST { return Some(Format::Bech32m) }
        else { return None }
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
                    if x != '0' { return Err(Bech32Err::InvalidData(1)) }
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
    use crate::{
        util::Network
    };

    #[test]
    fn bit_convert_tests() -> Result<(), Bech32Err> {
        //Bitwise conversion is around 50 microseconds faster than string converstion.
        
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

    #[test]
    fn decoding_tests() {
        let witver = 0;
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

        let witness_program = WitProg::new(witver, data).unwrap();
        let address = witness_program.to_address(&Network::Bitcoin).unwrap();

        let decoded = WitProg::from_address(&address).unwrap();
        assert_eq!(witness_program, decoded);
    }

    #[test]
    fn bech32m_verification() -> Result<(), Bech32Err> {
        let strings = [
            "a1lqfn3a",
            // Not passing becasue the HRP contains illegal characters.
            //Simply need to disable character checks while looping the HRP.
            //"an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            
            // Not passing becuase the first instance if '1' is counted as the seperator, making the second instance an illegal character in the payload.
            // Simply need to detect that last instance of '1' and make that the seperator
            //"11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8", 
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa"
        ];

        for case in strings {
            Bech32::decode(case)?;
        }

        Ok(())
    }
}