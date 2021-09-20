use crate::{
    bs58, 
    hash,
    util::try_into
};

pub enum VersionPrefix {
    BTCAddress,
    P2ScriptAddress,
    BTCTestNetAddress,
    PrivateKeyWIF,
    //BIP32
    Xprv,
    Xpub,
    None
}

pub enum Bs58Error {
    InvalidChar((char, usize)),
    NonAsciiChar(usize),
    Unknown(String)
}

/**
    Returns the Base58Check encoded value of the input data.
    * Prefix is based on use case as degined in the VersionPrefix enum
*/
pub fn check_encode(prefix: VersionPrefix, data: &[u8]) -> String {
    //Reassigning data as mutable vec
    let mut data = data.to_vec();
    
    //Set the prefix based on use
    let p: Vec<u8> = match prefix {
        VersionPrefix::BTCAddress => vec![0x00],
        VersionPrefix::BTCTestNetAddress => vec![0x05],
        VersionPrefix::P2ScriptAddress => vec![0x6F],
        VersionPrefix::PrivateKeyWIF => vec![0x80],
        VersionPrefix::Xprv => vec![0x04, 0x88, 0xAD, 0xE4],
        VersionPrefix::Xpub => vec![0x04, 0x88, 0xB2, 0x1E],
        VersionPrefix::None => vec![]
    };

    //Prepend the prefix to data.
    data.splice(0..0, p);

    //Create the checksum of the data. Store only the first 4 bytes as a vector.
    let checksum: Vec<u8> = hash::double_sha256(&data)[0..4].to_vec();

    //Append the checksum
    data.splice(data.len()..data.len(), checksum);

    //Return the Base58Check encoded value of the data
    bs58::encode(data).into_string()
}

/**
    Encodes a given u8 slice into base 58 wihtout a checksum
*/
pub fn encode(data: &[u8]) -> String {
    bs58::encode(data).into_string()
}

/**
    Decodes a given Base58 string into a Byte vector
*/
pub fn decode(encoded: &String) -> Result<Vec<u8>, Bs58Error> {
    match bs58::decode(encoded).into_vec() {
        Ok(x) => Ok(x),
        Err(x) => {
            match x {
                bs58::decode::Error::InvalidCharacter { character: c, index: i } => return Err(Bs58Error::InvalidChar((c, i))),
                bs58::decode::Error::NonAsciiCharacter { index: i } => return Err(Bs58Error::NonAsciiChar(i)),
                x => return Err(Bs58Error::Unknown(x.to_string()))
            }
        }
    }

}

/**
    Validate the checksum on a Base58Check encoded string
*/
pub fn validate_checksum(encoded: &str) -> Result<bool, Bs58Error> {
    let bytes = decode(&encoded.to_string())?;
    let payload = &bytes[..bytes.len()-4];
    let extracted_checksum: [u8; 4] = try_into(bytes[bytes.len()-4..].to_vec());
    let derived_checksum: [u8; 4] = try_into(hash::double_sha256(payload)[0..4].to_vec());

    Ok(extracted_checksum == derived_checksum)
}