use crate::{
    bs58, 
    hash,
    util::{
        try_into,
        as_u32_be
    }
};

#[derive(Debug, Clone)]
pub enum VersionPrefix {
    //One byte version prefixes
        BTCAddress = 0x00,
        BTCTestNetAddress = 0x6F,
        P2ScriptAddress = 0x05,
        TestnetP2SHAddress = 0xC4,
        PrivateKeyWIF = 0x80,
        TestNetPrivateKeyWIF = 0xef,
    
    //Four byte version prefixes
        //BIP-32
        Xprv = 0x0488ADE4, //Legacy P2PKH
        Xpub = 0x0488B21E,
        Tprv = 0x04358394,
        Tpub = 0x043587CF,
        //BIP-49
        Yprv = 0x049d7878, //P2SH nested P2WPKH
        Ypub = 0x049d7cb2,
        Uprv = 0x044a4e28,
        Upub = 0x044a5262,
        //BIP-84
        Zprv = 0x04b2430c, //P2WPKH
        Zpub = 0x04b24746,
        Vprv = 0x045f18bc,
        Vpub = 0x045f1cf6,

        //SLIP-0132
        SLIP132Ypub = 0x0295b43f, //Multi-signature P2WSH in P2SH
        SLIP132Zpub = 0x02aa7ed3, //Multi-signature P2WSH
        SLIP132Upub = 0x024289ef, //Multi-signature P2WSH in P2SH Testnet
        SLIP132Vpub = 0x02575483, //Multi-signature P2WSH Testnet

    //No data
        None
}

impl VersionPrefix {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            //Special cases where version bytes is not 4 bytes long
            VersionPrefix::BTCAddress => vec![0x00],
            VersionPrefix::BTCTestNetAddress => vec![0x6F],
            VersionPrefix::P2ScriptAddress => vec![0x05],
            VersionPrefix::TestnetP2SHAddress => vec![0xC4],
            VersionPrefix::PrivateKeyWIF => vec![0x80],
            VersionPrefix::TestNetPrivateKeyWIF => vec![0xef],
            VersionPrefix::None => vec![],
            
            //Cases where version bytes is 4 bytes long
            _ => (self.clone() as u32).to_be_bytes().to_vec()
        }
    }

    pub fn from_int(int: u32) -> Result<Self, ()> {
        Ok(match int {
            0x00 => Self::BTCAddress,
            0x6F => Self::BTCTestNetAddress,
            0x05 => Self::P2ScriptAddress,
            0xC4 => Self::TestnetP2SHAddress,
            0x80 => Self::PrivateKeyWIF,
            0xEF => Self:: TestNetPrivateKeyWIF,
            0x0488ADE4 => Self::Xprv,
            0x0488B21E => Self::Xpub,
            0x04358394 => Self::Tprv,
            0x043587cf => Self::Tpub,
            0x049d7878 => Self::Yprv,
            0x049d7cb2 => Self::Ypub,
            0x044a4e28 => Self::Uprv,
            0x044a5262 => Self::Upub,
            0x04b2430c => Self::Zprv,
            0x04b24746 => Self::Zpub,
            0x045f18bc => Self::Vprv,
            0x045f1cf6 => Self::Vpub,
            0x0295b43f => Self::SLIP132Ypub,
            0x02aa7ed3 => Self::SLIP132Zpub,
            0x024289ef => Self::SLIP132Upub,
            0x02575483 => Self::SLIP132Vpub,
            
            _ => return Err(())
        })
    }
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
    
    let p = prefix.to_bytes();

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