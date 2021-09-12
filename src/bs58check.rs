use crate::{bs58, hash};

pub enum VersionPrefix {
    BTCAddress,
    P2ScriptAddress,
    BTCTestNetAddress,
    PrivateKeyWIF,
    //BIP38,
    //BIP32
}

/**
    Returns the Base58Check encoded value of the input data.
    * Prefix is based on use case as degined in the VersionPrefix enum
*/
pub fn check_encode(prefix: VersionPrefix, data: Vec<u8>) -> String {
    //Reassing data as mutable vec
    let mut data = data;
    
    //Set the prefix based on use
    let p: Vec<u8> = match prefix {
        VersionPrefix::BTCAddress => vec![0x00],
        VersionPrefix::BTCTestNetAddress => vec![0x05],
        VersionPrefix::P2ScriptAddress => vec![0x6F],
        VersionPrefix::PrivateKeyWIF => vec![0x80]
    };

    //Prepend the prefix to data.
    data.splice(0..0, p);

    //Create the checksum of the data. Store only the first 4 bytes as a vector.
    let checksum: Vec<u8> = hash::sha256(hash::sha256(&data))[0..4].to_vec();

    //Append the checksum
    data.splice(data.len()..data.len(), checksum);

    //Return the Base58Check encoded value of the data
    bs58::encode(data).into_string()
}